// SPDX-License-Identifier: MIT

import { execFile as execFileCallback, type ExecFileOptions } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import process, { type ProcessEnv } from 'node:process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';

interface GenerateSbomOptions {
  readonly packageJsonPath?: string;
  readonly packageLockPath?: string;
  readonly outputPath?: string;
  readonly timestamp?: Date;
  readonly logger?: (message: string) => void;
}

interface CliArguments {
  readonly packageJsonPath?: string;
  readonly packageLockPath?: string;
  readonly outputPath?: string;
}

interface PackageLockEntry {
  readonly name?: string;
  readonly version?: string;
  readonly license?: string;
  readonly licenses?: Array<string | { type?: string }>;
}

interface Component {
  readonly type: 'library';
  readonly name: string;
  readonly version: string;
  readonly purl: string;
  readonly licenses?: Array<{ license: { id: string } }>;
}

interface GeneratedSbom {
  readonly cycloneDx: Record<string, unknown>;
  readonly spdx: Record<string, unknown>;
  readonly componentCount: number;
  readonly cycloneDxSignaturePath?: string;
  readonly spdxSignaturePath?: string;
}

function resolveCosignKeyRef(): string | undefined {
  if (process.env.COSIGN_KEY_REF && process.env.COSIGN_KEY_REF.trim() !== '') {
    return process.env.COSIGN_KEY_REF.trim();
  }
  if (process.env.COSIGN_PRIVATE_KEY && process.env.COSIGN_PRIVATE_KEY.trim() !== '') {
    return 'env://COSIGN_PRIVATE_KEY';
  }
  return undefined;
}

type CosignExec = (
  file: string,
  args: readonly string[],
  options: ExecFileOptions & { env?: ProcessEnv; stdio?: 'pipe' }
) => Promise<{ stdout: string; stderr: string }>;

const execFileAsync = promisify(execFileCallback) as CosignExec;

async function signSbom(
  outputPath: string,
  logger: (message: string) => void
): Promise<string | undefined> {
  const keyRef = resolveCosignKeyRef();
  if (!outputPath || !keyRef) {
    logger('Skipping SBOM signing: COSIGN_KEY_REF or COSIGN_PRIVATE_KEY not configured.');
    return undefined;
  }

  const cosignBinary = process.env.COSIGN_BINARY && process.env.COSIGN_BINARY.trim() !== ''
    ? process.env.COSIGN_BINARY.trim()
    : 'cosign';
  const signaturePath = `${outputPath}.sig`;
  const args = ['sign-blob', '--key', keyRef, '--output-signature', signaturePath, outputPath];

  try {
    await execFileAsync(cosignBinary, args, {
      env: process.env,
      stdio: 'pipe'
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`cosign sign-blob failed: ${message}`, { cause: error instanceof Error ? error : undefined });
  }

  logger(`SBOM signature written to ${signaturePath}`);
  return signaturePath;
}

function buildPurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const scopeSeparator = name.indexOf('/');
    if (scopeSeparator !== -1) {
      const scope = name.slice(1, scopeSeparator);
      const pkg = name.slice(scopeSeparator + 1);
      return `pkg:npm/%40${encodeURIComponent(scope)}/${encodeURIComponent(pkg)}@${encodeURIComponent(version)}`;
    }
  }
  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function toDeterministicSerial(components: readonly Component[]): string {
  const hash = crypto.createHash('sha256').update(JSON.stringify(components)).digest('hex');
  const uuid = `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
  return `urn:uuid:${uuid}`;
}

function toLicenseArray(license?: string): Array<{ license: { id: string } }> | undefined {
  if (!license) {
    return undefined;
  }
  return [
    {
      license: { id: license }
    }
  ];
}

function parseComponents(packages: Record<string, PackageLockEntry>): Component[] {
  const components = new Map<string, Component>();
  for (const [pkgPath, pkg] of Object.entries(packages)) {
    if (pkgPath === '') {
      continue;
    }
    const version = pkg.version;
    if (!version) {
      continue;
    }
    const name = pkg.name ?? pkgPath.replace(/^node_modules\//u, '');
    if (!name) {
      continue;
    }
    const license = pkg.license ?? (Array.isArray(pkg.licenses) ? pkg.licenses.map((item) => (typeof item === 'string' ? item : item.type ?? '')).filter(Boolean).join(' OR ') : undefined);
    const component: Component = {
      type: 'library',
      name,
      version,
      purl: buildPurl(name, version),
      ...(license ? { licenses: toLicenseArray(license) } : {})
    };
    components.set(`${name}@${version}`, component);
  }
  return Array.from(components.values()).sort((a, b) => a.purl.localeCompare(b.purl));
}

function toSpdxLicenseExpression(component: Component): string {
  if (!component.licenses || component.licenses.length === 0) {
    return 'NOASSERTION';
  }

  const ids = component.licenses
    .map((entry) => entry.license?.id)
    .filter((id): id is string => typeof id === 'string' && id.length > 0);

  if (ids.length === 0) {
    return 'NOASSERTION';
  }

  return ids.join(' OR ');
}

function sanitizeForSpdxId(value: string): string {
  return value.replace(/[^A-Za-z0-9-.]+/gu, '-');
}

function buildSpdxPackages(
  components: readonly Component[]
): Array<{ SPDXID: string } & Record<string, unknown>> {
  return components.map((component, index) => {
    const packageSpdxId = `SPDXRef-Package-${sanitizeForSpdxId(component.name)}-${sanitizeForSpdxId(component.version)}-${index}`;
    const licenseExpression = toSpdxLicenseExpression(component);

    return {
      SPDXID: packageSpdxId,
      name: component.name,
      versionInfo: component.version,
      downloadLocation: 'NOASSERTION',
      licenseConcluded: licenseExpression,
      licenseDeclared: licenseExpression,
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: component.purl
        }
      ]
    } satisfies { SPDXID: string } & Record<string, unknown>;
  });
}

function buildSpdxDocument(
  components: readonly Component[],
  packageJson: { name?: string; version?: string },
  generatedAt: string
): Record<string, unknown> {
  const packages = buildSpdxPackages(components);
  const documentNamespace = toDeterministicSerial(components);

  return {
    SPDXID: 'SPDXRef-DOCUMENT',
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    name: `${packageJson.name ?? 'unknown'}-${packageJson.version ?? '0.0.0'}`,
    documentNamespace,
    creationInfo: {
      creators: ['Tool: Alterra-Solutions oss-compliance-tooling'],
      created: generatedAt
    },
    packages,
    relationships: packages.map((pkg) => ({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: pkg.SPDXID
    }))
  } satisfies Record<string, unknown>;
}

function deriveSpdxOutputPath(outputPath: string): string {
  const parsed = path.parse(outputPath);
  return path.join(parsed.dir, `${parsed.name}.spdx.json`);
}

export async function generateSbom({
  packageJsonPath = path.resolve(process.cwd(), 'package.json'),
  packageLockPath = path.resolve(process.cwd(), 'package-lock.json'),
  outputPath,
  timestamp,
  logger = (message) => process.stdout.write(`${message}\n`)
}: GenerateSbomOptions): Promise<GeneratedSbom> {
  const packageJsonRaw = await readFile(packageJsonPath, 'utf8');
  const packageLockRaw = await readFile(packageLockPath, 'utf8');
  const packageJson = JSON.parse(packageJsonRaw) as { name?: string; version?: string };
  const packageLock = JSON.parse(packageLockRaw) as { packages?: Record<string, PackageLockEntry> };

  const components = parseComponents(packageLock.packages ?? {});
  const generatedAt = (timestamp ?? new Date()).toISOString();
  const cycloneDx = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: toDeterministicSerial(components),
    version: 1,
    metadata: {
      timestamp: generatedAt,
      tools: [
        {
          vendor: 'Alterra-Solutions',
          name: 'oss-compliance-tooling',
          version: packageJson.version ?? '0.0.0'
        }
      ],
      component: {
        type: 'application',
        name: packageJson.name ?? 'unknown',
        version: packageJson.version ?? '0.0.0'
      }
    },
    components
  } satisfies Record<string, unknown>;

  const spdx = buildSpdxDocument(components, packageJson, generatedAt);

  let cycloneDxSignaturePath: string | undefined;
  let spdxSignaturePath: string | undefined;
  if (outputPath) {
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(cycloneDx, null, 2)}\n`, 'utf8');
    logger(`SBOM written to ${outputPath}`);
    cycloneDxSignaturePath = await signSbom(outputPath, logger);

    const spdxPath = deriveSpdxOutputPath(outputPath);
    await mkdir(path.dirname(spdxPath), { recursive: true });
    await writeFile(spdxPath, `${JSON.stringify(spdx, null, 2)}\n`, 'utf8');
    logger(`SPDX SBOM written to ${spdxPath}`);
    spdxSignaturePath = await signSbom(spdxPath, logger);
  } else {
    logger(JSON.stringify(cycloneDx, null, 2));
    logger(JSON.stringify(spdx, null, 2));
  }

  return {
    cycloneDx,
    spdx,
    componentCount: components.length,
    cycloneDxSignaturePath,
    spdxSignaturePath
  };
}

function parseCliArguments(args: readonly string[]): CliArguments {
  let packageJsonPath: string | undefined;
  let packageLockPath: string | undefined;
  let outputPath: string | undefined;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--package-json') {
      packageJsonPath = path.resolve(args[i + 1] ?? 'package.json');
      i += 1;
    } else if (arg === '--package-lock') {
      packageLockPath = path.resolve(args[i + 1] ?? 'package-lock.json');
      i += 1;
    } else if (arg === '--output') {
      outputPath = path.resolve(args[i + 1] ?? 'sbom.json');
      i += 1;
    }
  }

  return { packageJsonPath, packageLockPath, outputPath };
}

async function cli(): Promise<void> {
  const options = parseCliArguments(process.argv.slice(2));
  await generateSbom({
    packageJsonPath: options.packageJsonPath,
    packageLockPath: options.packageLockPath,
    outputPath: options.outputPath,
    logger: (message) => process.stdout.write(`${message}\n`)
  });
}

function isExecutedDirectly(): boolean {
  const entryPoint = process.argv[1];
  if (!entryPoint) {
    return false;
  }
  return import.meta.url === pathToFileURL(entryPoint).href;
}

if (isExecutedDirectly()) {
  cli().catch((error: unknown) => {
    const failure = error instanceof Error ? error : new Error(String(error));
    process.stderr.write(`SBOM generation failed: ${failure.message}\n`);
    process.exitCode = 1;
  });
}
