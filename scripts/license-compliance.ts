// SPDX-License-Identifier: MIT

import { readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const PROPRIETARY_HEADER = '// SPDX-License-Identifier: MIT';
const ALLOWED_HEADER_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);
const SKIP_DIRECTORIES = new Set(['node_modules', '.git', 'third_party', 'third-party', 'dist', 'build', 'coverage']);
const FORBIDDEN_LICENSE_PATTERNS = [/GPL/i, /AGPL/i, /LGPL/i, /SSPL/i, /CDDL/i, /UNKNOWN/i];

interface LicenseComplianceOptions {
  readonly rootDir?: string;
  readonly fixHeaders?: boolean;
  readonly logger?: (message: string) => void;
}

interface CliArguments {
  readonly rootDir?: string;
  readonly fixHeaders: boolean;
}

interface DependencyRecord {
  readonly name: string;
  readonly version: string;
  readonly license: string;
}

class LicenseComplianceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LicenseComplianceError';
  }
}

async function* walkDirectory(dir: string): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (SKIP_DIRECTORIES.has(entry.name)) {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkDirectory(fullPath);
    } else if (entry.isFile()) {
      yield fullPath;
    }
  }
}

async function ensureHeader(filePath: string, fix: boolean): Promise<string | undefined> {
  const extension = path.extname(filePath);
  if (filePath.endsWith('.d.ts') || !ALLOWED_HEADER_EXTENSIONS.has(extension)) {
    return undefined;
  }

  const content = await readFile(filePath, 'utf8');
  const lines = content.split(/\r?\n/);
  if (lines[0] === PROPRIETARY_HEADER) {
    return undefined;
  }

  if (fix) {
    const updated = [PROPRIETARY_HEADER, ...lines.filter((line, index) => !(index === 0 && line.trim().length === 0))].join('\n');
    await writeFile(filePath, `${updated}\n`, 'utf8');
    return undefined;
  }

  return `Missing license header in ${filePath}`;
}

async function collectHeaderViolations(rootDir: string, fix: boolean): Promise<string[]> {
  const violations: string[] = [];
  for await (const filePath of walkDirectory(rootDir)) {
    const violation = await ensureHeader(filePath, fix);
    if (violation) {
      violations.push(violation);
    }
  }
  return violations;
}

function readLicenseArray(source: unknown): string[] | undefined {
  if (typeof source !== 'object' || source === null) {
    return undefined;
  }

  if (!('licenses' in source)) {
    return undefined;
  }

  const candidate = (source as { licenses?: unknown }).licenses;
  if (!Array.isArray(candidate)) {
    return undefined;
  }

  const normalized: string[] = [];
  for (const entry of candidate) {
    if (typeof entry === 'string') {
      normalized.push(entry);
      continue;
    }

    if (typeof entry === 'object' && entry !== null) {
      const maybeType = (entry as { type?: unknown }).type;
      if (typeof maybeType === 'string') {
        normalized.push(maybeType);
        continue;
      }
      if (maybeType === undefined) {
        continue;
      }
    }

    return undefined;
  }

  return normalized;
}

function toDependencyRecord(packagePath: string, data: Record<string, unknown>): DependencyRecord | undefined {
  const version = typeof data.version === 'string' ? data.version : undefined;
  if (!version) {
    return undefined;
  }

  let name: string | undefined;
  if (typeof data.name === 'string') {
    name = data.name;
  } else if (packagePath.startsWith('node_modules/')) {
    name = packagePath.replace(/^node_modules\//u, '').replace(/\/index$/u, '');
  }

  if (!name) {
    return undefined;
  }

  let license = '';
  if (typeof data.license === 'string') {
    license = data.license;
  } else {
    const licenses = readLicenseArray(data);
    if (licenses && licenses.length > 0) {
      license = licenses.filter((value) => value.length > 0).join(' OR ');
    }
  }

  return { name, version, license };
}

function detectLicenseViolations(dependencies: readonly DependencyRecord[]): string[] {
  const violations: string[] = [];
  for (const dependency of dependencies) {
    if (dependency.license.length === 0) {
      violations.push(`Dependency ${dependency.name}@${dependency.version} has no license metadata.`);
      continue;
    }

    if (FORBIDDEN_LICENSE_PATTERNS.some((pattern) => pattern.test(dependency.license))) {
      violations.push(`Dependency ${dependency.name}@${dependency.version} uses forbidden license: ${dependency.license}`);
    }
  }
  return violations;
}

async function collectDependencies(rootDir: string): Promise<DependencyRecord[]> {
  const lockPath = path.join(rootDir, 'package-lock.json');
  const exists = await stat(lockPath).then(() => true).catch(() => false);
  if (!exists) {
    throw new LicenseComplianceError(`package-lock.json not found at ${lockPath}`);
  }

  const raw = await readFile(lockPath, 'utf8');
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  const packages = parsed.packages as Record<string, Record<string, unknown>> | undefined;
  if (!packages) {
    return [];
  }

  const dependencies: DependencyRecord[] = [];
  for (const [pkgPath, data] of Object.entries(packages)) {
    if (pkgPath === '') {
      continue;
    }
    const record = toDependencyRecord(pkgPath, data);
    if (record) {
      dependencies.push(record);
    }
  }
  return dependencies;
}

export async function runLicenseCompliance({ rootDir = process.cwd(), fixHeaders = false, logger = (message) => process.stdout.write(`${message}\n`) }: LicenseComplianceOptions): Promise<void> {
  const headerViolations = await collectHeaderViolations(rootDir, fixHeaders);
  const dependencies = await collectDependencies(rootDir);
  const licenseViolations = detectLicenseViolations(dependencies);

  const violations = [...headerViolations, ...licenseViolations];
  if (violations.length > 0) {
    violations.forEach((violation) => logger(violation));
    throw new LicenseComplianceError(`${violations.length} compliance issue(s) detected.`);
  }

  logger('License compliance check passed.');
}

function parseCliArguments(args: readonly string[]): CliArguments {
  let rootDir: string | undefined;
  let fix = false;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--root') {
      rootDir = path.resolve(args[i + 1] ?? process.cwd());
      i += 1;
    } else if (arg === '--fix') {
      fix = true;
    }
  }

  return { rootDir, fixHeaders: fix };
}

async function cli(): Promise<void> {
  const options = parseCliArguments(process.argv.slice(2));
  await runLicenseCompliance({
    rootDir: options.rootDir,
    fixHeaders: options.fixHeaders,
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
    process.stderr.write(`License compliance failed: ${failure.message}\n`);
    process.exitCode = 1;
  });
}

export { LicenseComplianceError };
