// SPDX-License-Identifier: MIT

import * as fs from 'node:fs/promises';
import { join, relative, extname, dirname } from 'node:path';

import { assertNetworkFetchAllowed } from './network-guard.js';

export type PackageEcosystem =
  | 'npm'
  | 'pypi'
  | 'go'
  | 'rubygems'
  | 'cargo'
  | 'maven'
  | 'nuget'
  | 'oci'
  | 'apk'
  | 'deb'
  | 'rpm';

export interface PackageSummary {
  readonly name: string;
  readonly version: string;
  readonly ecosystem: PackageEcosystem;
  readonly purl: string;
}

export interface LicenseFinding {
  readonly path: string;
  readonly spdxId: string;
  readonly packageName?: string;
}

export interface OsvVulnerability {
  readonly id: string;
  readonly summary?: string;
  readonly severity?: Array<Record<string, unknown>>;
}

export interface VulnerabilityFinding {
  readonly package: PackageSummary;
  readonly vulnerabilities: OsvVulnerability[];
}

export interface CycloneDxBom {
  readonly bomFormat: 'CycloneDX';
  readonly specVersion: '1.5';
  readonly version: number;
  readonly metadata: {
    readonly timestamp: string;
    readonly tools: Array<{ vendor: string; name: string; version: string }>;
  };
  readonly components: Array<{
    readonly bomRef: string;
    readonly name: string;
    readonly version: string;
    readonly type: 'library';
    readonly purl: string;
    readonly licenses?: Array<{ license: { id: string } }>;
  }>;
}

export interface ScannerOptions {
  readonly ociLayersPath?: string;
  readonly fetchImpl?: typeof fetch;
  readonly cache?: Map<string, OsvVulnerability[]>;
  readonly now?: () => Date;
  readonly persistCache?: (key: string, vulnerabilities: OsvVulnerability[]) => Promise<void>;
  readonly osvRetryOptions?: OsvRetryOptions;
}

export interface ScannerResult {
  readonly packages: PackageSummary[];
  readonly bom: CycloneDxBom;
  readonly licenses: LicenseFinding[];
  readonly vulnerabilities: VulnerabilityFinding[];
}

const OSV_BATCH_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const OSV_BATCH_TIMEOUT_MS = 10_000;
const OSV_BATCH_MAX_ATTEMPTS = 3;
const OSV_BATCH_RETRY_BASE_MS = 500;
const LICENSE_PREFIXES = ['LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT'] as const;
const DEFAULT_DISCOVERY_MAX_DEPTH = 4;
const IGNORED_DISCOVERY_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'vendor',
  '.gradle',
  'build',
  'dist',
  'target',
  '.idea',
  '.vscode',
  '.scanner-cache',
  'tmp',
  'temp',
  'obj',
  'bin'
]);

const KNOWN_MAVEN_PACKAGINGS = new Set([
  'aar',
  'ear',
  'jar',
  'maven-plugin',
  'par',
  'pom',
  'rar',
  'sar',
  'war',
  'zip'
]);

interface FileDiscoveryOptions {
  readonly names?: ReadonlyArray<string>;
  readonly extensions?: ReadonlyArray<string>;
  readonly maxDepth?: number;
}

async function discoverFiles(workspacePath: string, options: FileDiscoveryOptions = {}): Promise<string[]> {
  const normalizedNames = new Set((options.names ?? []).map((name) => name.toLowerCase()));
  const normalizedExtensions = new Set(
    (options.extensions ?? []).map((extension) => extension.toLowerCase())
  );
  const maxDepth = options.maxDepth ?? DEFAULT_DISCOVERY_MAX_DEPTH;
  const results: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: workspacePath, depth: 0 }];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift();

    if (!current) {
      continue;
    }

    const { dir, depth } = current;

    if (visited.has(dir)) {
      continue;
    }

    visited.add(dir);

    let entries: Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>;

    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const entryPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (depth >= maxDepth) {
          continue;
        }

        if (IGNORED_DISCOVERY_DIRECTORIES.has(entry.name)) {
          continue;
        }

        queue.push({ dir: entryPath, depth: depth + 1 });
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const lowerName = entry.name.toLowerCase();
      const entryExtension = extname(lowerName);
      const nameMatches = normalizedNames.size > 0 && normalizedNames.has(lowerName);
      const extensionMatches =
        normalizedExtensions.size > 0 && normalizedExtensions.has(entryExtension);

      if (
        (normalizedNames.size === 0 && normalizedExtensions.size === 0) ||
        nameMatches ||
        extensionMatches
      ) {
        results.push(entryPath);
      }
    }
  }

  return results;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await fs.stat(path);
    return true;
  } catch (error) {
    const errorWithCode = error as { code?: string } | undefined;

    if (errorWithCode?.code === 'ENOENT') {
      return false;
    }

    throw error;
  }
}

function encodePurlComponent(value: string): string {
  return encodeURIComponent(value).replace(/%2F/giu, '/');
}

function createPurl(
  name: string,
  version: string,
  ecosystem: PackageEcosystem,
  qualifiers: Record<string, string> | undefined = undefined
): string {
  const encodedName = encodePurlComponent(name);

  if (ecosystem === 'npm') {
    return `pkg:npm/${encodedName}@${version}`;
  }

  if (ecosystem === 'pypi') {
    return `pkg:pypi/${encodedName}@${version}`;
  }

  if (ecosystem === 'go') {
    return `pkg:golang/${encodedName}@${version}`;
  }

  if (ecosystem === 'rubygems') {
    return `pkg:gem/${encodedName}@${version}`;
  }

  if (ecosystem === 'cargo') {
    return `pkg:cargo/${encodedName}@${version}`;
  }

  if (ecosystem === 'maven') {
    const segments = name.split(':');
    const hasNamespace = segments.length > 1;
    const groupPart = hasNamespace ? segments[0] ?? '' : '';
    const artifactPart = hasNamespace ? segments[1] ?? '' : segments[0] ?? '';
    const groupSegments = groupPart.split('.').filter((segment) => segment.length > 0);
    const namespace = groupSegments.map(encodePurlComponent).join('/');
    const artifact = encodePurlComponent(artifactPart);
    const prefix = namespace.length > 0 ? `${namespace}/` : '';
    const qualifierEntries = Object.entries(qualifiers ?? {}).filter(
      ([, value]) => value.length > 0
    );
    const qualifierSuffix =
      qualifierEntries.length > 0
        ? `?${qualifierEntries
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
            .join('&')}`
        : '';
    return `pkg:maven/${prefix}${artifact}@${version}${qualifierSuffix}`;
  }

  if (ecosystem === 'nuget') {
    return `pkg:nuget/${encodedName}@${version}`;
  }

  if (ecosystem === 'apk') {
    return `pkg:apk/alpine/${encodedName}@${version}`;
  }

  if (ecosystem === 'deb') {
    return `pkg:deb/debian/${encodedName}@${version}`;
  }

  if (ecosystem === 'rpm') {
    return `pkg:rpm/redhat/${encodedName}@${version}`;
  }

  return `pkg:oci/${encodedName}@${version}`;
}

function addPackage(target: Map<string, PackageSummary>, summary: PackageSummary): void {
  if (!summary.name || !summary.version) {
    return;
  }

  const key = summary.purl;

  if (!target.has(key)) {
    target.set(key, summary);
  }
}

function parseYarnSpecifier(specifier: string): string | null {
  let normalized = specifier.trim();

  if (normalized.length === 0) {
    return null;
  }

  if (normalized.startsWith('"') && normalized.endsWith('"')) {
    normalized = normalized.slice(1, -1);
  }

  const atIndex = normalized.lastIndexOf('@');

  if (atIndex <= 0) {
    return null;
  }

  const name = normalized.slice(0, atIndex);
  const remainder = normalized.slice(atIndex + 1);

  if (remainder.includes(':')) {
    const [protocol] = remainder.split(':', 1);

    if (protocol && protocol !== 'npm') {
      return null;
    }
  }

  return name;
}

export async function collectNodePackages(workspacePath: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();
  const lockPath = join(workspacePath, 'package-lock.json');

  if (await fileExists(lockPath)) {
    try {
      const json = JSON.parse(await fs.readFile(lockPath, 'utf8')) as Record<string, unknown>;

      if (typeof json.packages === 'object' && json.packages !== null) {
        const entries = json.packages as Record<string, { name?: string; version?: string }>;

        for (const [pkgPath, pkg] of Object.entries(entries)) {
          if (pkgPath === '') {
            continue;
          }

          const name = pkg.name ?? pkgPath.split('node_modules/').pop() ?? pkgPath;
          const version = pkg.version ?? '';
          addPackage(packages, {
            name,
            version,
            ecosystem: 'npm',
            purl: createPurl(name, version, 'npm')
          });
        }
      } else if (typeof json.dependencies === 'object' && json.dependencies !== null) {
        const dependencies = json.dependencies as Record<string, { version?: string } | string>;

        for (const [name, dependency] of Object.entries(dependencies)) {
          const version = typeof dependency === 'string' ? dependency : dependency.version ?? '';
          addPackage(packages, {
            name,
            version,
            ecosystem: 'npm',
            purl: createPurl(name, version, 'npm')
          });
        }
      }
    } catch {
      // ignore malformed lock files
    }
  }

  const pnpmLockPath = join(workspacePath, 'pnpm-lock.yaml');

  if (await fileExists(pnpmLockPath)) {
    const contents = await fs.readFile(pnpmLockPath, 'utf8');

    for (const line of contents.split(/\r?\n/u)) {
      const trimmed = line.trim();

      if (!trimmed.startsWith('/')) {
        continue;
      }

      const key = trimmed.slice(1).split(':')[0] ?? '';
      const separatorIndex = key.lastIndexOf('@');

      if (separatorIndex <= 0) {
        continue;
      }

      const name = key.slice(0, separatorIndex);
      const version = key.slice(separatorIndex + 1);
      addPackage(packages, {
        name,
        version,
        ecosystem: 'npm',
        purl: createPurl(name, version, 'npm')
      });
    }
  }

  const yarnLockPath = join(workspacePath, 'yarn.lock');

  if (await fileExists(yarnLockPath)) {
    const contents = await fs.readFile(yarnLockPath, 'utf8');
    const lines = contents.split(/\r?\n/u);
    let pendingSpecs: string[] = [];

    for (const rawLine of lines) {
      const line = rawLine.trimEnd();

      if (!line) {
        continue;
      }

      if (!rawLine.startsWith(' ') && line.endsWith(':')) {
        const header = line.slice(0, -1);
        pendingSpecs = header.split(/,\s*/u).map((entry) => entry.trim()).filter(Boolean);
        continue;
      }

      if (pendingSpecs.length === 0) {
        continue;
      }

      const trimmed = line.trim();

      if (trimmed.startsWith('version ')) {
        const [, rawVersion] = trimmed.split(/\s+/u);
        const version = (rawVersion ?? '').replace(/^"|"$/gu, '');

        for (const specifier of pendingSpecs) {
          const name = parseYarnSpecifier(specifier);

          if (!name) {
            continue;
          }

          addPackage(packages, {
            name,
            version,
            ecosystem: 'npm',
            purl: createPurl(name, version, 'npm')
          });
        }

        pendingSpecs = [];
        continue;
      }

      if (trimmed.startsWith('version:')) {
        const version = trimmed.slice('version:'.length).trim().replace(/^"|"$/gu, '');

        for (const specifier of pendingSpecs) {
          const name = parseYarnSpecifier(specifier);

          if (!name) {
            continue;
          }

          addPackage(packages, {
            name,
            version,
            ecosystem: 'npm',
            purl: createPurl(name, version, 'npm')
          });
        }

        pendingSpecs = [];
      }
    }
  }

  return packages;
}

async function collectPythonPackages(workspacePath: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();
  const requirementsPath = join(workspacePath, 'requirements.txt');

  if (await fileExists(requirementsPath)) {
    const contents = await fs.readFile(requirementsPath, 'utf8');

    for (const line of contents.split(/\r?\n/u)) {
      const trimmed = line.trim();

      if (trimmed.length === 0 || trimmed.startsWith('#')) {
        continue;
      }

      const [name, version] = trimmed.split('==');

      if (!name || !version) {
        continue;
      }

      addPackage(packages, {
        name,
        version,
        ecosystem: 'pypi',
        purl: createPurl(name, version, 'pypi')
      });
    }
  }

  const poetryLockPath = join(workspacePath, 'poetry.lock');

  if (await fileExists(poetryLockPath)) {
    const contents = await fs.readFile(poetryLockPath, 'utf8');
    let currentName: string | undefined;
    let currentVersion: string | undefined;

    for (const line of contents.split(/\r?\n/u)) {
      const trimmed = line.trim();

      if (trimmed === '[[package]]') {
        if (currentName && currentVersion) {
          addPackage(packages, {
            name: currentName,
            version: currentVersion,
            ecosystem: 'pypi',
            purl: createPurl(currentName, currentVersion, 'pypi')
          });
        }

        currentName = undefined;
        currentVersion = undefined;
        continue;
      }

      if (trimmed.startsWith('name =')) {
        currentName = trimmed.split('=').pop()?.trim().replace(/^"|"$/gu, '') ?? undefined;
      }

      if (trimmed.startsWith('version =')) {
        currentVersion = trimmed.split('=').pop()?.trim().replace(/^"|"$/gu, '') ?? undefined;
      }
    }

    if (currentName && currentVersion) {
      addPackage(packages, {
        name: currentName,
        version: currentVersion,
        ecosystem: 'pypi',
        purl: createPurl(currentName, currentVersion, 'pypi')
      });
    }
  }

  return packages;
}

async function collectGoPackages(workspacePath: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();
  const goModPath = join(workspacePath, 'go.mod');

  if (await fileExists(goModPath)) {
    const contents = await fs.readFile(goModPath, 'utf8');
    let inRequireBlock = false;

    for (const line of contents.split(/\r?\n/u)) {
      const trimmed = line.trim();

      if (trimmed.startsWith('require (')) {
        inRequireBlock = true;
        continue;
      }

      if (inRequireBlock && trimmed === ')') {
        inRequireBlock = false;
        continue;
      }

      if (!inRequireBlock && !trimmed.startsWith('require ')) {
        continue;
      }

      const normalized = trimmed.replace(/^require\s+/u, '');
      const [name, version] = normalized.split(/\s+/u);

      if (!name || !version) {
        continue;
      }

      addPackage(packages, {
        name,
        version,
        ecosystem: 'go',
        purl: createPurl(name, version, 'go')
      });
    }
  }

  const goSumPath = join(workspacePath, 'go.sum');

  if (await fileExists(goSumPath)) {
    const contents = await fs.readFile(goSumPath, 'utf8');

    for (const line of contents.split(/\r?\n/u)) {
      const [module, version] = line.trim().split(/\s+/u);

      if (!module || !version || version.endsWith('/go.mod')) {
        continue;
      }

      addPackage(packages, {
        name: module,
        version,
        ecosystem: 'go',
        purl: createPurl(module, version, 'go')
      });
    }
  }

  return packages;
}

async function collectRubyPackages(workspacePath: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();
  const gemfileLockPath = join(workspacePath, 'Gemfile.lock');

  if (!(await fileExists(gemfileLockPath))) {
    return packages;
  }

  try {
    const contents = await fs.readFile(gemfileLockPath, 'utf8');
    let inSpecsSection = false;

    for (const rawLine of contents.split(/\r?\n/u)) {
      const line = rawLine.trimEnd();

      if (line.startsWith('GEM')) {
        continue;
      }

      if (line.trim() === 'specs:') {
        inSpecsSection = true;
        continue;
      }

      if (!line.startsWith('    ')) {
        if (inSpecsSection && line.trim().length === 0) {
          continue;
        }

        if (inSpecsSection && !line.startsWith('    ')) {
          inSpecsSection = false;
        }

        continue;
      }

      if (!inSpecsSection) {
        continue;
      }

      const trimmed = line.trim();
      const match = trimmed.match(/^([^\s(]+)\s*\(([^)]+)\)/u);

      if (!match) {
        continue;
      }

      const [, name, version] = match;

      addPackage(packages, {
        name,
        version,
        ecosystem: 'rubygems',
        purl: createPurl(name, version, 'rubygems')
      });
    }
  } catch {
    // ignore malformed Gemfile.lock
  }

  return packages;
}

async function collectCargoPackages(workspacePath: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();
  const cargoLockPath = join(workspacePath, 'Cargo.lock');

  if (!(await fileExists(cargoLockPath))) {
    return packages;
  }

  try {
    const contents = await fs.readFile(cargoLockPath, 'utf8');
    let currentName: string | undefined;
    let currentVersion: string | undefined;

    for (const line of contents.split(/\r?\n/u)) {
      const trimmed = line.trim();

      if (trimmed === '[[package]]') {
        if (currentName && currentVersion) {
          addPackage(packages, {
            name: currentName,
            version: currentVersion,
            ecosystem: 'cargo',
            purl: createPurl(currentName, currentVersion, 'cargo')
          });
        }

        currentName = undefined;
        currentVersion = undefined;
        continue;
      }

      if (trimmed.startsWith('name =')) {
        currentName = trimmed.split('=').pop()?.trim().replace(/^"|"$/gu, '') ?? undefined;
      }

      if (trimmed.startsWith('version =')) {
        currentVersion = trimmed.split('=').pop()?.trim().replace(/^"|"$/gu, '') ?? undefined;
      }
    }

    if (currentName && currentVersion) {
      addPackage(packages, {
        name: currentName,
        version: currentVersion,
        ecosystem: 'cargo',
        purl: createPurl(currentName, currentVersion, 'cargo')
      });
    }
  } catch {
    // ignore malformed Cargo.lock files
  }

  return packages;
}

async function collectJavaPackages(workspacePath: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();
  const pomPaths = await discoverFiles(workspacePath, { names: ['pom.xml'] });

  for (const pomPath of pomPaths) {
    try {
      const xml = await fs.readFile(pomPath, 'utf8');
      const dependencyRegex = /<dependency\b[^>]*>([\s\S]*?)<\/dependency>/giu;

      for (const match of xml.matchAll(dependencyRegex)) {
        const block = match[1] ?? '';
        const groupMatch = block.match(/<groupId>([^<]+)<\/groupId>/iu);
        const artifactMatch = block.match(/<artifactId>([^<]+)<\/artifactId>/iu);
        const versionMatch = block.match(/<version>([^<]+)<\/version>/iu);
        const scopeMatch = block.match(/<scope>([^<]+)<\/scope>/iu);

        const groupId = groupMatch?.[1]?.trim();
        const artifactId = artifactMatch?.[1]?.trim();
        const version = versionMatch?.[1]?.trim();
        const scope = scopeMatch?.[1]?.trim().toLowerCase();

        if (!groupId || !artifactId || !version) {
          continue;
        }

        if (scope === 'test' || scope === 'provided') {
          continue;
        }

        if (version.includes('${')) {
          continue;
        }

        const coordinate = `${groupId}:${artifactId}`;
        addPackage(packages, {
          name: coordinate,
          version,
          ecosystem: 'maven',
          purl: createPurl(coordinate, version, 'maven')
        });
      }
    } catch {
      // ignore malformed pom.xml
    }
  }

  const gradleLockPaths = await discoverFiles(workspacePath, { names: ['gradle.lockfile'] });

  for (const gradleLockPath of gradleLockPaths) {
    try {
      const contents = await fs.readFile(gradleLockPath, 'utf8');

      for (const rawLine of contents.split(/\r?\n/u)) {
        const line = rawLine.trim();

        if (!line || line.startsWith('#')) {
          continue;
        }

        const [coordinatePart, rhsPart] = line.split('=', 2);

        if (!coordinatePart || !rhsPart) {
          continue;
        }

        const coordinateSegments = coordinatePart
          .split(':')
          .map((segment) => segment.trim())
          .filter((segment) => segment.length > 0);

        if (coordinateSegments.length < 2 || coordinateSegments.length > 5) {
          continue;
        }

        const groupId = coordinateSegments[0] ?? '';
        const artifactId = coordinateSegments[1] ?? '';

        if (!groupId || !artifactId) {
          continue;
        }

        let version: string | null = null;
        let packaging: string | undefined;
        let classifier: string | undefined;

        if (coordinateSegments.length >= 3) {
          version = coordinateSegments[coordinateSegments.length - 1]?.trim() ?? null;

          if (!version || version.includes('${')) {
            continue;
          }

          const extras = coordinateSegments.slice(2, -1);

          if (extras.length === 1) {
            const candidate = extras[0];
            const normalizedCandidate = candidate.toLowerCase();

            if (KNOWN_MAVEN_PACKAGINGS.has(normalizedCandidate)) {
              packaging = candidate;
            } else {
              classifier = candidate;
            }
          } else if (extras.length === 2) {
            packaging = extras[0];
            classifier = extras[1];
          } else if (extras.length > 2) {
            continue;
          }

          if (classifier && classifier.includes('${')) {
            classifier = undefined;
          }

          if (packaging && packaging.includes('${')) {
            packaging = undefined;
          }
        }

        if (!version) {
          const fallbackVersion = rhsPart.trim();

          if (!fallbackVersion || fallbackVersion.includes('${')) {
            continue;
          }

          version = fallbackVersion;
        }

        if (!version) {
          continue;
        }

        const coordinate = `${groupId}:${artifactId}`;
        const qualifiers: Record<string, string> = {};

        if (packaging) {
          qualifiers.type = packaging;
        }

        if (classifier) {
          qualifiers.classifier = classifier;
        }

        addPackage(packages, {
          name: coordinate,
          version,
          ecosystem: 'maven',
          purl: createPurl(coordinate, version, 'maven', qualifiers)
        });
      }
    } catch {
      // ignore malformed gradle.lockfile
    }
  }

  return packages;
}

async function collectDotnetPackages(workspacePath: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();
  const lockPaths = await discoverFiles(workspacePath, { names: ['packages.lock.json'] });

  for (const lockPath of lockPaths) {
    try {
      const json = JSON.parse(await fs.readFile(lockPath, 'utf8')) as Record<string, unknown>;
      const dependencies = json.dependencies;
      const projectDependencies = (json as { project?: { frameworks?: Record<string, unknown> } }).project?.frameworks;

      const dependencySources: Array<Record<string, unknown>> = [];

      if (dependencies && typeof dependencies === 'object') {
        dependencySources.push(dependencies as Record<string, unknown>);
      }

      if (projectDependencies && typeof projectDependencies === 'object') {
        dependencySources.push(projectDependencies as Record<string, unknown>);
      }

      for (const source of dependencySources) {
        for (const framework of Object.values(source)) {
          if (!framework || typeof framework !== 'object') {
            continue;
          }

          for (const [name, metadata] of Object.entries(framework as Record<string, unknown>)) {
            if (!metadata || typeof metadata !== 'object') {
              continue;
            }

            const resolved = (metadata as { resolved?: unknown; version?: unknown }).resolved;
            const versionFallback = (metadata as { version?: unknown }).version;
            const version =
              typeof resolved === 'string'
                ? resolved
                : typeof versionFallback === 'string'
                  ? versionFallback
                  : null;

            if (!version || version.includes('$')) {
              continue;
            }

            addPackage(packages, {
              name,
              version,
              ecosystem: 'nuget',
              purl: createPurl(name, version, 'nuget')
            });
          }
        }
      }
    } catch {
      // ignore malformed lock files
    }
  }

  const projectPaths = await discoverFiles(workspacePath, { extensions: ['.csproj'] });

  for (const projectPath of projectPaths) {
    try {
      const projectContents = await fs.readFile(projectPath, 'utf8');
      const selfClosingRegex = /<PackageReference\s+([^>]*?)\/>/giu;
      const blockRegex = /<PackageReference\s+([^>]*?)(?<!\/)>([\s\S]*?)<\/PackageReference>/giu;

      for (const match of projectContents.matchAll(selfClosingRegex)) {
        const attributes = match[1] ?? '';
        const include = attributes.match(/Include="([^"]+)"/iu)?.[1]?.trim();
        let version = attributes.match(/Version="([^"]+)"/iu)?.[1]?.trim();

        if (!include) {
          continue;
        }

        if (!version || version.includes('$')) {
          continue;
        }

        addPackage(packages, {
          name: include,
          version,
          ecosystem: 'nuget',
          purl: createPurl(include, version, 'nuget')
        });
      }

      for (const match of projectContents.matchAll(blockRegex)) {
        const attributes = match[1] ?? '';
        const inner = match[2] ?? '';
        const include = attributes.match(/Include="([^"]+)"/iu)?.[1]?.trim();
        let version = attributes.match(/Version="([^"]+)"/iu)?.[1]?.trim();

        if (!version) {
          const innerMatch = inner.match(/<Version>([^<]+)<\/Version>/iu);
          version = innerMatch?.[1]?.trim();
        }

        if (!include || !version || version.includes('$')) {
          continue;
        }

        addPackage(packages, {
          name: include,
          version,
          ecosystem: 'nuget',
          purl: createPurl(include, version, 'nuget')
        });
      }
    } catch {
      // ignore malformed project files
    }
  }

  return packages;
}

async function collectOciPackages(layersPath?: string): Promise<Map<string, PackageSummary>> {
  const packages = new Map<string, PackageSummary>();

  if (!layersPath) {
    return packages;
  }

  const manifestPath = join(layersPath, 'packages.json');

  if (await fileExists(manifestPath)) {
    try {
      const json = JSON.parse(await fs.readFile(manifestPath, 'utf8')) as
        | { packages?: Array<{ name: string; version: string }> }
        | Array<{ name: string; version: string }>;

      const entries = Array.isArray(json) ? json : json.packages ?? [];

      for (const entry of entries) {
        if (!entry?.name || !entry.version) {
          continue;
        }

        addPackage(packages, {
          name: entry.name,
          version: entry.version,
          ecosystem: 'oci',
          purl: createPurl(entry.name, entry.version, 'oci')
        });
      }
    } catch {
      // ignore malformed manifests
    }
  }

  const apkInstalledPath = join(layersPath, 'apk-installed');

  if (await fileExists(apkInstalledPath)) {
    const contents = await fs.readFile(apkInstalledPath, 'utf8');

    for (const line of contents.split(/\r?\n/u)) {
      const trimmed = line.trim();

      if (trimmed.length === 0 || trimmed.startsWith('#')) {
        continue;
      }

      const match = trimmed.match(/^([^\s]+)\s+([^\s]+)$/u);

      if (!match) {
        continue;
      }

      const [, name, version] = match;
      addPackage(packages, {
        name,
        version,
        ecosystem: 'apk',
        purl: createPurl(name, version, 'apk')
      });
    }
  }

  const dpkgStatusPath = join(layersPath, 'var', 'lib', 'dpkg', 'status');

  if (await fileExists(dpkgStatusPath)) {
    const contents = await fs.readFile(dpkgStatusPath, 'utf8');
    let currentName: string | undefined;
    let currentVersion: string | undefined;

    for (const rawLine of contents.split(/\r?\n/u)) {
      const line = rawLine.trim();

      if (line.length === 0) {
        if (currentName && currentVersion) {
          addPackage(packages, {
            name: currentName,
            version: currentVersion,
            ecosystem: 'deb',
            purl: createPurl(currentName, currentVersion, 'deb')
          });
        }

        currentName = undefined;
        currentVersion = undefined;
        continue;
      }

      if (line.startsWith('Package:')) {
        currentName = line.slice('Package:'.length).trim();
      } else if (line.startsWith('Version:')) {
        currentVersion = line.slice('Version:'.length).trim();
      }
    }

    if (currentName && currentVersion) {
      addPackage(packages, {
        name: currentName,
        version: currentVersion,
        ecosystem: 'deb',
        purl: createPurl(currentName, currentVersion, 'deb')
      });
    }
  }

  const rpmPackagesPath = join(layersPath, 'rpm-packages.json');

  if (await fileExists(rpmPackagesPath)) {
    try {
      const json = JSON.parse(await fs.readFile(rpmPackagesPath, 'utf8')) as
        | { packages?: Array<{ name?: string; version?: string }> }
        | Array<{ name?: string; version?: string }>;

      const entries = Array.isArray(json) ? json : json.packages ?? [];

      for (const entry of entries) {
        if (!entry?.name || !entry.version) {
          continue;
        }

        addPackage(packages, {
          name: entry.name,
          version: entry.version,
          ecosystem: 'rpm',
          purl: createPurl(entry.name, entry.version, 'rpm')
        });
      }
    } catch {
      // ignore malformed rpm manifests
    }
  }

  return packages;
}

function inferSpdxId(contents: string): string | undefined {
  const normalized = contents.toLowerCase().replace(/\s+/gu, ' ');
  // Lisansin kendisi metnin basinda adini verir; baska yerde gecen "GPL ile uyumlu" gibi atiflar sayilmaz.
  const heading = normalized.slice(0, 400);

  if (heading.includes('gnu affero general public license')) {
    return 'AGPL-3.0-only';
  }

  if (heading.includes('gnu lesser general public license')) {
    return heading.includes('version 2.1') ? 'LGPL-2.1-only' : 'LGPL-3.0-only';
  }

  if (heading.includes('gnu library general public license')) {
    return 'LGPL-2.0-only';
  }

  if (heading.includes('mozilla public license')) {
    return 'MPL-2.0';
  }

  if (normalized.includes('python software foundation license')) {
    return 'Python-2.0';
  }

  if (normalized.includes('mit license') || normalized.includes('permission is hereby granted, free of charge')) {
    return 'MIT';
  }

  if (normalized.includes('apache license')) {
    return 'Apache-2.0';
  }

  if (normalized.includes('bsd 3-clause')) {
    return 'BSD-3-Clause';
  }

  if (normalized.includes('bsd 2-clause')) {
    return 'BSD-2-Clause';
  }

  if (normalized.includes('redistribution and use in source and binary forms')) {
    return normalized.includes('neither the name') || normalized.includes('may be used to endorse or promote')
      ? 'BSD-3-Clause'
      : 'BSD-2-Clause';
  }

  if (normalized.includes('permission to use, copy, modify, and/or distribute this software for any purpose')) {
    return normalized.includes('provided that the above copyright notice') ? 'ISC' : '0BSD';
  }

  if (normalized.includes('this is free and unencumbered software released into the public domain')) {
    return 'Unlicense';
  }

  if (normalized.includes('cc0 1.0 universal')) {
    return 'CC0-1.0';
  }

  if (heading.includes('gnu general public license')) {
    return heading.includes('version 2') ? 'GPL-2.0-only' : 'GPL-3.0-only';
  }

  return undefined;
}

/** npm paketinde lisans dosyasinin yanindaki package.json'da beyan edilen SPDX ifadesi (en guvenilir kaynak). */
async function declaredNpmLicense(licenseFilePath: string): Promise<string | undefined> {
  try {
    const manifest = JSON.parse(await fs.readFile(join(dirname(licenseFilePath), 'package.json'), 'utf8')) as {
      license?: unknown;
      licenses?: unknown;
    };
    if (typeof manifest.license === 'string' && /^[A-Za-z0-9.+\-() ]+$/u.test(manifest.license.trim())) {
      return manifest.license.trim();
    }
  } catch {
    // package.json yoksa ya da okunamazsa metinden tahmine dusulur.
  }
  return undefined;
}

function inferPackageName(workspacePath: string, filePath: string): string | undefined {
  const relativePath = relative(workspacePath, filePath);
  const segments = relativePath.split(/\\|\//u).filter((segment) => segment.length > 0);

  const nodeModulesIndex = segments.lastIndexOf('node_modules');

  if (nodeModulesIndex >= 0 && segments.length > nodeModulesIndex + 1) {
    const firstSegment = segments[nodeModulesIndex + 1];

    if (firstSegment?.startsWith('@') && segments.length > nodeModulesIndex + 2) {
      return `${firstSegment}/${segments[nodeModulesIndex + 2]}`;
    }

    return firstSegment;
  }

  const sitePackagesIndex = segments.findIndex((segment) => segment.endsWith('site-packages'));

  if (sitePackagesIndex >= 0 && segments.length > sitePackagesIndex + 1) {
    return segments[sitePackagesIndex + 1];
  }

  const gemsIndex = segments.findIndex((segment) => segment.endsWith('gems'));

  if (gemsIndex >= 0 && segments.length > gemsIndex + 1) {
    const gemSegment = segments[gemsIndex + 1];
    const versionSeparator = gemSegment.lastIndexOf('-');

    if (versionSeparator > 0) {
      return gemSegment.slice(0, versionSeparator);
    }

    return gemSegment;
  }

  const cargoIndex = segments.findIndex((segment) => segment === 'registry' || segment === 'git');

  if (cargoIndex >= 0 && segments.length > cargoIndex + 2) {
    const candidate = segments[segments.length - 2];
    const versionSeparator = candidate.lastIndexOf('-');

    if (versionSeparator > 0) {
      return candidate.slice(0, versionSeparator);
    }

    return candidate;
  }

  const vcsIndex = segments.findIndex((segment) => segment === 'github.com' || segment === 'gitlab.com' || segment === 'bitbucket.org');

  if (vcsIndex >= 0 && segments.length > vcsIndex + 1) {
    return segments.slice(vcsIndex, segments.length - 1).join('/');
  }

  return undefined;
}

async function detectLicenseFiles(workspacePath: string): Promise<LicenseFinding[]> {
  const findings: LicenseFinding[] = [];

  async function walk(currentPath: string): Promise<void> {
    const entries = await fs.readdir(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const entryPath = join(currentPath, entry.name);

      if (entry.isDirectory()) {
        await walk(entryPath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      if (!isLicenseFileName(entry.name)) {
        continue;
      }

      const declared = entryPath.includes('node_modules') ? await declaredNpmLicense(entryPath) : undefined;
      const spdxId = declared ?? inferSpdxId(await fs.readFile(entryPath, 'utf8'));

      if (!spdxId) {
        continue;
      }

      findings.push({
        path: entryPath,
        spdxId,
        packageName: inferPackageName(workspacePath, entryPath)
      });
    }
  }

  await walk(workspacePath);
  return findings;
}

function isLicenseFileName(filename: string): boolean {
  const trimmed = filename.trim();

  if (trimmed.length === 0) {
    return false;
  }

  const upper = trimmed.toUpperCase();

  return LICENSE_PREFIXES.some((prefix) => {
    if (upper === prefix) {
      return true;
    }

    const prefixWithDot = `${prefix}.`;
    const prefixWithHyphen = `${prefix}-`;
    const prefixWithUnderscore = `${prefix}_`;

    return (
      upper.startsWith(prefixWithDot) ||
      upper.startsWith(prefixWithHyphen) ||
      upper.startsWith(prefixWithUnderscore)
    );
  });
}

function mapEcosystemToOsv(ecosystem: PackageEcosystem): string {
  switch (ecosystem) {
    case 'npm':
      return 'npm';
    case 'pypi':
      return 'PyPI';
    case 'go':
      return 'Go';
    case 'rubygems':
      return 'RubyGems';
    case 'cargo':
      return 'crates.io';
    case 'maven':
      return 'Maven';
    case 'nuget':
      return 'NuGet';
    case 'apk':
      return 'Alpine';
    case 'deb':
      return 'Debian';
    case 'rpm':
      return 'RPM';
    default:
      return 'OCI';
  }
}

export interface OsvRetryOptions {
  readonly maxAttempts?: number;
  readonly timeoutMs?: number;
  readonly baseDelayMs?: number;
}

async function queryOsvBatch(
  packages: PackageSummary[],
  fetchImpl: typeof fetch,
  cache: Map<string, OsvVulnerability[]>,
  persistCache: ((key: string, vulnerabilities: OsvVulnerability[]) => Promise<void>) | undefined,
  retryOptions: OsvRetryOptions | undefined
): Promise<VulnerabilityFinding[]> {
  const timeoutMs = retryOptions?.timeoutMs ?? OSV_BATCH_TIMEOUT_MS;
  const maxAttempts = Math.max(1, retryOptions?.maxAttempts ?? OSV_BATCH_MAX_ATTEMPTS);
  const retryBaseMs = retryOptions?.baseDelayMs ?? OSV_BATCH_RETRY_BASE_MS;
  const queries: Array<{ package: { name: string; ecosystem: string }; version: string }> = [];
  const pendingKeys: string[] = [];

  for (const pkg of packages) {
    const key = pkg.purl;

    if (!cache.has(key)) {
      queries.push({
        package: { name: pkg.name, ecosystem: mapEcosystemToOsv(pkg.ecosystem) },
        version: pkg.version
      });
      pendingKeys.push(key);
    }
  }

  if (queries.length > 0) {
    assertNetworkFetchAllowed('OSV vulnerability queries');
    const persistOperations: Array<Promise<void>> = [];

    let lastError: unknown;

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetchImpl(OSV_BATCH_ENDPOINT, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ queries }),
          signal: controller.signal
        });

        clearTimeout(timeout);

        if (!response.ok) {
          throw new Error(`OSV query failed with status ${response.status}`);
        }

        const payload = (await response.json()) as {
          results?: Array<{ vulns?: OsvVulnerability[] }>;
        };

        payload.results?.forEach((result, index) => {
          const key = pendingKeys[index];

          if (key) {
            const vulnerabilities = result.vulns ?? [];
            cache.set(key, vulnerabilities);
            if (persistCache) {
              persistOperations.push(persistCache(key, vulnerabilities));
            }
          }
        });

        if (persistOperations.length > 0) {
          await Promise.allSettled(persistOperations);
        }

        lastError = undefined;
        break;
      } catch (error) {
        clearTimeout(timeout);
        lastError = error;

        if (attempt < maxAttempts - 1) {
          const delay = retryBaseMs * 2 ** attempt;
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }

    if (lastError) {
      const message = lastError instanceof Error ? lastError.message : String(lastError ?? '');
      console.warn(`Failed to query OSV batch endpoint: ${message}`);
    }
  }

  return packages.map((pkg) => {
    const key = pkg.purl;
    return {
      package: pkg,
      vulnerabilities: cache.get(key) ?? []
    };
  });
}

function buildCycloneDx(
  packages: PackageSummary[],
  licenses: LicenseFinding[],
  now: Date
): CycloneDxBom {
  const licenseMap = new Map<string, string[]>();

  for (const finding of licenses) {
    if (!finding.packageName) {
      continue;
    }

    const existing = licenseMap.get(finding.packageName) ?? [];

    if (!existing.includes(finding.spdxId)) {
      existing.push(finding.spdxId);
      licenseMap.set(finding.packageName, existing);
    }
  }

  const components = packages.map((pkg) => {
    const licenseIds = licenseMap.get(pkg.name) ?? [];

    return {
      bomRef: pkg.purl,
      name: pkg.name,
      version: pkg.version,
      type: 'library' as const,
      purl: pkg.purl,
      ...(licenseIds.length > 0
        ? { licenses: licenseIds.map((id) => ({ license: { id } })) }
        : {})
    };
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: [
        {
          vendor: 'Otomatik',
          name: 'oss-scanner',
          version: '0.1.0'
        }
      ]
    },
    components
  };
}

export async function runScanners(workspacePath: string, options: ScannerOptions = {}): Promise<ScannerResult> {
  const packagesMap = new Map<string, PackageSummary>();
  const [
    nodePackages,
    pythonPackages,
    goPackages,
    rubyPackages,
    cargoPackages,
    javaPackages,
    dotnetPackages,
    ociPackages
  ] = await Promise.all([
    collectNodePackages(workspacePath),
    collectPythonPackages(workspacePath),
    collectGoPackages(workspacePath),
    collectRubyPackages(workspacePath),
    collectCargoPackages(workspacePath),
    collectJavaPackages(workspacePath),
    collectDotnetPackages(workspacePath),
    collectOciPackages(options.ociLayersPath)
  ]);

  for (const pkg of [
    ...nodePackages.values(),
    ...pythonPackages.values(),
    ...goPackages.values(),
    ...rubyPackages.values(),
    ...cargoPackages.values(),
    ...javaPackages.values(),
    ...dotnetPackages.values(),
    ...ociPackages.values()
  ]) {
    addPackage(packagesMap, pkg);
  }

  const packages = Array.from(packagesMap.values()).sort((a, b) => a.purl.localeCompare(b.purl));
  const licenseFindings = await detectLicenseFiles(workspacePath);
  const fetchImpl = options.fetchImpl ?? fetch;
  const cache = options.cache ?? new Map<string, OsvVulnerability[]>();
  const vulnerabilities = await queryOsvBatch(
    packages,
    fetchImpl,
    cache,
    options.persistCache,
    options.osvRetryOptions
  );
  const now = options.now?.() ?? new Date();
  const bom = buildCycloneDx(packages, licenseFindings, now);

  return {
    packages,
    bom,
    licenses: licenseFindings,
    vulnerabilities
  };
}
