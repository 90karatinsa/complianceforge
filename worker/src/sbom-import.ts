// SPDX-License-Identifier: MIT

import { createHash } from 'node:crypto';

import type {
  LicenseFinding,
  PackageSummary,
  ScannerResult,
  VulnerabilityFinding
} from './scanners.js';

type SupportedFormat = 'CycloneDX' | 'SPDX';

interface CycloneDxComponent {
  readonly bomRef?: string;
  readonly name?: string;
  readonly version?: string;
  readonly purl?: string;
  readonly licenses?: Array<{ license?: { id?: string } | undefined }>;
  readonly type?: string;
}

interface CycloneDxDocument {
  readonly bomFormat?: string;
  readonly specVersion?: string;
  readonly metadata?: Record<string, unknown>;
  readonly components?: CycloneDxComponent[];
}

interface SpdxExternalRef {
  readonly referenceType?: string;
  readonly referenceLocator?: string;
}

interface SpdxPackage {
  readonly name?: string;
  readonly versionInfo?: string;
  readonly licenseConcluded?: string;
  readonly licenseDeclared?: string;
  readonly externalRefs?: SpdxExternalRef[];
}

interface SpdxDocument {
  readonly spdxVersion?: string;
  readonly packages?: SpdxPackage[];
}

interface NormalizedResult {
  readonly format: SupportedFormat;
  readonly bom: Record<string, unknown>;
  readonly packages: PackageSummary[];
  readonly licenses: LicenseFinding[];
  readonly vulnerabilities: VulnerabilityFinding[];
}

function createFallbackPurl(name: string, version: string): string {
  const encodedName = encodeURIComponent(name.replace(/\s+/gu, '-').toLowerCase());
  const safeVersion = encodeURIComponent(version || '0.0.0');
  return `pkg:generic/${encodedName}@${safeVersion}`;
}

function inferEcosystem(purl: string | undefined, componentType?: string): PackageSummary['ecosystem'] {
  if (typeof purl === 'string') {
    const normalized = purl.toLowerCase();

    if (normalized.startsWith('pkg:npm/')) {
      return 'npm';
    }

    if (normalized.startsWith('pkg:pypi/')) {
      return 'pypi';
    }

    if (normalized.startsWith('pkg:golang/')) {
      return 'go';
    }

    if (normalized.startsWith('pkg:gem/')) {
      return 'rubygems';
    }

    if (normalized.startsWith('pkg:cargo/')) {
      return 'cargo';
    }

    if (normalized.startsWith('pkg:apk/')) {
      return 'apk';
    }

    if (normalized.startsWith('pkg:deb/')) {
      return 'deb';
    }

    if (normalized.startsWith('pkg:rpm/')) {
      return 'rpm';
    }

    if (normalized.startsWith('pkg:oci/')) {
      return 'oci';
    }
  }

  const normalizedType = componentType?.toLowerCase();

  if (normalizedType === 'container') {
    return 'oci';
  }

  return 'oci';
}

function toPackageSummary(
  name: string,
  version: string,
  purl: string | undefined,
  componentType?: string
): PackageSummary {
  const ecosystem = inferEcosystem(purl, componentType);

  return {
    name,
    version,
    ecosystem,
    purl: purl && purl.trim().length > 0 ? purl : createFallbackPurl(name, version)
  } satisfies PackageSummary;
}

function addPackageUnique(target: Map<string, PackageSummary>, summary: PackageSummary): void {
  if (!summary.name || !summary.version || !summary.purl) {
    return;
  }

  const key = summary.purl.toLowerCase();

  if (!target.has(key)) {
    target.set(key, summary);
  }
}

function toLicenseFindings(
  component: { name?: string; licenses?: Array<{ license?: { id?: string } | undefined }> },
  componentPath: string
): LicenseFinding[] {
  if (!Array.isArray(component.licenses)) {
    return [];
  }

  const findings: LicenseFinding[] = [];

  for (const entry of component.licenses) {
    const spdxId = entry?.license?.id;

    if (typeof spdxId !== 'string' || spdxId.trim().length === 0) {
      continue;
    }

    findings.push({
      path: componentPath,
      spdxId,
      packageName: component.name
    });
  }

  return findings;
}

function normalizeCycloneDx(document: CycloneDxDocument): NormalizedResult {
  const components = Array.isArray(document.components) ? document.components : [];
  const packages = new Map<string, PackageSummary>();
  const licenses: LicenseFinding[] = [];

  for (const component of components) {
    if (!component || typeof component !== 'object') {
      continue;
    }

    const name = typeof component.name === 'string' ? component.name : undefined;
    const version = typeof component.version === 'string' ? component.version : undefined;

    if (!name || !version) {
      continue;
    }

    const summary = toPackageSummary(name, version, component.purl, component.type);
    addPackageUnique(packages, summary);
    licenses.push(...toLicenseFindings(component, component.bomRef ?? name));
  }

  const bom: Record<string, unknown> = {
    bomFormat: 'CycloneDX',
    specVersion: document.specVersion ?? '1.5',
    version: 1,
    metadata: document.metadata ?? {},
    components
  };

  return {
    format: 'CycloneDX',
    bom,
    packages: Array.from(packages.values()),
    licenses,
    vulnerabilities: []
  } satisfies NormalizedResult;
}

function extractSpdxPurl(pkg: SpdxPackage): string | undefined {
  if (!Array.isArray(pkg.externalRefs)) {
    return undefined;
  }

  for (const ref of pkg.externalRefs) {
    if (ref?.referenceType?.toLowerCase() === 'purl' && typeof ref.referenceLocator === 'string') {
      return ref.referenceLocator;
    }
  }

  return undefined;
}

function normalizeSpdx(document: SpdxDocument): NormalizedResult {
  const packages = new Map<string, PackageSummary>();
  const licenses: LicenseFinding[] = [];

  const packageEntries = Array.isArray(document.packages) ? document.packages : [];

  for (const pkg of packageEntries) {
    if (!pkg || typeof pkg !== 'object') {
      continue;
    }

    const name = typeof pkg.name === 'string' ? pkg.name : undefined;
    const version = typeof pkg.versionInfo === 'string' ? pkg.versionInfo : undefined;

    if (!name || !version) {
      continue;
    }

    const purl = extractSpdxPurl(pkg);
    const summary = toPackageSummary(name, version, purl);
    addPackageUnique(packages, summary);

    const licenseExpression =
      typeof pkg.licenseConcluded === 'string' && pkg.licenseConcluded.trim().length > 0
        ? pkg.licenseConcluded
        : typeof pkg.licenseDeclared === 'string' && pkg.licenseDeclared.trim().length > 0
          ? pkg.licenseDeclared
          : undefined;

    if (licenseExpression) {
      const entries = extractLicenseIds(licenseExpression);

      for (const spdxId of entries) {
        licenses.push({
          path: name,
          spdxId,
          packageName: name
        });
      }
    }
  }

  const bom: Record<string, unknown> = {
    spdxVersion: document.spdxVersion ?? 'SPDX-2.3',
    packages: packageEntries
  };

  return {
    format: 'SPDX',
    bom,
    packages: Array.from(packages.values()),
    licenses,
    vulnerabilities: []
  } satisfies NormalizedResult;
}

function normalizeFormat(value: string): SupportedFormat {
  const normalized = value.trim().toLowerCase();

  if (normalized === 'cyclonedx') {
    return 'CycloneDX';
  }

  if (normalized === 'spdx') {
    return 'SPDX';
  }

  throw new Error(`Unsupported SBOM format: ${value}`);
}

export interface NormalizeSbomInput {
  readonly format: string;
  readonly document: unknown;
}

export function normalizeImportedSbom(input: NormalizeSbomInput): NormalizedResult {
  if (!input || typeof input !== 'object') {
    throw new Error('SBOM input must be an object.');
  }

  const format = normalizeFormat(input.format);

  if (!input.document || typeof input.document !== 'object') {
    throw new Error('SBOM document must be a JSON object.');
  }

  if (format === 'CycloneDX') {
    return normalizeCycloneDx(input.document as CycloneDxDocument);
  }

  return normalizeSpdx(input.document as SpdxDocument);
}

export function buildScannerResultFromImport(result: NormalizedResult): ScannerResult {
  const licenseMap = new Map<string, string[]>();

  for (const license of result.licenses) {
    if (!license.packageName) {
      continue;
    }

    const current = licenseMap.get(license.packageName) ?? [];

    if (!current.includes(license.spdxId)) {
      current.push(license.spdxId);
    }

    licenseMap.set(license.packageName, current);
  }

  const components =
    result.format === 'CycloneDX'
      ? ((result.bom.components as CycloneDxDocument['components']) ?? [])
      : result.packages.map((pkg) => {
          const licenses = (licenseMap.get(pkg.name) ?? []).map((id) => ({ license: { id } }));

          return {
            bomRef: pkg.purl,
            name: pkg.name,
            version: pkg.version,
            type: 'library',
            purl: pkg.purl,
            ...(licenses.length > 0 ? { licenses } : {})
          } satisfies CycloneDxComponent;
        });

  return {
    packages: result.packages,
    licenses: result.licenses,
    vulnerabilities: result.vulnerabilities,
    bom: {
      ...(result.format === 'CycloneDX'
        ? result.bom
        : {
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            version: 1,
            metadata: { generated: new Date().toISOString() },
            components
          })
    }
  } satisfies ScannerResult;
}

export function hashSbomDocument(document: Record<string, unknown>): string {
  const serialized = JSON.stringify(document);
  return createHash('sha256').update(serialized).digest('hex');
}

function extractLicenseIds(expression: string): string[] {
  const matches = expression.match(/[A-Za-z0-9.+-]+(?:-WITH-[A-Za-z0-9.+-]+)?/gu) ?? [];
  const unique = new Set<string>();

  for (const token of matches) {
    const normalized = token.trim();

    if (!normalized || normalized === 'AND' || normalized === 'OR' || normalized === 'WITH') {
      continue;
    }

    unique.add(normalized);
  }

  return Array.from(unique);
}

