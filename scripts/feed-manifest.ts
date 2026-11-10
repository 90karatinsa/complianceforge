// SPDX-License-Identifier: MIT

import { readFile } from 'node:fs/promises';
import { createGunzip } from 'node:zlib';
import { verify as verifySignature } from 'node:crypto';
import { Buffer } from 'node:buffer';

export const MAX_FEED_ARCHIVE_BYTES = 10 * 1024 * 1024; // 10 MiB

export class FeedArchiveTooLargeError extends Error {
  public readonly limitBytes: number;

  constructor(limitBytes: number) {
    super(`Feed archive exceeds maximum size of ${Math.floor(limitBytes / (1024 * 1024))} MiB.`);
    this.name = 'FeedArchiveTooLargeError';
    this.limitBytes = limitBytes;
  }
}

async function gunzipWithLimit(buffer: Buffer, limitBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const gunzip = createGunzip();
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const finalizeReject = (error: Error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };

    gunzip.on('data', (chunk) => {
      total += chunk.byteLength;
      if (total > limitBytes) {
        finalizeReject(new FeedArchiveTooLargeError(limitBytes));
        gunzip.destroy();
        return;
      }
      chunks.push(chunk);
    });

    gunzip.on('error', (error) => {
      const failure =
        error instanceof Error
          ? new Error('Feed archive could not be decompressed.', { cause: error })
          : new Error('Feed archive could not be decompressed.');
      finalizeReject(failure);
    });

    gunzip.on('end', () => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(Buffer.concat(chunks));
    });

    gunzip.end(buffer);
  });
}

export interface LoadedFeedArchive {
  readonly manifest: Record<string, unknown>;
  readonly signature: string | null;
}

export async function loadFeedArchive(filePath: string): Promise<LoadedFeedArchive> {
  const buffer = await readFile(filePath);
  let decompressed: Buffer;

  try {
    decompressed = await gunzipWithLimit(buffer, MAX_FEED_ARCHIVE_BYTES);
  } catch (error) {
    if (error instanceof FeedArchiveTooLargeError) {
      throw error;
    }
    if (error instanceof Error) {
      throw error;
    }
    throw new Error('Feed archive could not be decompressed.');
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(decompressed.toString('utf8'));
  } catch (error) {
    throw new Error('Feed archive is not valid JSON.', { cause: error instanceof Error ? error : undefined });
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Feed archive payload must be an object.');
  }

  const manifest = (parsed as { manifest?: unknown }).manifest;

  if (!manifest || typeof manifest !== 'object') {
    throw new Error('Feed archive is missing a manifest.');
  }

  const signatureValue = (parsed as { signature?: unknown }).signature;
  const signature = typeof signatureValue === 'string' && signatureValue.trim().length > 0 ? signatureValue : null;

  assertManifestWithinLimit(manifest as Record<string, unknown>);

  return { manifest: manifest as Record<string, unknown>, signature };
}

export interface VerifyFeedSignatureOptions {
  readonly manifest: Record<string, unknown>;
  readonly signature: string | null;
  readonly publicKey?: string | null;
}

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const ED25519_SIGNATURE_BYTES = 64;
const ED25519_PUBLIC_KEY_DER_BYTES = 44;

function decodeCanonicalBase64Url(value: string, field: string): Buffer {
  if (!BASE64URL_PATTERN.test(value)) {
    throw new Error(`${field} must be a base64url string.`);
  }

  let decoded: Buffer;

  try {
    decoded = Buffer.from(value, 'base64url');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid base64url payload.';
    throw new Error(`${field} must decode from base64url: ${message}`);
  }

  const canonical = decoded.toString('base64url');

  if (canonical !== value) {
    throw new Error(`${field} must use canonical base64url encoding.`);
  }

  return decoded;
}

export async function verifyFeedSignature(options: VerifyFeedSignatureOptions): Promise<void> {
  const rawSignature = typeof options.signature === 'string' ? options.signature.trim() : '';
  const hasSignature = rawSignature.length > 0;
  const rawPublicKey = typeof options.publicKey === 'string' ? options.publicKey.trim() : '';
  const hasPublicKey = rawPublicKey.length > 0;

  if (!hasSignature) {
    if (hasPublicKey) {
      throw new Error('Signature required when feed public key is configured.');
    }
    return;
  }

  if (!hasPublicKey) {
    throw new Error('Feed signature provided but no public key configured.');
  }

  const decodedSignature = decodeCanonicalBase64Url(rawSignature, 'Feed signature');

  if (decodedSignature.byteLength !== ED25519_SIGNATURE_BYTES) {
    throw new Error('Feed signature must decode to 64 bytes (Ed25519 signature).');
  }

  const decodedPublicKey = decodeCanonicalBase64Url(rawPublicKey, 'Feed public key');

  if (decodedPublicKey.byteLength !== ED25519_PUBLIC_KEY_DER_BYTES) {
    throw new Error('Feed public key must be a DER-encoded Ed25519 SPKI (44 bytes).');
  }

  const manifestBuffer = Buffer.from(canonicalizeManifest(options.manifest), 'utf8');

  const isValid = verifySignature(null, manifestBuffer, {
    key: decodedPublicKey,
    format: 'der',
    type: 'spki'
  }, decodedSignature);

  if (!isValid) {
    throw new Error('Feed signature verification failed.');
  }
}

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { readonly [key: string]: JsonValue };

function stableSerialize(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  if (typeof value === 'number') {
    return Number.isFinite(value) ? JSON.stringify(value) : 'null';
  }

  if (typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const serialized = value.map((entry) => stableSerialize(entry ?? null)).join(',');
    return `[${serialized}]`;
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .map(([key, entryValue]) => [key, stableSerialize(entryValue)] as const)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

    const serialized = entries.map(([key, entry]) => `${JSON.stringify(key)}:${entry}`).join(',');
    return `{${serialized}}`;
  }

  return 'null';
}

export function canonicalizeManifest(manifest: Record<string, unknown>): string {
  return stableSerialize(manifest as JsonValue);
}

export function assertManifestWithinLimit(manifest: Record<string, unknown>): void {
  const serialized = canonicalizeManifest(manifest);
  const size = Buffer.byteLength(serialized, 'utf8');

  if (size > MAX_FEED_ARCHIVE_BYTES) {
    throw new FeedArchiveTooLargeError(MAX_FEED_ARCHIVE_BYTES);
  }
}

function compareVersionStrings(a: string, b: string): number {
  const tokenize = (value: string): number[] =>
    value
      .split(/[^0-9]+/gu)
      .filter((segment) => segment.length > 0)
      .map((segment) => Number.parseInt(segment, 10))
      .filter((value) => Number.isFinite(value));

  const aTokens = tokenize(a);
  const bTokens = tokenize(b);
  const length = Math.max(aTokens.length, bTokens.length);

  for (let index = 0; index < length; index += 1) {
    const aValue = aTokens[index] ?? 0;
    const bValue = bTokens[index] ?? 0;

    if (aValue > bValue) {
      return 1;
    }

    if (aValue < bValue) {
      return -1;
    }
  }

  if (a > b) {
    return 1;
  }

  if (a < b) {
    return -1;
  }

  return 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export interface FeedPackageEntry {
  readonly filename: string;
  readonly sha256: string;
  readonly sizeBytes: number | null;
  readonly storedAt: string | null;
}

export interface FeedVulnerabilityEntry {
  readonly packagePurl: string;
  readonly vulnerabilities: unknown[];
  readonly fetchedAt: Date | null;
}

export interface NormalizedFeedManifest {
  readonly feedVersion: string;
  readonly packages: FeedPackageEntry[];
  readonly vulnerabilities: FeedVulnerabilityEntry[];
  readonly minimumDowngradeVersion: string;
}

function normalizeSha256(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('Feed manifest package entries must include a sha256 string.');
  }

  const trimmed = value.trim();

  if (!/^[a-f0-9]{64}$/iu.test(trimmed)) {
    throw new Error('Feed manifest package sha256 values must be 64 hex characters.');
  }

  return trimmed.toLowerCase();
}

function normalizeSizeBytes(value: unknown): number | null {
  if (value === undefined || value === null) {
    return null;
  }

  const normalized = typeof value === 'string' ? Number.parseInt(value, 10) : Number(value);

  if (!Number.isFinite(normalized) || normalized < 0) {
    throw new Error('Feed manifest package size_bytes must be a non-negative integer.');
  }

  if (!Number.isSafeInteger(normalized)) {
    throw new Error('Feed manifest package size_bytes exceeds safe integer range.');
  }

  return normalized;
}

function normalizeStoredAt(value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value !== 'string') {
    throw new Error('Feed manifest package stored_at must be a string when provided.');
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeFetchedAt(value: unknown): Date | null {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value !== 'string') {
    throw new Error('Feed manifest vulnerability fetched_at values must be ISO strings when provided.');
  }

  const trimmed = value.trim();

  if (trimmed.length === 0) {
    return null;
  }

  const timestamp = Date.parse(trimmed);

  if (Number.isNaN(timestamp)) {
    throw new Error('Feed manifest vulnerability fetched_at values must be valid ISO timestamps.');
  }

  return new Date(timestamp);
}

function normalizeMinimumDowngradeVersion(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('Feed manifest must include a minimum_downgrade_version string.');
  }

  const trimmed = value.trim();

  if (trimmed.length === 0) {
    throw new Error('Feed manifest minimum_downgrade_version must not be empty.');
  }

  return trimmed;
}

export function parseFeedManifest(manifest: Record<string, unknown>): NormalizedFeedManifest {
  assertManifestWithinLimit(manifest);

  const versionValue = manifest['feed_version'];

  if (typeof versionValue !== 'string' || versionValue.trim().length === 0) {
    throw new Error('Feed manifest must include a feed_version string.');
  }

  const feedVersion = versionValue.trim();
  const minimumDowngradeVersion = normalizeMinimumDowngradeVersion(
    manifest['minimum_downgrade_version']
  );

  if (compareVersionStrings(minimumDowngradeVersion, feedVersion) > 0) {
    throw new Error('Feed manifest minimum_downgrade_version must not exceed feed_version.');
  }

  const rawPackages = Array.isArray(manifest['packages']) ? manifest['packages'] : [];
  const packages: FeedPackageEntry[] = rawPackages.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new Error(`Feed manifest package at index ${index} must be an object.`);
    }

    const filenameValue = entry.filename;

    if (typeof filenameValue !== 'string' || filenameValue.trim().length === 0) {
      throw new Error('Feed manifest packages must include a filename.');
    }

    const filename = filenameValue.trim();
    const sha256 = normalizeSha256(entry.sha256);
    const sizeBytes = normalizeSizeBytes(entry.size_bytes);
    const storedAt = normalizeStoredAt(entry.stored_at);

    return { filename, sha256, sizeBytes, storedAt } satisfies FeedPackageEntry;
  });

  const rawVulnerabilities = Array.isArray(manifest['vulnerabilities']) ? manifest['vulnerabilities'] : [];
  const vulnerabilities: FeedVulnerabilityEntry[] = rawVulnerabilities.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new Error(`Feed manifest vulnerability at index ${index} must be an object.`);
    }

    const purlValue = entry.package_purl;

    if (typeof purlValue !== 'string' || purlValue.trim().length === 0) {
      throw new Error('Feed manifest vulnerabilities must include a package_purl.');
    }

    const packagePurl = purlValue.trim();
    const vulnerabilitiesList = Array.isArray(entry.vulnerabilities) ? entry.vulnerabilities : [];
    const fetchedAt = normalizeFetchedAt(entry.fetched_at);

    return { packagePurl, vulnerabilities: vulnerabilitiesList, fetchedAt } satisfies FeedVulnerabilityEntry;
  });

  return { feedVersion, packages, vulnerabilities, minimumDowngradeVersion } satisfies NormalizedFeedManifest;
}

