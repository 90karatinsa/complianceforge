// SPDX-License-Identifier: MIT

import { createHash } from 'node:crypto';
import { gzip as gzipCallback } from 'node:zlib';
import { promisify } from 'node:util';

const gzip = promisify(gzipCallback);

export interface EvidencePackEntry {
  readonly path: string;
  readonly data: unknown;
  readonly mediaType?: string;
}

export interface EvidencePackSignerInput {
  readonly data: Buffer;
  readonly hash: string;
  readonly hashAlgorithm: string;
}

export interface EvidencePackSignerResult {
  readonly signature: string;
  readonly algorithm?: string;
}

export interface BuildEvidencePackOptions {
  readonly tenantId: string;
  readonly projectId: string;
  readonly scanId: string;
  readonly feedVersion?: string | null;
  readonly noticeVersionId?: string | null;
  readonly entries: ReadonlyArray<EvidencePackEntry>;
  readonly purgeManifest?: Record<string, unknown> | null;
  readonly clock?: () => Date;
  readonly signer?: (input: EvidencePackSignerInput) => Promise<EvidencePackSignerResult | void>;
}

export interface EvidencePackResult {
  readonly archive: Buffer;
  readonly manifest: Record<string, unknown>;
  readonly hashAlgorithm: string;
  readonly signature?: { readonly algorithm: string; readonly value: string };
}

function stableSerialize(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return JSON.stringify(null);
    }

    return JSON.stringify(value);
  }

  if (typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const serialized = value.map((item) => stableSerialize(item));
    return `[${serialized.join(',')}]`;
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, itemValue]) => itemValue !== undefined)
      .map(([key, itemValue]) => [key, itemValue] as const)
      .sort(([a], [b]) => a.localeCompare(b));

    const parts = entries.map(([key, itemValue]) => `${JSON.stringify(key)}:${stableSerialize(itemValue)}`);
    return `{${parts.join(',')}}`;
  }

  return JSON.stringify(String(value));
}

function normalizeEntryBuffer(data: unknown): Buffer {
  if (Buffer.isBuffer(data)) {
    return data;
  }

  if (typeof data === 'string') {
    return Buffer.from(data, 'utf8');
  }

  if (data === null || data === undefined) {
    return Buffer.from('null', 'utf8');
  }

  if (typeof data === 'number' || typeof data === 'boolean') {
    return Buffer.from(JSON.stringify(data), 'utf8');
  }

  return Buffer.from(stableSerialize(data), 'utf8');
}

export async function buildEvidencePack(options: BuildEvidencePackOptions): Promise<EvidencePackResult> {
  const hashAlgorithm = 'sha256';
  const generatedAt = (options.clock ?? (() => new Date()))().toISOString();

  const seenPaths = new Set<string>();

  const files = options.entries.map((entry) => {
    if (seenPaths.has(entry.path)) {
      throw new Error(`Duplicate evidence entry path detected: ${entry.path}`);
    }
    seenPaths.add(entry.path);

    const buffer = normalizeEntryBuffer(entry.data);
    const sha256 = createHash(hashAlgorithm).update(buffer).digest('hex');
    return {
      path: entry.path,
      buffer,
      sha256,
      mediaType: entry.mediaType ?? 'application/octet-stream'
    };
  });

  const archivePayload = {
    generated_at: generatedAt,
    files: files.map((file) => ({
      path: file.path,
      media_type: file.mediaType,
      content: file.buffer.toString('base64')
    }))
  } satisfies Record<string, unknown>;

  const serializedArchive = Buffer.from(stableSerialize(archivePayload), 'utf8');
  const archive = await gzip(serializedArchive);
  const archiveHash = createHash(hashAlgorithm).update(archive).digest('hex');

  let signatureInfo: EvidencePackResult['signature'];

  if (options.signer) {
    const signerResult = await options.signer({
      data: archive,
      hash: archiveHash,
      hashAlgorithm
    });

    if (signerResult && typeof signerResult.signature === 'string' && signerResult.signature.length > 0) {
      signatureInfo = {
        algorithm: signerResult.algorithm ?? 'unknown',
        value: signerResult.signature
      };
    }
  }

  const manifest: Record<string, unknown> = {
    tenant_id: options.tenantId,
    project_id: options.projectId,
    scan_id: options.scanId,
    generated_at: generatedAt,
    feed_version: options.feedVersion ?? null,
    notice_version_id: options.noticeVersionId ?? null,
    purge_manifest: options.purgeManifest ?? null,
    hash_algorithm: hashAlgorithm,
    archive_sha256: archiveHash,
    files: files.map((file) => ({
      path: file.path,
      sha256: file.sha256,
      size: file.buffer.byteLength,
      media_type: file.mediaType
    })),
    inline_data: archive.toString('base64')
  };

  if (signatureInfo) {
    manifest.signature = signatureInfo;
  }

  return {
    archive,
    manifest,
    hashAlgorithm,
    signature: signatureInfo
  };
}
