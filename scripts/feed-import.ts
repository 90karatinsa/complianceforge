// SPDX-License-Identifier: MIT

import { readFile } from 'node:fs/promises';
import process from 'node:process';

import {
  assertManifestWithinLimit,
  loadFeedArchive,
  parseFeedManifest,
  verifyFeedSignature,
  type NormalizedFeedManifest
} from './feed-manifest.ts';

interface VerifyOptions {
  readonly archivePath?: string;
  readonly manifestPath?: string;
  readonly signaturePath?: string | null;
  readonly publicKeyPath?: string;
  readonly logger?: (message: string) => void;
}

export interface VerifiedFeedArchive {
  readonly manifest: Record<string, unknown>;
  readonly normalized: NormalizedFeedManifest;
  readonly signature: string | null;
}

const BASE64_INLINE_PATTERN = /^[A-Za-z0-9+/=_-]+$/u;
const MIN_INLINE_KEY_LENGTH = 40;

function canonicalizeBase64Url(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=/gu, '')
    .replace(/\+/gu, '-')
    .replace(/\//gu, '_');
}

function normalizeInlinePublicKeyCandidate(
  candidate: string
): { canonical: string | null; isCandidate: boolean } {
  const trimmed = candidate.trim();
  if (trimmed.length < MIN_INLINE_KEY_LENGTH) {
    return { canonical: null, isCandidate: false };
  }

  if (!BASE64_INLINE_PATTERN.test(trimmed)) {
    return { canonical: null, isCandidate: false };
  }

  const normalized = trimmed.replace(/-/gu, '+').replace(/_/gu, '/');
  const padding = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padding);

  try {
    const decoded = Buffer.from(padded, 'base64');
    if (decoded.byteLength !== 44) {
      return { canonical: null, isCandidate: true };
    }
    return { canonical: canonicalizeBase64Url(decoded), isCandidate: true };
  } catch {
    return { canonical: null, isCandidate: true };
  }
}

async function readPublicKey(publicKeyPath?: string): Promise<string | null> {
  const normalizedPath = publicKeyPath?.trim();

  if (normalizedPath && normalizedPath.length > 0) {
    const inlineCandidate = normalizeInlinePublicKeyCandidate(normalizedPath);
    if (inlineCandidate.canonical) {
      return inlineCandidate.canonical;
    }

    try {
      const raw = (await readFile(normalizedPath, 'utf8')).trim();
      const normalized = normalizeInlinePublicKeyCandidate(raw);
      return normalized.canonical ?? raw;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException)?.code;

      if (code !== 'ENOENT') {
        throw error;
      }

      if (inlineCandidate.isCandidate) {
        throw new Error('Provided feed public key is not valid Ed25519 material or an accessible file path.');
      }

      throw error;
    }
  }

  if (process.env.FEED_PUBLIC_KEY && process.env.FEED_PUBLIC_KEY.trim().length > 0) {
    const inline = normalizeInlinePublicKeyCandidate(process.env.FEED_PUBLIC_KEY.trim());
    if (inline.canonical) {
      return inline.canonical;
    }
    if (inline.isCandidate) {
      throw new Error('FEED_PUBLIC_KEY must be canonical Ed25519 base64/base64url data.');
    }
    return process.env.FEED_PUBLIC_KEY.trim();
  }

  if (process.env.FEED_PUBLIC_KEY_PATH && process.env.FEED_PUBLIC_KEY_PATH.trim().length > 0) {
    const raw = (await readFile(process.env.FEED_PUBLIC_KEY_PATH.trim(), 'utf8')).trim();
    const normalized = normalizeInlinePublicKeyCandidate(raw);
    return normalized.canonical ?? raw;
  }

  return null;
}

async function loadArchivePayload(options: VerifyOptions): Promise<{
  manifest: Record<string, unknown>;
  signature: string | null;
}> {
  if (options.archivePath) {
    return loadFeedArchive(options.archivePath);
  }

  if (!options.manifestPath) {
    throw new Error('Either --archive or --manifest must be provided.');
  }

  const manifestContent = await readFile(options.manifestPath, 'utf8');
  let parsed: unknown;

  try {
    parsed = JSON.parse(manifestContent);
  } catch (error) {
    throw new Error('Manifest file is not valid JSON.', {
      cause: error instanceof Error ? error : undefined
    });
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Manifest file must decode to an object.');
  }

  const manifest = parsed as Record<string, unknown>;
  assertManifestWithinLimit(manifest);

  let signature: string | null = null;

  if (options.signaturePath) {
    const signatureContent = await readFile(options.signaturePath, 'utf8');
    const trimmedSignature = signatureContent.trim();
    signature = trimmedSignature.length > 0 ? trimmedSignature : null;
  }

  return { manifest, signature };
}

export async function verifyFeedArchive(options: VerifyOptions): Promise<VerifiedFeedArchive> {
  const { manifest, signature } = await loadArchivePayload(options);
  const publicKey = await readPublicKey(options.publicKeyPath);

  try {
    await verifyFeedSignature({ manifest, signature, publicKey });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Feed signature verification failed.';
    if (options.logger) {
      options.logger(`Feed manifest verification failed: ${message}`);
    }
    throw error instanceof Error ? error : new Error(message);
  }

  const normalized = parseFeedManifest(manifest);

  if (options.logger) {
    options.logger('Feed manifest verified successfully.');
  }

  return { manifest, normalized, signature };
}

export interface ManageFeedPayload {
  readonly tenant_id: string;
  readonly manifest_id: string;
  readonly version?: string;
}

export function buildActivationPayload(payload: ManageFeedPayload): ManageFeedPayload {
  return payload;
}

export function buildRollbackPayload(payload: ManageFeedPayload): ManageFeedPayload {
  return payload;
}

function parseArgs(
  argv: readonly string[]
): { command: string | undefined; flags: Map<string, string>; helpRequested: boolean } {
  const [, , command, ...rest] = argv;
  const flags = new Map<string, string>();
  let helpRequested = false;

  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];

    if (token === '--help' || token === '-h') {
      helpRequested = true;
      continue;
    }

    if (!token?.startsWith('--')) {
      continue;
    }

    const key = token.slice(2);
    const value = rest[index + 1];

    if (!key) {
      throw new Error('Flag name must follow --.');
    }

    if (typeof value === 'string' && !value.startsWith('--')) {
      flags.set(key, value);
      index += 1;
      continue;
    }

    throw new Error(`Flag --${key} requires a value.`);
  }

  return { command, flags, helpRequested };
}

const USAGE_MESSAGE = [
  'Usage: feed-import <verify|activate|rollback> [--options]',
  '',
  'Commands:',
  '  verify    Validate feed archives offline (requires --archive or --manifest).',
  '  activate  Print activation payload after optional offline verification.',
  '  rollback  Print rollback payload for a feed manifest.',
  '',
  'Options:',
  '  --archive <path>    Path to a feed .tgz archive to verify.',
  '  --manifest <path>   Path to a manifest JSON file.',
  '  --signature <path>  Detached signature for --manifest verification.',
  '  --public-key <key>  Feed public key (base64url or file path).',
  '  --tenant-id <uuid>  Target tenant identifier (activate/rollback).',
  '  --manifest-id <id>  Feed manifest identifier (activate/rollback).',
  '  --version <value>   Explicit manifest version override.',
  '',
  'Offline verification guidance:',
  '  Run `feed-import verify` on removable media before activation in air-gapped environments.',
  '  Ensure signatures are validated against the trusted feed public key prior to promotion.'
].join('\n');

export async function runCli(argv: readonly string[]): Promise<number> {
  let parsedArgs;

  try {
    parsedArgs = parseArgs(argv);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid CLI flag usage.';
    console.error(message);
    console.error(USAGE_MESSAGE);
    return 1;
  }

  const { command, flags, helpRequested } = parsedArgs;

  if (!command && helpRequested) {
    console.log(USAGE_MESSAGE);
    return 0;
  }

  if (!command) {
    console.error(USAGE_MESSAGE);
    return 1;
  }

  if (command === 'help' || command === '--help' || command === '-h') {
    console.log(USAGE_MESSAGE);
    return 0;
  }

  if (helpRequested) {
    console.log(USAGE_MESSAGE);
    return 0;
  }

  if (command === 'verify') {
    const archivePath = flags.get('archive');
    const manifestPath = flags.get('manifest');
    const signaturePath = flags.get('signature');

    if (!archivePath && !manifestPath) {
      console.error('verify command requires either --archive <path> or --manifest <path>.');
      return 1;
    }

    if (manifestPath && !signaturePath && flags.get('public-key')) {
      console.error('verify command requires --signature <path> when a public key is provided.');
      return 1;
    }

    await verifyFeedArchive({
      archivePath: archivePath ?? undefined,
      manifestPath: manifestPath ?? undefined,
      signaturePath: signaturePath ?? undefined,
      publicKeyPath: flags.get('public-key'),
      logger: console.log
    });
    return 0;
  }

  if (command === 'activate') {
    const tenantId = flags.get('tenant-id');
    const manifestId = flags.get('manifest-id');
    const version = flags.get('version') ?? undefined;
    const archivePath = flags.get('archive');
    const manifestPath = flags.get('manifest');
    const signaturePath = flags.get('signature');

    if (!tenantId || !manifestId) {
      console.error('activate command requires --tenant-id <uuid> and --manifest-id <uuid>.');
      return 1;
    }

    if (archivePath || manifestPath) {
      if (manifestPath && !signaturePath && flags.get('public-key')) {
        console.error('activate command requires --signature <path> when verifying with a public key.');
        return 1;
      }

      await verifyFeedArchive({
        archivePath: archivePath ?? undefined,
        manifestPath: manifestPath ?? undefined,
        signaturePath: signaturePath ?? undefined,
        publicKeyPath: flags.get('public-key'),
        logger: console.log
      });
    }

    const payload = buildActivationPayload({ tenant_id: tenantId, manifest_id: manifestId, version });
    console.log(JSON.stringify(payload, null, 2));
    return 0;
  }

  if (command === 'rollback') {
    const tenantId = flags.get('tenant-id');
    const manifestId = flags.get('manifest-id');
    const version = flags.get('version') ?? undefined;

    if (!tenantId || !manifestId) {
      console.error('rollback command requires --tenant-id <uuid> and --manifest-id <uuid>.');
      return 1;
    }

    const payload = buildRollbackPayload({ tenant_id: tenantId, manifest_id: manifestId, version });
    console.log(JSON.stringify(payload, null, 2));
    return 0;
  }

  console.error(`Unknown command ${command}.`);
  return 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runCli(process.argv)
    .then((code) => {
      if (code !== 0) {
        process.exit(code);
      }
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exit(1);
    });
}

