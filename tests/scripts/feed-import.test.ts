// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as signEd25519 } from 'node:crypto';
import { gzipSync } from 'node:zlib';

import {
  verifyFeedArchive,
  buildActivationPayload,
  buildRollbackPayload,
  runCli,
  type ManageFeedPayload
} from '../../scripts/feed-import.ts';
import {
  canonicalizeManifest,
  MAX_FEED_ARCHIVE_BYTES,
  FeedArchiveTooLargeError
} from '../../scripts/feed-manifest.ts';

function createTempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'feed-import-test-'));
}

describe('feed import CLI helpers', () => {
  it('verifies a signed feed archive', async () => {
    const tmpDir = await createTempDir();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const manifest = {
      feed_version: '2024.07',
      minimum_downgrade_version: '2024.06',
      packages: [
        {
          filename: 'osv-2024-07.json',
          sha256: 'a'.repeat(64),
          size_bytes: 2048,
          stored_at: 's3://feeds/osv-2024-07.json'
        }
      ],
      vulnerabilities: [
        {
          package_purl: 'pkg:npm/lodash@4.17.21',
          vulnerabilities: [{ id: 'OSV-2024-0001' }],
          fetched_at: '2024-07-01T00:00:00.000Z'
        }
      ]
    } satisfies Record<string, unknown>;
    const manifestJson = canonicalizeManifest(manifest);
    const signature = signEd25519(null, Buffer.from(manifestJson, 'utf8'), privateKey).toString(
      'base64url'
    );
    const archivePayload = { manifest, signature };
    const archivePath = join(tmpDir, 'feed.tgz');
    const keyPath = join(tmpDir, 'public.pem');

    await writeFile(archivePath, gzipSync(Buffer.from(JSON.stringify(archivePayload), 'utf8')));
    await writeFile(keyPath, Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64url'));

    const result = await verifyFeedArchive({ archivePath, publicKeyPath: keyPath });
    expect(result.manifest).toEqual(manifest);
    expect(result.signature).toBe(signature);
    expect(result.normalized.minimumDowngradeVersion).toBe('2024.06');
  });

  it('rejects archives with invalid signatures', async () => {
    const tmpDir = await createTempDir();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const manifest = {
      feed_version: '2024.07',
      minimum_downgrade_version: '2024.06',
      packages: [],
      vulnerabilities: []
    } satisfies Record<string, unknown>;
    const manifestJson = canonicalizeManifest(manifest);
    const signature = signEd25519(null, Buffer.from(manifestJson, 'utf8'), privateKey).toString(
      'base64url'
    );
    const badPayload = { manifest, signature: signature.slice(0, -4) };
    const archivePath = join(tmpDir, 'feed-bad.tgz');
    const keyPath = join(tmpDir, 'public.pem');

    await writeFile(archivePath, gzipSync(Buffer.from(JSON.stringify(badPayload), 'utf8')));
    await writeFile(keyPath, Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64url'));

    await expect(verifyFeedArchive({ archivePath, publicKeyPath: keyPath })).rejects.toThrow(
      /(canonical base64url|must decode to 64 bytes)/i
    );
  });

  it('requires signatures when a feed public key is configured', async () => {
    const tmpDir = await createTempDir();
    const { publicKey } = generateKeyPairSync('ed25519');
    const manifest = { version: '2024.01', entries: [] };
    const archivePath = join(tmpDir, 'feed-missing-signature.tgz');
    const keyPath = join(tmpDir, 'public.pem');

    await writeFile(
      archivePath,
      gzipSync(Buffer.from(JSON.stringify({ manifest }), 'utf8'))
    );
    await writeFile(keyPath, Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64url'));

    await expect(verifyFeedArchive({ archivePath, publicKeyPath: keyPath })).rejects.toThrow(
      /Signature required when feed public key is configured/u
    );
  });

  it('verifies manifests with shuffled key order', async () => {
    const tmpDir = await createTempDir();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const manifest = {
      feed_version: '2024.05',
      minimum_downgrade_version: '2024.04',
      packages: [
        {
          filename: 'osv-2024-05.json',
          sha256: 'b'.repeat(64),
          size_bytes: 1024,
          stored_at: 's3://feeds/osv-2024-05.json'
        }
      ],
      vulnerabilities: []
    } satisfies Record<string, unknown>;
    const signature = signEd25519(
      null,
      Buffer.from(canonicalizeManifest(manifest), 'utf8'),
      privateKey
    ).toString('base64url');
    const archivePath = join(tmpDir, 'feed-shuffled.tgz');
    const keyPath = join(tmpDir, 'public.pem');

    const shuffledManifest = {
      vulnerabilities: [],
      packages: [
        {
          sha256: 'b'.repeat(64),
          filename: 'osv-2024-05.json',
          stored_at: 's3://feeds/osv-2024-05.json',
          size_bytes: 1024
        }
      ],
      feed_version: '2024.05',
      minimum_downgrade_version: '2024.04'
    } satisfies Record<string, unknown>;
    await writeFile(
      archivePath,
      gzipSync(Buffer.from(JSON.stringify({ manifest: shuffledManifest, signature }), 'utf8'))
    );
    await writeFile(keyPath, Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64url'));

    await expect(verifyFeedArchive({ archivePath, publicKeyPath: keyPath })).resolves.toMatchObject({
      manifest: shuffledManifest,
      normalized: {
        feedVersion: '2024.05',
        packages: [
          {
            filename: 'osv-2024-05.json',
            sha256: 'b'.repeat(64),
            sizeBytes: 1024,
            storedAt: 's3://feeds/osv-2024-05.json'
          }
        ],
        vulnerabilities: [],
        minimumDowngradeVersion: '2024.04'
      }
    });
  });

  it('verifies standalone manifest and signature files', async () => {
    const tmpDir = await createTempDir();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const manifest = {
      feed_version: '2024.10',
      packages: [],
      vulnerabilities: [],
      minimum_downgrade_version: '2024.06'
    } satisfies Record<string, unknown>;
    const manifestPath = join(tmpDir, 'manifest.json');
    const signaturePath = join(tmpDir, 'signature');
    const keyPath = join(tmpDir, 'public.key');

    const signature = signEd25519(
      null,
      Buffer.from(canonicalizeManifest(manifest), 'utf8'),
      privateKey
    ).toString('base64url');

    await writeFile(manifestPath, JSON.stringify(manifest));
    await writeFile(signaturePath, `${signature}\n`);
    await writeFile(keyPath, Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64url'));

    const result = await verifyFeedArchive({
      manifestPath,
      signaturePath,
      publicKeyPath: keyPath
    });

    expect(result.normalized.minimumDowngradeVersion).toBe('2024.06');
  });

  it('accepts inline public key strings without hitting the filesystem', async () => {
    const tmpDir = await createTempDir();
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const manifest = {
      feed_version: '2024.11',
      packages: [],
      vulnerabilities: [],
      minimum_downgrade_version: '2024.09'
    } satisfies Record<string, unknown>;
    const manifestPath = join(tmpDir, 'manifest.json');
    const signaturePath = join(tmpDir, 'signature');

    const signature = signEd25519(
      null,
      Buffer.from(canonicalizeManifest(manifest), 'utf8'),
      privateKey
    ).toString('base64url');

    await writeFile(manifestPath, JSON.stringify(manifest));
    await writeFile(signaturePath, signature);

    const inlineKey = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64url');

    const result = await verifyFeedArchive({
      manifestPath,
      signaturePath,
      publicKeyPath: inlineKey
    });

    expect(result.signature).toBe(signature);
  });

  it('rejects inline public key strings that are not valid Ed25519 material', async () => {
    const tmpDir = await createTempDir();
    const { privateKey } = generateKeyPairSync('ed25519');
    const manifest = {
      feed_version: '2024.12',
      packages: [],
      vulnerabilities: [],
      minimum_downgrade_version: '2024.10'
    } satisfies Record<string, unknown>;
    const manifestPath = join(tmpDir, 'manifest.json');
    const signaturePath = join(tmpDir, 'signature');

    const signature = signEd25519(
      null,
      Buffer.from(canonicalizeManifest(manifest), 'utf8'),
      privateKey
    ).toString('base64url');

    await writeFile(manifestPath, JSON.stringify(manifest));
    await writeFile(signaturePath, signature);

    await expect(
      verifyFeedArchive({
        manifestPath,
        signaturePath,
        publicKeyPath: 'A'.repeat(41)
      })
    ).rejects.toThrow(/feed public key is not valid Ed25519 material/i);
  });

  it('fails verification when manifest signature is missing alongside a public key', async () => {
    const tmpDir = await createTempDir();
    const { publicKey } = generateKeyPairSync('ed25519');
    const manifest = {
      feed_version: '2024.08',
      packages: [],
      vulnerabilities: [],
      minimum_downgrade_version: '2024.07'
    } satisfies Record<
      string,
      unknown
    >;
    const manifestPath = join(tmpDir, 'manifest.json');
    const keyPath = join(tmpDir, 'public.key');

    await writeFile(manifestPath, JSON.stringify(manifest));
    await writeFile(keyPath, Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64url'));

    await expect(
      verifyFeedArchive({ manifestPath, signaturePath: undefined, publicKeyPath: keyPath })
    ).rejects.toThrow(/Signature required when feed public key is configured/u);
  });

  it('builds activation payload with manifest hash', () => {
    const payload: ManageFeedPayload = {
      tenant_id: '11111111-2222-4333-8444-555555555555',
      manifest_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      version: '2024.02'
    };
    expect(buildActivationPayload(payload)).toEqual(payload);
  });

  it('produces consistent hashes for manifests with shuffled keys', () => {
    const payloadA: ManageFeedPayload = {
      tenant_id: '11111111-2222-4333-8444-555555555555',
      manifest_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      version: '2024.03'
    };
    const payloadB: ManageFeedPayload = {
      tenant_id: '11111111-2222-4333-8444-555555555555',
      manifest_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      version: '2024.03'
    };

    expect(buildActivationPayload(payloadA)).toEqual(buildActivationPayload(payloadB));
  });

  it('builds rollback payload mirroring the API schema', () => {
    const payload: ManageFeedPayload = {
      tenant_id: '11111111-2222-4333-8444-555555555555',
      manifest_id: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
      version: '2024.01'
    };

    expect(buildRollbackPayload(payload)).toEqual(payload);
  });

  it('rejects archives that exceed the maximum decompressed size', async () => {
    const tmpDir = await createTempDir();
    const oversizedPadding = 'x'.repeat(MAX_FEED_ARCHIVE_BYTES + 1);
    const manifest = {
      feed_version: '2024.09',
      packages: [],
      vulnerabilities: [],
      minimum_downgrade_version: '2024.08',
      padding: oversizedPadding
    } satisfies Record<string, unknown>;
    const archivePath = join(tmpDir, 'oversize-feed.tgz');

    await writeFile(archivePath, gzipSync(Buffer.from(JSON.stringify({ manifest }), 'utf8')));

    await expect(
      verifyFeedArchive({ archivePath, publicKeyPath: undefined })
    ).rejects.toBeInstanceOf(FeedArchiveTooLargeError);
  });

  it('renders CLI usage and offline guidance when --help is provided', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    try {
      const exitCode = await runCli(['node', 'feed-import.ts', '--help']);
      expect(exitCode).toBe(0);
      const output = logSpy.mock.calls.map((args) => args.join(' ')).join('\n');
      expect(output).toContain('Usage: feed-import <verify|activate|rollback>');
      expect(output).toContain('Offline verification guidance');
      expect(errorSpy).not.toHaveBeenCalled();
    } finally {
      logSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  it('allows subcommand-scoped help flags without validating arguments', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    try {
      const exitCode = await runCli(['node', 'feed-import.ts', 'verify', '--help']);
      expect(exitCode).toBe(0);
      const output = logSpy.mock.calls.map((args) => args.join(' ')).join('\n');
      expect(output).toContain('Usage: feed-import <verify|activate|rollback>');
      expect(errorSpy).not.toHaveBeenCalled();
    } finally {
      logSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  it('treats flags without values as usage errors', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    try {
      const exitCode = await runCli([
        'node',
        'feed-import.ts',
        'verify',
        '--manifest',
        '/tmp/feed.json',
        '--signature'
      ]);

      expect(exitCode).toBe(1);
      expect(errorSpy).toHaveBeenCalled();
      expect(errorSpy.mock.calls[0]?.[0]).toBe('Flag --signature requires a value.');
      const usageMessage = errorSpy.mock.calls.map((call) => call.join(' ')).join('\n');
      expect(usageMessage).toContain('Usage: feed-import <verify|activate|rollback>');
      expect(logSpy).not.toHaveBeenCalled();
    } finally {
      logSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });
});

