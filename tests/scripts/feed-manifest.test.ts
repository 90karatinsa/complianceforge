// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import { gzipSync } from 'node:zlib';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  parseFeedManifest,
  loadFeedArchive,
  MAX_FEED_ARCHIVE_BYTES,
  FeedArchiveTooLargeError
} from '../../scripts/feed-manifest.ts';

describe('feed manifest minimum downgrade validation', () => {
  it('accepts minimum downgrade versions that are equal to or below the feed version', () => {
    const manifest = {
      feed_version: '2024.05',
      minimum_downgrade_version: '2024.04',
      packages: [],
      vulnerabilities: []
    } as Record<string, unknown>;

    const normalized = parseFeedManifest(manifest);
    expect(normalized.minimumDowngradeVersion).toBe('2024.04');
  });

  it('rejects minimum downgrade versions greater than the feed version', () => {
    const manifest = {
      feed_version: '2024.05',
      minimum_downgrade_version: '2025.01',
      packages: [],
      vulnerabilities: []
    } as Record<string, unknown>;

    expect(() => parseFeedManifest(manifest)).toThrow(
      'Feed manifest minimum_downgrade_version must not exceed feed_version.'
    );
  });

  it('rejects manifests missing minimum downgrade version metadata', () => {
    const manifest = {
      feed_version: '2024.05',
      packages: [],
      vulnerabilities: []
    } as Record<string, unknown>;

    expect(() => parseFeedManifest(manifest)).toThrow(
      'Feed manifest must include a minimum_downgrade_version string.'
    );
  });
});

describe('feed archive loading', () => {
  it('rejects archives whose decompressed payload exceeds the configured limit', async () => {
    const tmpDir = await mkdtemp(path.join(tmpdir(), 'feed-oversize-'));
    const archivePath = path.join(tmpDir, 'oversize.tgz');
    const oversizePayload = {
      manifest: { feed_version: '2024.10', packages: [], vulnerabilities: [] },
      signature: null,
      padding: 'x'.repeat(MAX_FEED_ARCHIVE_BYTES + 1)
    } as Record<string, unknown>;

    await writeFile(archivePath, gzipSync(Buffer.from(JSON.stringify(oversizePayload), 'utf8')));

    await expect(loadFeedArchive(archivePath)).rejects.toBeInstanceOf(FeedArchiveTooLargeError);

    await rm(tmpDir, { recursive: true, force: true });
  });
});
