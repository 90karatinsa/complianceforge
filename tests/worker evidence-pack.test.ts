// SPDX-License-Identifier: MIT

import { describe, expect, it, vi } from 'vitest';
import { gunzipSync } from 'node:zlib';

import { buildEvidencePack } from '../worker/src/evidence-pack.ts';

describe('evidence pack bundler', () => {
  it('assembles archive metadata with signature and feed linkage', async () => {
    const signer = vi.fn(async ({ hash }: { hash: string }) => ({
      signature: `sig-${hash}`,
      algorithm: 'cosign'
    }));

    const result = await buildEvidencePack({
      tenantId: 'tenant-1',
      projectId: 'project-1',
      scanId: 'scan-1',
      feedVersion: '2024.05',
      noticeVersionId: 'notice-abc',
      purgeManifest: { items: [] },
      clock: () => new Date('2024-01-01T00:00:00Z'),
      signer,
      entries: [
        { path: 'sbom.json', data: { bomFormat: 'CycloneDX' }, mediaType: 'application/json' },
        { path: 'summary.json', data: { policy: 'pass' }, mediaType: 'application/json' }
      ]
    });

    expect(result.hashAlgorithm).toBe('sha256');
    expect(result.signature).toEqual({ algorithm: 'cosign', value: expect.stringMatching(/^sig-/) });

    const manifest = result.manifest;
    expect(manifest.tenant_id).toBe('tenant-1');
    expect(manifest.project_id).toBe('project-1');
    expect(manifest.scan_id).toBe('scan-1');
    expect(manifest.feed_version).toBe('2024.05');
    expect(manifest.notice_version_id).toBe('notice-abc');
    expect(manifest.purge_manifest).toEqual({ items: [] });
    expect(typeof manifest.inline_data).toBe('string');

    const files = manifest.files as Array<Record<string, unknown>>;
    expect(files).toHaveLength(2);
    expect(files.map((file) => file.path)).toEqual(['sbom.json', 'summary.json']);

    const archiveBuffer = Buffer.from(String(manifest.inline_data), 'base64');
    expect(archiveBuffer.equals(result.archive)).toBe(true);

    const decompressed = JSON.parse(gunzipSync(archiveBuffer).toString('utf8')) as {
      files: Array<{ path: string; media_type: string; content: string }>;
    };
    expect(decompressed.files).toHaveLength(2);
    expect(decompressed.files[0]?.content).toBeDefined();
  });

  it('produces deterministic archives for identical inputs', async () => {
    const options = {
      tenantId: 'tenant-1',
      projectId: 'project-1',
      scanId: 'scan-1',
      feedVersion: null,
      noticeVersionId: null,
      entries: [{ path: 'example.json', data: { value: 1 }, mediaType: 'application/json' }] as const,
      purgeManifest: null,
      clock: () => new Date('2024-02-02T00:00:00Z')
    } satisfies Parameters<typeof buildEvidencePack>[0];

    const first = await buildEvidencePack(options);
    const second = await buildEvidencePack(options);

    expect(first.archive.equals(second.archive)).toBe(true);
    expect(first.manifest.archive_sha256).toBe(second.manifest.archive_sha256);
  });

  it('rejects duplicate entry paths', async () => {
    await expect(
      buildEvidencePack({
        tenantId: 'tenant-1',
        projectId: 'project-1',
        scanId: 'scan-1',
        entries: [
          { path: 'sbom.json', data: { bomFormat: 'CycloneDX' } },
          { path: 'sbom.json', data: { bomFormat: 'CycloneDX', version: 2 } }
        ]
      })
    ).rejects.toThrow(/Duplicate evidence entry path detected: sbom\.json/);
  });
});
