// SPDX-License-Identifier: MIT

import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { findProjectRoots, runScanners, type OsvVulnerability } from '../worker/src/scanners.ts';

/** Ag kullanmamak icin: her paket "biliniyor, acigi yok". */
class BosOnbellek extends Map<string, OsvVulnerability[]> {
  override has(): boolean {
    return true;
  }
  override get(): OsvVulnerability[] {
    return [];
  }
}

function kilit(paketler: Record<string, string>): string {
  const packages: Record<string, { version: string }> = { '': { version: '1.0.0' } };
  for (const [ad, surum] of Object.entries(paketler)) packages[`node_modules/${ad}`] = { version: surum };
  return JSON.stringify({ lockfileVersion: 3, packages });
}

describe('alt projelerdeki kilit dosyalari', () => {
  let kok = '';

  afterEach(async () => {
    if (kok) await rm(kok, { recursive: true, force: true });
  });

  it('kok, web/ ve services/api/ taranir; node_modules ve .git atlanir', async () => {
    kok = await mkdtemp(path.join(tmpdir(), 'cf-kok-'));
    await writeFile(path.join(kok, 'package-lock.json'), kilit({ lodash: '4.17.21' }));
    await mkdir(path.join(kok, 'web'));
    await writeFile(path.join(kok, 'web', 'package-lock.json'), kilit({ react: '18.3.1' }));
    await mkdir(path.join(kok, 'services', 'api'), { recursive: true });
    await writeFile(path.join(kok, 'services', 'api', 'requirements.txt'), 'requests==2.31.0\n');
    await mkdir(path.join(kok, 'node_modules', 'gizli'), { recursive: true });
    await writeFile(path.join(kok, 'node_modules', 'gizli', 'package-lock.json'), kilit({ sahte: '0.0.1' }));
    await mkdir(path.join(kok, '.git'));
    await writeFile(path.join(kok, '.git', 'package-lock.json'), kilit({ sahte2: '0.0.1' }));

    const kokler = (await findProjectRoots(kok)).map((k) => path.relative(kok, k) || '.').sort();
    expect(kokler).toEqual(['.', 'services/api', 'web']);

    const sonuc = await runScanners(kok, { cache: new BosOnbellek() });
    const purller = sonuc.packages.map((p) => p.purl);
    expect(purller).toContain('pkg:npm/lodash@4.17.21');
    expect(purller).toContain('pkg:npm/react@18.3.1');
    expect(purller).toContain('pkg:pypi/requests@2.31.0');
    expect(purller.some((p) => p.includes('sahte'))).toBe(false);
  });

  it('ayni paket iki alt projede gecerse bir kez sayilir', async () => {
    kok = await mkdtemp(path.join(tmpdir(), 'cf-kok-'));
    await writeFile(path.join(kok, 'package-lock.json'), kilit({ lodash: '4.17.21' }));
    await mkdir(path.join(kok, 'web'));
    await writeFile(path.join(kok, 'web', 'package-lock.json'), kilit({ lodash: '4.17.21' }));
    const sonuc = await runScanners(kok, { cache: new BosOnbellek() });
    expect(sonuc.packages.filter((p) => p.purl === 'pkg:npm/lodash@4.17.21')).toHaveLength(1);
  });

  it('OSV sorgusunu 1000lik parcalara boler; basarisiz parca hata olarak doner', async () => {
    kok = await mkdtemp(path.join(tmpdir(), 'cf-kok-'));
    const paketler: Record<string, string> = {};
    for (let i = 0; i < 1500; i += 1) paketler[`paket-${i}`] = '1.0.0';
    await writeFile(path.join(kok, 'package-lock.json'), kilit(paketler));
    vi.stubEnv('ALLOW_NETWORK_FETCH', 'true');

    const boyutlar: number[] = [];
    const fetchImpl = vi.fn(async (_url: unknown, init?: RequestInit) => {
      const govde = JSON.parse(String(init?.body)) as { queries: unknown[] };
      boyutlar.push(govde.queries.length);
      if (boyutlar.length > 1) return new Response('', { status: 400 });
      return new Response(JSON.stringify({ results: govde.queries.map(() => ({ vulns: [{ id: 'GHSA-test' }] })) }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    }) as unknown as typeof fetch;

    const sonuc = await runScanners(kok, { fetchImpl, osvRetryOptions: { maxAttempts: 1 } });
    expect(boyutlar).toEqual([1000, 500]);
    expect(sonuc.vulnerabilities.filter((v) => v.vulnerabilities.length > 0)).toHaveLength(1000);
    expect(sonuc.vulnerabilityQueryError).toMatch(/500 paket/);
  });
});

