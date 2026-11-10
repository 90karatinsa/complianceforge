// SPDX-License-Identifier: MIT

import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
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
});
