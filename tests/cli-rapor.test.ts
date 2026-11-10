// SPDX-License-Identifier: MIT

import { describe, expect, it } from 'vitest';
import type { PackageSummary, VulnerabilityFinding } from '../worker/src/scanners.ts';
import {
  cikisKodu,
  duzeltilmisSurum,
  surumKarsilastir,
  lisansSinifi,
  markdownRapor,
  ozetCikar,
  siddetBul,
  type OsvAyrinti
} from '../cli/rapor.ts';

const lodash: PackageSummary = { name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20' };
const minimist: PackageSummary = { name: 'minimist', version: '1.2.5', ecosystem: 'npm', purl: 'pkg:npm/minimist@1.2.5' };

const lodashAyrinti: OsvAyrinti = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH' },
  affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }]
};

describe('lisansSinifi', () => {
  it('siniflari ayirir', () => {
    expect(lisansSinifi('MIT')).toBe('serbest');
    expect(lisansSinifi('Apache-2.0')).toBe('serbest');
    expect(lisansSinifi('BSD-3-Clause')).toBe('serbest');
    expect(lisansSinifi('LGPL-2.1-only')).toBe('zayif-copyleft');
    expect(lisansSinifi('MPL-2.0')).toBe('zayif-copyleft');
    expect(lisansSinifi('GPL-3.0-only')).toBe('guclu-copyleft');
    expect(lisansSinifi('AGPL-3.0-or-later')).toBe('guclu-copyleft');
    expect(lisansSinifi('Ozel-Lisans')).toBe('bilinmiyor');
    expect(lisansSinifi('')).toBe('bilinmiyor');
  });

  it('OR ifadesinde en serbest secenegi, AND ifadesinde en kisitlayici parcayi alir', () => {
    expect(lisansSinifi('(MIT OR GPL-3.0-only)')).toBe('serbest');
    expect(lisansSinifi('MIT AND GPL-2.0-only')).toBe('guclu-copyleft');
    expect(lisansSinifi('GPL-2.0-only WITH Classpath-exception-2.0 OR MIT')).toBe('serbest');
  });
});

describe('siddetBul ve duzeltilmisSurum', () => {
  it('GHSA etiketini kullanir', () => {
    expect(siddetBul(lodashAyrinti)).toBe('YUKSEK');
    expect(siddetBul({ id: 'x', database_specific: { severity: 'MODERATE' } })).toBe('ORTA');
    expect(siddetBul(undefined)).toBe('BILINMIYOR');
  });

  it('etiket yoksa CVSS v3 vektorunden tahmin eder', () => {
    expect(siddetBul({ id: 'x', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] })).toBe('KRITIK');
    expect(siddetBul({ id: 'x', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' }] })).toBe('YUKSEK');
    expect(siddetBul({ id: 'x', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N' }] })).toBe('ORTA');
  });

  it('ilgili paketin duzeltilmis surumunu bulur', () => {
    expect(duzeltilmisSurum(lodashAyrinti, 'lodash')).toBe('4.17.21');
    expect(duzeltilmisSurum(lodashAyrinti, 'baska-paket')).toBeUndefined();
  });

  it('kurulu surumun dalindaki duzeltmeyi secer', () => {
    const next: OsvAyrinti = {
      id: 'GHSA-next',
      affected: [{
        package: { name: 'next', ecosystem: 'npm' },
        ranges: [{ events: [{ introduced: '15.0.0' }, { fixed: '15.5.28' }, { introduced: '16.0.0' }, { fixed: '16.4.1' }] }]
      }]
    };
    expect(duzeltilmisSurum(next, 'next', '16.0.3')).toBe('16.4.1');
    expect(duzeltilmisSurum(next, 'next', '15.2.0')).toBe('15.5.28');
    expect(surumKarsilastir('1.10.2', '1.9.0')).toBeGreaterThan(0);
    expect(surumKarsilastir('16.0.3', '16.0.3')).toBe(0);
  });
});

describe('ozetCikar, cikisKodu ve markdownRapor', () => {
  const bulgular: VulnerabilityFinding[] = [
    { package: lodash, vulnerabilities: [{ id: 'GHSA-35jh-r3h4-6jhm' }] },
    { package: minimist, vulnerabilities: [{ id: 'GHSA-xvch-5gv4-984h' }] }
  ];
  const ozet = ozetCikar({
    hedef: '/proje',
    zaman: new Date('2026-11-10T00:00:00Z'),
    cevrimdisi: false,
    paketler: [lodash, minimist],
    lisanslar: [
      { path: '/proje/node_modules/lodash/LICENSE', spdxId: 'MIT', packageName: 'lodash' },
      { path: '/proje/node_modules/lodash/LICENSE.md', spdxId: 'MIT', packageName: 'lodash' },
      { path: '/proje/node_modules/gpl-paket/COPYING', spdxId: 'GPL-3.0-only', packageName: 'gpl-paket' }
    ],
    bulgular,
    ayrintilar: new Map([
      ['GHSA-35jh-r3h4-6jhm', lodashAyrinti],
      ['GHSA-xvch-5gv4-984h', { id: 'GHSA-xvch-5gv4-984h', summary: 'Prototype Pollution in minimist', database_specific: { severity: 'CRITICAL' } }]
    ])
  });

  it('sayar, tekillestirir ve siddete gore siralar', () => {
    expect(ozet.paketSayisi).toBe(2);
    expect(ozet.ekosistemler).toEqual({ npm: 2 });
    expect(ozet.lisansSayilari).toEqual({ serbest: 1, 'zayif-copyleft': 0, 'guclu-copyleft': 1, bilinmiyor: 0 });
    expect(ozet.acikSayilari.KRITIK).toBe(1);
    expect(ozet.acikSayilari.YUKSEK).toBe(1);
    expect(ozet.aciklar.map((a) => a.paket.name)).toEqual(['minimist', 'lodash']);
    expect(ozet.aciklar[1]?.duzeltme).toBe('4.17.21');
  });

  it('esige gore cikis kodu verir', () => {
    expect(cikisKodu(ozet, 'KRITIK', false)).toBe(2);
    expect(cikisKodu(ozet, 'yok', false)).toBe(0);
    expect(cikisKodu(ozet, 'yok', true)).toBe(2);
    const temiz = { ...ozet, acikSayilari: { KRITIK: 0, YUKSEK: 0, ORTA: 3, DUSUK: 0, BILINMIYOR: 5 } };
    expect(cikisKodu(temiz, 'YUKSEK', false)).toBe(0);
    expect(cikisKodu(temiz, 'ORTA', false)).toBe(2);
    expect(cikisKodu({ ...temiz, acikSorgusuHatasi: 'OSV 400' }, 'yok', false)).toBe(3);
    expect(markdownRapor({ ...temiz, acikSorgusuHatasi: 'OSV 400' })).toContain('açık sorgusu tamamlanamadı');
  });

  it('Markdown rapor uretir', () => {
    const md = markdownRapor(ozet);
    expect(md).toContain('# ComplianceForge tarama raporu');
    expect(md).toContain('| KRITIK | minimist@1.2.5 | GHSA-xvch-5gv4-984h |');
    expect(md).toContain('GHSA-35jh-r3h4-6jhm, CVE-2021-23337');
    expect(md).toContain('| güçlü copyleft (GPL, AGPL…) | gpl-paket | GPL-3.0-only |');
  });
});
