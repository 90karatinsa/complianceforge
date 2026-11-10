// SPDX-License-Identifier: MIT

// Tek komutluk taramanin saf (yan etkisiz) parcalari: lisans siniflandirma, OSV ayrintisindan siddet ve
// duzeltilmis surum cikarma, ozet, Markdown rapor ve CI cikis kodu. Ag ve dosya islemleri cli/scan.ts'te.

import type { LicenseFinding, PackageSummary, VulnerabilityFinding } from '../worker/src/scanners.ts';

export type LisansSinifi = 'serbest' | 'zayif-copyleft' | 'guclu-copyleft' | 'bilinmiyor';
export type Siddet = 'KRITIK' | 'YUKSEK' | 'ORTA' | 'DUSUK' | 'BILINMIYOR';

export const SIDDET_SIRASI: readonly Siddet[] = ['KRITIK', 'YUKSEK', 'ORTA', 'DUSUK', 'BILINMIYOR'];

const SERBEST = [
  /^MIT(-0)?$/i, /^Apache-2\.0$/i, /^BSD-[0-9]-Clause/i, /^0?BSD$/i, /^ISC$/i, /^Unlicense$/i, /^CC0-1\.0$/i,
  /^Zlib$/i, /^BlueOak-1\.0\.0$/i, /^Python-2\.0$/i, /^PSF-2\.0$/i, /^WTFPL$/i, /^CC-BY-[0-9.]+$/i, /^BSL-1\.0$/i
];
const ZAYIF_COPYLEFT = [/^LGPL/i, /^MPL/i, /^EPL/i, /^CDDL/i, /^EUPL/i, /^CPL/i, /^OSL/i];
const GUCLU_COPYLEFT = [/^AGPL/i, /^GPL/i, /^SSPL/i, /^CC-BY-(NC|SA)/i, /^RPL/i];

/** SPDX kimligini risk sinifina ayirir. "MIT OR GPL-3.0" gibi ifadelerde en serbest secenek gecerlidir. */
export function lisansSinifi(spdx: string): LisansSinifi {
  const secenekler = spdx.replace(/[()]/g, '').split(/\s+OR\s+/i).map((s) => s.trim()).filter(Boolean);
  if (secenekler.length === 0) {
    return 'bilinmiyor';
  }
  const siniflar = secenekler.map((tek): LisansSinifi => {
    const parcalar = tek.split(/\s+AND\s+/i).map((s) => s.replace(/\s+WITH\s+.*/i, '').trim());
    const tekSinif = (p: string): LisansSinifi =>
      GUCLU_COPYLEFT.some((r) => r.test(p)) ? 'guclu-copyleft'
        : ZAYIF_COPYLEFT.some((r) => r.test(p)) ? 'zayif-copyleft'
          : SERBEST.some((r) => r.test(p)) ? 'serbest' : 'bilinmiyor';
    const hepsi = parcalar.map(tekSinif);
    // AND: en kisitlayici parca belirler.
    for (const s of ['guclu-copyleft', 'bilinmiyor', 'zayif-copyleft'] as const) {
      if (hepsi.includes(s)) return s;
    }
    return 'serbest';
  });
  for (const s of ['serbest', 'zayif-copyleft', 'bilinmiyor'] as const) {
    if (siniflar.includes(s)) return s;
  }
  return 'guclu-copyleft';
}

/** OSV /v1/vulns/{id} cevabinin kullandigimiz kismi. */
export interface OsvAyrinti {
  readonly id: string;
  readonly summary?: string;
  readonly aliases?: readonly string[];
  readonly database_specific?: { readonly severity?: string };
  readonly severity?: ReadonlyArray<{ readonly type?: string; readonly score?: string }>;
  readonly affected?: ReadonlyArray<{
    readonly package?: { readonly name?: string; readonly ecosystem?: string };
    readonly ranges?: ReadonlyArray<{ readonly events?: ReadonlyArray<Record<string, string>> }>;
    readonly database_specific?: { readonly severity?: string };
  }>;
}

const GHSA_SIDDET: Record<string, Siddet> = { CRITICAL: 'KRITIK', HIGH: 'YUKSEK', MODERATE: 'ORTA', MEDIUM: 'ORTA', LOW: 'DUSUK' };

/** GitHub (GHSA) kayitlarindaki siddet etiketini, yoksa CVSS v3 vektorunun etki alanlarindan kaba bir tahmin yapar. */
export function siddetBul(ayrinti: OsvAyrinti | undefined): Siddet {
  if (!ayrinti) return 'BILINMIYOR';
  const etiket = ayrinti.database_specific?.severity ?? ayrinti.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity;
  if (etiket && GHSA_SIDDET[etiket.toUpperCase()]) {
    return GHSA_SIDDET[etiket.toUpperCase()];
  }
  const vektor = ayrinti.severity?.find((s) => s.type?.startsWith('CVSS_V3'))?.score;
  if (vektor) {
    const deger = (ad: string) => new RegExp(`/${ad}:([A-Z])`).exec(vektor)?.[1];
    const yuksekEtki = ['C', 'I', 'A'].filter((ad) => deger(ad) === 'H').length;
    const agdan = deger('AV') === 'N' && deger('PR') === 'N';
    if (yuksekEtki >= 2 && agdan) return 'KRITIK';
    if (yuksekEtki >= 1) return 'YUKSEK';
    if (['C', 'I', 'A'].some((ad) => deger(ad) === 'L')) return 'ORTA';
    return 'DUSUK';
  }
  return 'BILINMIYOR';
}

/** Ilgili paketin ilk "fixed" olayini dondurur (duzeltilmis surum). */
export function duzeltilmisSurum(ayrinti: OsvAyrinti | undefined, paketAdi: string): string | undefined {
  for (const a of ayrinti?.affected ?? []) {
    if (a.package?.name && a.package.name !== paketAdi) continue;
    for (const r of a.ranges ?? []) {
      const olay = r.events?.find((e) => typeof e.fixed === 'string');
      if (olay) return olay.fixed;
    }
  }
  return undefined;
}

export interface AcikSatiri {
  readonly paket: PackageSummary;
  readonly id: string;
  readonly takmaAdlar: readonly string[];
  readonly ozet: string;
  readonly siddet: Siddet;
  readonly duzeltme?: string;
}

export interface LisansSatiri {
  readonly paket: string;
  readonly spdx: string;
  readonly sinif: LisansSinifi;
}

export interface TaramaOzeti {
  readonly hedef: string;
  readonly zaman: string;
  readonly cevrimdisi: boolean;
  readonly paketSayisi: number;
  readonly ekosistemler: Record<string, number>;
  readonly lisansSayilari: Record<LisansSinifi, number>;
  readonly lisansSorunlari: readonly LisansSatiri[];
  readonly acikSayilari: Record<Siddet, number>;
  readonly aciklar: readonly AcikSatiri[];
}

export function ozetCikar(args: {
  hedef: string;
  zaman: Date;
  cevrimdisi: boolean;
  paketler: readonly PackageSummary[];
  lisanslar: readonly LicenseFinding[];
  bulgular: readonly VulnerabilityFinding[];
  ayrintilar: ReadonlyMap<string, OsvAyrinti>;
}): TaramaOzeti {
  const ekosistemler: Record<string, number> = {};
  for (const p of args.paketler) ekosistemler[p.ecosystem] = (ekosistemler[p.ecosystem] ?? 0) + 1;

  const lisansSayilari: Record<LisansSinifi, number> = { serbest: 0, 'zayif-copyleft': 0, 'guclu-copyleft': 0, bilinmiyor: 0 };
  const gorulen = new Set<string>();
  const lisansSorunlari: LisansSatiri[] = [];
  for (const l of args.lisanslar) {
    const paket = l.packageName ?? l.path;
    const anahtar = `${paket}|${l.spdxId}`;
    if (gorulen.has(anahtar)) continue;
    gorulen.add(anahtar);
    const sinif = lisansSinifi(l.spdxId);
    lisansSayilari[sinif] += 1;
    if (sinif !== 'serbest') lisansSorunlari.push({ paket, spdx: l.spdxId, sinif });
  }
  const sinifSirasi: LisansSinifi[] = ['guclu-copyleft', 'zayif-copyleft', 'bilinmiyor', 'serbest'];
  lisansSorunlari.sort((a, b) => sinifSirasi.indexOf(a.sinif) - sinifSirasi.indexOf(b.sinif) || a.paket.localeCompare(b.paket));

  const acikSayilari: Record<Siddet, number> = { KRITIK: 0, YUKSEK: 0, ORTA: 0, DUSUK: 0, BILINMIYOR: 0 };
  const aciklar: AcikSatiri[] = [];
  for (const b of args.bulgular) {
    for (const v of b.vulnerabilities) {
      const ayrinti = args.ayrintilar.get(v.id);
      const siddet = siddetBul(ayrinti);
      acikSayilari[siddet] += 1;
      aciklar.push({
        paket: b.package,
        id: v.id,
        takmaAdlar: ayrinti?.aliases ?? [],
        ozet: ayrinti?.summary ?? v.summary ?? '',
        siddet,
        duzeltme: duzeltilmisSurum(ayrinti, b.package.name)
      });
    }
  }
  aciklar.sort((a, b) => SIDDET_SIRASI.indexOf(a.siddet) - SIDDET_SIRASI.indexOf(b.siddet) || a.paket.purl.localeCompare(b.paket.purl));

  return {
    hedef: args.hedef,
    zaman: args.zaman.toISOString(),
    cevrimdisi: args.cevrimdisi,
    paketSayisi: args.paketler.length,
    ekosistemler,
    lisansSayilari,
    lisansSorunlari,
    acikSayilari,
    aciklar
  };
}

/** CI icin cikis kodu: 0 temiz, 2 esik asildi. */
export function cikisKodu(ozet: TaramaOzeti, esik: Siddet | 'yok', copyleftEngelle: boolean): number {
  if (copyleftEngelle && ozet.lisansSayilari['guclu-copyleft'] > 0) return 2;
  if (esik === 'yok') return 0;
  const sinir = SIDDET_SIRASI.indexOf(esik);
  const asan = SIDDET_SIRASI.slice(0, sinir + 1).filter((s) => s !== 'BILINMIYOR');
  return asan.some((s) => ozet.acikSayilari[s] > 0) ? 2 : 0;
}

const SINIF_ADI: Record<LisansSinifi, string> = {
  serbest: 'serbest (MIT, Apache, BSD…)',
  'zayif-copyleft': 'zayıf copyleft (LGPL, MPL…)',
  'guclu-copyleft': 'güçlü copyleft (GPL, AGPL…)',
  bilinmiyor: 'tanınmayan'
};

function hucre(metin: string): string {
  return metin.replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
}

export function markdownRapor(ozet: TaramaOzeti, enFazlaSatir = 200): string {
  const satirlar: string[] = [];
  satirlar.push('# ComplianceForge tarama raporu', '');
  satirlar.push(`- Hedef: \`${ozet.hedef}\``);
  satirlar.push(`- Zaman: ${ozet.zaman}`);
  satirlar.push(`- Paket: ${ozet.paketSayisi} (${Object.entries(ozet.ekosistemler).map(([e, n]) => `${e} ${n}`).join(', ') || 'yok'})`);
  if (ozet.cevrimdisi) satirlar.push('- Çevrimdışı tarama: açık sorgusu yapılmadı.');
  satirlar.push('', '## Bilinen açıklar', '');
  satirlar.push(SIDDET_SIRASI.map((s) => `${s} ${ozet.acikSayilari[s]}`).join(' · '), '');
  if (ozet.aciklar.length > 0) {
    satirlar.push('| Şiddet | Paket | Açık | Düzeltilmiş sürüm | Özet |', '|---|---|---|---|---|');
    for (const a of ozet.aciklar.slice(0, enFazlaSatir)) {
      const kimlik = [a.id, ...a.takmaAdlar.filter((t) => t.startsWith('CVE-'))].join(', ');
      satirlar.push(`| ${a.siddet} | ${hucre(`${a.paket.name}@${a.paket.version}`)} | ${hucre(kimlik)} | ${a.duzeltme ?? '—'} | ${hucre(a.ozet)} |`);
    }
    if (ozet.aciklar.length > enFazlaSatir) satirlar.push('', `…ve ${ozet.aciklar.length - enFazlaSatir} satır daha (tamamı JSON raporda).`);
  }
  satirlar.push('', '## Lisanslar', '');
  for (const s of ['guclu-copyleft', 'zayif-copyleft', 'bilinmiyor', 'serbest'] as const) {
    satirlar.push(`- ${SINIF_ADI[s]}: ${ozet.lisansSayilari[s]}`);
  }
  if (ozet.lisansSorunlari.length > 0) {
    satirlar.push('', '| Sınıf | Paket | Lisans |', '|---|---|---|');
    for (const l of ozet.lisansSorunlari.slice(0, enFazlaSatir)) {
      satirlar.push(`| ${SINIF_ADI[l.sinif]} | ${hucre(l.paket)} | ${hucre(l.spdx)} |`);
    }
  }
  satirlar.push('', 'Lisanslar paketlerin LICENSE dosyalarından okunur; bağımlılıkları kurulmamış projede bu bölüm boş kalır.', '');
  return satirlar.join('\n');
}
