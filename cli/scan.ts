// SPDX-License-Identifier: MIT

// Tek komutluk tarama: sunucu, veritabani ve kuyruk olmadan bir proje klasorunu tarar.
//
//   npm run scan -- <klasor> [--out <dizin>] [--offline] [--fail-on kritik|yuksek|orta|dusuk|yok] [--deny-copyleft]
//
// Paketler: npm, PyPI, Go, RubyGems, Cargo, Maven, NuGet (worker/src/scanners.ts). Acik sorgusu OSV.dev'e
// gider; --offline ile hic ag kullanilmaz. Cikis kodu: 0 temiz, 1 kullanim hatasi, 2 esik asildi,
// 3 acik sorgusu tamamlanamadi (sonuc eksik).

import { mkdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { runScanners, type OsvVulnerability } from '../worker/src/scanners.ts';
import { cikisKodu, markdownRapor, ozetCikar, SIDDET_SIRASI, type OsvAyrinti, type Siddet } from './rapor.ts';

const OSV_AYRINTI = 'https://api.osv.dev/v1/vulns/';
const ESIK_ADLARI: Record<string, Siddet | 'yok'> = {
  kritik: 'KRITIK', critical: 'KRITIK', yuksek: 'YUKSEK', high: 'YUKSEK', orta: 'ORTA', medium: 'ORTA',
  dusuk: 'DUSUK', low: 'DUSUK', yok: 'yok', none: 'yok'
};

interface Secenekler {
  hedef: string;
  cikti?: string;
  cevrimdisi: boolean;
  esik: Siddet | 'yok';
  copyleftEngelle: boolean;
}

const KULLANIM = `Kullanim: npm run scan -- <klasor> [secenekler]

  --out <dizin>       rapor.md, rapor.json ve sbom.cdx.json yaz
  --offline           ag kullanma (acik sorgusu yapilmaz)
  --fail-on <esik>    bu siddette ya da ustunde acik varsa cikis kodu 2 (varsayilan: yuksek;
                      kritik | yuksek | orta | dusuk | yok)
  --deny-copyleft     guclu copyleft lisans (GPL, AGPL, SSPL) varsa cikis kodu 2`;

function secenekleriOku(argv: readonly string[]): Secenekler {
  const s: Secenekler = { hedef: '', cevrimdisi: false, esik: 'YUKSEK', copyleftEngelle: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--out') s.cikti = argv[++i];
    else if (a === '--offline') s.cevrimdisi = true;
    else if (a === '--deny-copyleft') s.copyleftEngelle = true;
    else if (a === '--fail-on') {
      const esik = ESIK_ADLARI[(argv[++i] ?? '').toLowerCase()];
      if (!esik) throw new Error('--fail-on: kritik, yuksek, orta, dusuk ya da yok olmali.');
      s.esik = esik;
    } else if (a === '-h' || a === '--help') {
      console.log(KULLANIM);
      process.exit(0);
    } else if (a.startsWith('-')) throw new Error(`Bilinmeyen secenek: ${a}`);
    else if (!s.hedef) s.hedef = a;
    else throw new Error(`Fazladan arguman: ${a}`);
  }
  if (!s.hedef) throw new Error('Taranacak klasor verilmedi.');
  if (s.cikti === '') throw new Error('--out bir dizin ister.');
  return s;
}

/** Cevrimdisi tarama: her paket "biliniyor ve acigi yok" sayilir, OSV'ye hic istek gitmez. */
class BosOnbellek extends Map<string, OsvVulnerability[]> {
  override has(): boolean {
    return true;
  }
  override get(): OsvVulnerability[] {
    return [];
  }
}

async function ayrintilariGetir(kimlikler: readonly string[]): Promise<Map<string, OsvAyrinti>> {
  const sonuc = new Map<string, OsvAyrinti>();
  const kuyruk = [...kimlikler];
  const isci = async () => {
    for (let id = kuyruk.shift(); id; id = kuyruk.shift()) {
      try {
        const cevap = await fetch(OSV_AYRINTI + encodeURIComponent(id), { signal: AbortSignal.timeout(10_000) });
        if (cevap.ok) sonuc.set(id, (await cevap.json()) as OsvAyrinti);
      } catch {
        // Ayrinti alinamazsa acik yine listelenir, siddeti BILINMIYOR kalir.
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, kuyruk.length) }, isci));
  return sonuc;
}

function terminalOzeti(ozet: ReturnType<typeof ozetCikar>): string {
  const satirlar = [
    `ComplianceForge · ${ozet.hedef}`,
    `  paket      : ${ozet.paketSayisi} (${Object.entries(ozet.ekosistemler).map(([e, n]) => `${e} ${n}`).join(', ') || 'bulunamadi'})`,
    `  aciklar    : ${ozet.cevrimdisi ? 'sorgulanmadi (--offline)' : SIDDET_SIRASI.map((s) => `${s} ${ozet.acikSayilari[s]}`).join(' · ')}`,
    ...(ozet.acikSorgusuHatasi ? [`  ! UYARI    : acik sorgusu tamamlanamadi, liste eksik (${ozet.acikSorgusuHatasi})`] : []),
    `  lisanslar  : serbest ${ozet.lisansSayilari.serbest} · zayif copyleft ${ozet.lisansSayilari['zayif-copyleft']} · guclu copyleft ${ozet.lisansSayilari['guclu-copyleft']} · taninmayan ${ozet.lisansSayilari.bilinmiyor}`
  ];
  for (const a of ozet.aciklar.filter((x) => x.siddet === 'KRITIK' || x.siddet === 'YUKSEK').slice(0, 10)) {
    satirlar.push(`  ! ${a.siddet.padEnd(6)} ${a.paket.name}@${a.paket.version}  ${a.id}${a.duzeltme ? `  -> ${a.duzeltme}` : ''}  ${a.ozet.slice(0, 70)}`);
  }
  for (const l of ozet.lisansSorunlari.filter((x) => x.sinif === 'guclu-copyleft').slice(0, 10)) {
    satirlar.push(`  ! GPL    ${l.paket}  ${l.spdx}`);
  }
  return satirlar.join('\n');
}

async function main(): Promise<number> {
  let s: Secenekler;
  try {
    s = secenekleriOku(process.argv.slice(2));
  } catch (hata) {
    console.error(`${(hata as Error).message}\n\n${KULLANIM}`);
    return 1;
  }
  const hedef = path.resolve(s.hedef);
  if (!(await stat(hedef).catch(() => null))?.isDirectory()) {
    console.error(`Klasor bulunamadi: ${hedef}`);
    return 1;
  }
  if (!s.cevrimdisi) process.env.ALLOW_NETWORK_FETCH = 'true';

  const zaman = new Date();
  const sonuc = await runScanners(hedef, s.cevrimdisi ? { cache: new BosOnbellek() } : {});
  const kimlikler = [...new Set(sonuc.vulnerabilities.flatMap((b) => b.vulnerabilities.map((v) => v.id)))];
  const ayrintilar = s.cevrimdisi || kimlikler.length === 0 ? new Map<string, OsvAyrinti>() : await ayrintilariGetir(kimlikler);
  const ozet = ozetCikar({
    hedef, zaman, cevrimdisi: s.cevrimdisi, acikSorgusuHatasi: sonuc.vulnerabilityQueryError, paketler: sonuc.packages, lisanslar: sonuc.licenses,
    bulgular: sonuc.vulnerabilities, ayrintilar
  });

  console.log(terminalOzeti(ozet));
  if (s.cikti) {
    const dizin = path.resolve(s.cikti);
    await mkdir(dizin, { recursive: true });
    await writeFile(path.join(dizin, 'rapor.md'), markdownRapor(ozet));
    await writeFile(path.join(dizin, 'rapor.json'), `${JSON.stringify(ozet, null, 2)}\n`);
    await writeFile(path.join(dizin, 'sbom.cdx.json'), `${JSON.stringify(sonuc.bom, null, 2)}\n`);
    console.log(`  rapor      : ${dizin}/{rapor.md, rapor.json, sbom.cdx.json}`);
  }
  return cikisKodu(ozet, s.esik, s.copyleftEngelle);
}

process.exitCode = await main();
