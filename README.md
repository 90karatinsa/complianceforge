# ComplianceForge

> **English:** ComplianceForge checks a project's open-source dependencies for known vulnerabilities (OSV.dev)
> and licence risk, and writes a CycloneDX SBOM: one command, no server or database. Covers npm, PyPI, Go,
> RubyGems, Cargo, Maven and NuGet. The repository also holds an experimental multi-tenant server (Fastify API,
> BullMQ worker, PostgreSQL) built around the same scanning engine.

Açık kaynak bağımlılıklarının güvenlik açığı ve lisans uyumluluğunu denetler.

## Tek komutla tarama

Node.js 20+ yeterli; sunucu, veritabanı ya da kuyruk gerekmez.

```bash
npm ci
npm run scan -- /proje/klasoru --out rapor
```

| Seçenek | İş |
|---|---|
| `--out <dizin>` | `rapor.md`, `rapor.json` ve `sbom.cdx.json` (CycloneDX 1.5) yazar |
| `--offline` | Hiç ağ kullanmaz; açık sorgusu yapılmaz, yalnız paket ve lisans dökümü çıkar |
| `--fail-on <eşik>` | Bu şiddette ya da üstünde açık varsa çıkış kodu 2 (`kritik`, `yuksek` (varsayılan), `orta`, `dusuk`, `yok`) |
| `--deny-copyleft` | Güçlü copyleft lisans (GPL, AGPL, SSPL) varsa çıkış kodu 2 |

Çıkış kodları: `0` eşik aşılmadı, `1` kullanım hatası, `2` eşik aşıldı. CI'da doğrudan kullanılabilir.

**Ne bulur:**

- **Paketler:** kilit ve manifest dosyalarından (npm, PyPI, Go, RubyGems, Cargo, Maven, NuGet). Alt klasörlerdeki
  projeler de taranır (monorepo: `web/`, `services/api/` …); `node_modules`, `.git`, `venv` ve derleme çıktıları atlanır.
- **Bilinen açıklar:** OSV.dev'den; GitHub (GHSA) şiddeti ya da CVSS v3 vektöründen tahmin, CVE takma adları ve
  düzeltilmiş sürüm.
- **Lisanslar:** npm paketlerinde `package.json`'daki beyan, diğerlerinde LICENSE metni; serbest, zayıf copyleft,
  güçlü copyleft ve tanınmayan diye sınıflanır. `MIT OR GPL-3.0` gibi ifadelerde en serbest seçenek geçerlidir.

**Gizlilik:** Açık sorgusunda OSV.dev'e yalnız paket adları ve sürümleri gider; kaynak kod gönderilmez.
`--offline` ile hiç istek yapılmaz.

## Durum ve bilinen eksikler

- Tek komutluk tarayıcı (`cli/`) ve tarama motoru (`worker/src/scanners.ts`) çalışıyor; 477 test geçiyor.
- Lisanslar ancak bağımlılıkları kurulmuş projede (`node_modules` vb.) tam okunur.
- OSV toplu sorgusu tek istekte gönderilir; çok büyük projelerde (1000+ paket) bölünmesi gerekecek.
- **Sunucu platformu (`api/`, `worker/`) deneysel.** PostgreSQL, Redis ve imzalı bir lisans dosyası ister.
  `npm run build` sunucu kodunda tip hataları veriyor (çalışma zamanı `tsx`); Dockerfile'lar derlenmiş çıktı
  beklediği için şu an çalışmaz.
- Bağımlılıklarda fastify 4 ve vitest 1 sürümlerinden gelen bilinen açıklar var; ikisi de büyük sürüm geçişi
  istiyor (fastify 5, vitest 4). vitest yalnız geliştirme aracıdır, tarayıcıya girmez.

## Sunucu platformu (deneysel)

Aşağıdaki bölümler çok kiracılı sunucu kurulumunu anlatır: Fastify API, BullMQ worker, PostgreSQL ve Redis,
CycloneDX SBOM ve politika değerlendirme motoru.

### Hızlı başlangıç (sunucu)

Örnek yapılandırmayı kopyalayarak ve temel bağımlılıkları kurarak yerel ortamı ayağa kaldırabilirsiniz.

```bash
cp .env.example .env
npm install
make up
npm run migrate
npm run seed
npm run compliance
npm run lint
npm run build
npm test
```

`make seed` hedefi otomatik olarak `npm run migrate` ve `npm run seed` komutlarını çağırır; manuel kontrol gerektiğinde yukarıdaki sıralamayı izleyebilirsiniz. `npm run compliance`, lisans ve güvenlik taramalarını (license:check + security:scan + sbom:generate) tek adımda çalıştırır ve CI sürecine entegre edilmelidir.

## Air-Gap Kurulum Paketleri

Kurumsal ortamlar için Windows, macOS ve Debian paketleri tek komutla üretilebilir. Tüm çıktılar `dist/installers/` dizinine yazılır ve imzalama/manifest doğrulaması için offline ortamda saklanmalıdır.

- `npm run package:windows` – WiX tabanlı MSI üretir, EULA (`deploy/installers/windows/License.rtf`) dahil edilir ve offline doğrulama tokeni zorunlu kılınır.
- `npm run package:macos` – `pkgbuild` + `productbuild` çıktısını DMG içine sarar ve SHA-256 checksum dosyası (`*.sha256`) üretir.
- `npm run package:deb` – Deterministik `dpkg-deb --build --root-owner-group` çağrısı ile `.deb` paketi üretir ve preinst betiği EULA kabulünü doğrular.
- `npm run package:all` – Yukarıdaki üç komutu sırasıyla çalıştırır.

Kurulum/upgrade sırasında CLI ve paketleyici araçlar EULA kabulünü zorunlu tutar; `license-manager` komutlarında `--accept-eula` bayrağını kullanın ve ayrıntılar için [docs/EULA.md](./docs/EULA.md) ile [docs/offline-updates.md](./docs/offline-updates.md) dosyalarına başvurun.

Bu adımların tamamı tek satırlık komut değişkenleriyle CI ve yerel otomasyon için de özetlenmiştir:

- `LOCAL_CMD="npm run lint && npm run build && npm test && npm run compliance"`
- `CI_CMD="npm run lint && npm run build && npm test && npm run compliance"`

API ve worker süreçlerini geliştirme sırasında ayrı terminallerde `npm run dev:api` ve `npm run dev:worker` komutlarıyla çalıştırabilirsiniz.

## Katkıda Bulunma

Pull request açmadan önce aşağıdaki sıralı kontrolleri çalıştırarak lint → tip kontrolü → test → uyumluluk akışını doğrulayın:

1. `npm run lint`
2. `npm run build`
3. `npm test`
4. `npm run compliance`

CI de aynı sırayı takip eder; yerelde başarısız olan herhangi bir adım PR aşamasında da engelleyici olacaktır.

### Demo API Anahtarı

Seed betiği (`npm run seed`), `.env` dosyanızdaki `API_KEYS_SALT` değeri ve varsayılan `alterra-demo-api-token` belirtecini kullanarak demo kiracı için deterministik bir API anahtarı üretir. Aynı salt + token kombinasyonunu istemci tarafında hashleyerek (`sha256("<salt>:alterra-demo-api-token")`) `Authorization: Bearer alterra-demo-api-token` başlığıyla API çağrıları yapabilirsiniz.
Uyumluluk denetimi (`npm run compliance`) bu demo belirtecini otomatik allowlist'e ekler; örnek değeri değiştirirseniz `scripts/security-scan.ts` içindeki varsayılan regex'i güncelleyin ki sahte pozitifler oluşmasın.

### Tarama İsteklerinde Idempotency-Key Zorunluluğu

- `POST /v1/scans` uç noktası, her istekte `Idempotency-Key` başlığının gönderilmesini zorunlu kılar; değer 1–128 arası URL-safe karakterlerden (`[A-Za-z0-9_-]`) oluşmalıdır.
- API anahtarı salt değeri (`API_KEYS_SALT`) ile SHA-256 hashlenen bu anahtar, aynı tenant için tarama taleplerinin tekilleştirilmesini sağlar.
- Aynı `Idempotency-Key` ile yinelenen çağrılar yeni iş kuyruğu kaydı oluşturmaz; ilk isteğin cevabı 200 durum kodu ile aynen döndürülür.

## Proje Yapısı

- `api/` – Fastify tabanlı API hizmeti
- `worker/` – BullMQ ile tarama kuyruğu işleyicileri
- `scanners/` – SBOM, lisans ve zafiyet tarama istemcileri (TODO)
- `schemas/` – Veritabanı şemaları ve migrasyonlar (TODO)
- `docs/` – OpenAPI şeması ve dokümantasyon (TODO)
- `fixtures/` – Test ve demo artefaktları (TODO)
- `scripts/` – Otomasyon ve bakım betikleri (TODO)
- `web/` – Statik health panel (TODO)

## Bağımlılıklar

- [`prom-client`](https://github.com/siimon/prom-client) – Prometheus uyumlu metriklerin toplanması ve yayınlanması için Node.js istemcisi.

## Ortam Değişkenleri

Yerel değerler `.env.example` dosyasında örneklendirildi. Başlıca anahtarların amacı aşağıdaki gibidir:

- `DATABASE_URL` – PostgreSQL bağlantı dizgesi.
- `REDIS_URL` – BullMQ kuyruğu ve metrikler için Redis bağlantısı.
- `API_KEYS_SALT` – API anahtarlarının türetilmesi için kullanılan salt değeri (boş bırakılamaz).
- `LICENSE_PUBLIC_KEY` – Lisans dosyalarının imzasını doğrulamak için kullanılan Ed25519 public key (base64url kodlu).
- `MAX_CONCURRENCY` – Worker kuyruğunun aynı anda çalıştırabileceği tarama sayısı.
- `SCAN_TIMEOUT_S` – Tek bir tarama işinin zaman aşımı limiti.
- `WEBHOOK_MAX_RETRY` – Webhook bildirimleri için maksimum yeniden deneme sayısı.
- `SCAN_QUEUE_NAME` – Worker örneklerinin dinlediği BullMQ kuyruğunun adı (API ve worker aynı değeri kullanmalıdır).
- `TELEMETRY_ENABLED` – Varsayılan olarak `false`; `true` yapıldığında isteğe bağlı ürün telemetrisi etkinleşir (detaylar ve opt-out adımları için [docs/privacy.md](./docs/privacy.md) dokümanına bakın).
- `ALLOW_NETWORK_FETCH` – Varsayılanı `false`; yalnızca `true`/`1`/`yes` değerleriyle açıkça etkinleştirildiğinde dış ağ üzerinden artefakt indirilmesine izin verilir (aksi halde git/arşiv/OCI kaynakları reddedilir).
- `OCI_REGISTRY_AUTH` – Özel OCI kayıtları için kimlik bilgilerini içeren JSON.
- `PROMETHEUS_PORT` – Prometheus metrik sunucusunun bağlanacağı port.
- `GIT_BIN`, `TAR_BIN`, `UNZIP_BIN` – Worker fetcher yardımcılarının kullanacağı sistem araçlarının yolları.
- `COSIGN_KEY_REF` – SBOM çıktısını imzalamak için kullanılacak cosign anahtar referansı (örn. `/etc/cosign.key` veya `kms://...`).
- `COSIGN_PRIVATE_KEY` – `COSIGN_KEY_REF` sağlanmadığında `env://COSIGN_PRIVATE_KEY` şemasıyla kullanılacak PEM içerik (CI süreçlerinde gizli olarak tanımlayın).
- `COSIGN_BINARY` – Varsayılan `cosign` ikilisinin yerine farklı bir yol belirtmek için kullanılabilir.

API ve worker süreçleri, `scan:execute` yetkisini içeren aktif bir lisans olmadan başlatılmaz; lisans eksik, süresi geçmiş veya iptal edilmişse servisler deterministik olarak hata verip loglara ayrıntılı uyarı yazar.

API süreci, Prometheus formatında metrikleri `http://localhost:3000/metrics` üzerinden yayınlar. Bu uç nokta kuyruğun derinliği, tarama süreleri ve webhook sonuçları gibi ölçümleri expose eder.

### AWS Secrets Manager Entegrasyonu

- `DATABASE_URL`, `REDIS_URL`, `API_KEYS_SALT` ve `LICENSE_PUBLIC_KEY` gibi hassas değerler `secretsmanager://<secret-adı>[#jsonAnahtarı]` şemasıyla AWS Secrets Manager üzerinden çekilebilir. `#jsonAnahtarı` parametresi, secret içeriği JSON olduğunda belirli bir alanı seçmenizi sağlar.
- API ve worker süreçleri `LICENSE_PUBLIC_KEY` değerini resolve ettikten sonra lisans denetleyicisine aynen iletir; Secrets Manager URI kullansanız bile secret içeriğinin base64url kodlu Ed25519 public key olduğundan emin olun.
- Örnek: `DATABASE_URL=secretsmanager://prod/primary-database` veya `API_KEYS_SALT=secretsmanager://prod/api-config#salt`.
- Çözümleyici, AWS SDK kimlik bilgilerini standart yöntemlerle (IAM role, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`) okur; aynı zamanda `AWS_REGION`/`AWS_DEFAULT_REGION` değişkenlerinden bölgeyi tespit eder.
- Secret oluşturmak için: `aws secretsmanager create-secret --name prod/primary-database --secret-string 'postgres://user:pass@db.example.com:5432/app'`. JSON secret için: `aws secretsmanager create-secret --name prod/api-config --secret-string '{"salt":"my-derived-salt"}'`.
- CI/CD'de IAM rolünün `secretsmanager:GetSecretValue` yetkisine sahip olduğundan emin olun; eksik izinler başlatma sırasında deterministik hata mesajı ile raporlanır.

## Webhook Güvenliği

- Webhook hedefleri yalnızca HTTPS üzerinden çağrılır; `http://` şemasıyla gönderilen kayıtlar otomatik olarak reddedilir.
- DNS çözümlemeleri özel ağ (RFC1918, loopback, link-local) ve localhost adreslerini engeller, bu sayede SSRF girişimleri ve iç ağ veri sızıntıları önlenir.
- Her deneme için 10 saniyelik zaman aşımı uygulanır ve başarısız olan çağrılar üsse dayalı gecikmeyle yeniden denenir.

## Artefakt İndirme Güvenliği

- Git artefaktları yalnızca `https://`, `ssh://` veya klasik `git@host:repo.git` (SCP) sözdizimini kabul eder; `http://` veya anonim protokoller reddedilir.
- Arşiv (zip/tar) ve OCI manifest/katman istekleri yalnızca HTTPS üzerinden yapılır; HTTP veya yönlendirme içeren cevaplar (3xx) güvenlik gerekçesiyle başarısız sayılır ve API katmanı `http://` arşiv URL'lerini 400 hatasıyla daha baştan reddeder.
- Git, arşiv ve OCI indirmeleri varsayılan olarak özel ağ (RFC1918, loopback, link-local) adreslerine ya da `localhost` benzeri host adlarına yönlendirilirse iptal edilir; iç ağa açık kaynak deposu barındırmanız gerekiyorsa şu an tek yol air-gap paket yükleme/fixtures ile çalışmaktır (özel ağ allowlist desteği henüz sunulmamaktadır).
- Tüm ağ indirmeleri `ALLOW_NETWORK_FETCH` değişkeni `true`/`1`/`yes` olarak ayarlanmadığı sürece kısa devre edilerek tamamen engellenir; değişken etkin olsa bile yukarıdaki genel ağ güvenlik kuralları (HTTPS zorunluluğu + özel ağ engeli) yürürlüktedir.
- HTTP `fetch` çağrıları yönlendirmeleri manuel modda çalıştırır (`redirect: 'manual'`), böylece saldırgan kontrollü 3xx cevaplar özel ağa yönlendirme amacıyla kullanılamaz.

## Performans ve Yük Testleri

- `scripts/perf/load.k6.js` senaryosu `/v1/health` ve `/v1/scans` uç noktalarını arka arkaya çağırarak p95 < 250 ms ve hata oranı < %0.5 eşiklerini doğrular.
- Yerel veya CI doğrulaması için `npm run perf:test` komutunu kullanın; `BASE_URL`, `API_TOKEN` ve `PROJECT_ID` ortam değişkenleri set edilmezse varsayılan localhost değerleri kullanılır.
- Komut, k6 CLI'nin kurulu olmasını gerektirir ve başarısız olduğunda pipeline'ı kıracak şekilde eşik ihlallerini non-zero çıkış koduyla raporlar.

## CI

`.github/workflows/ci.yml` her gönderimde şunları çalıştırır: bağımlılık kurulumu, tarayıcının tip kontrolü ve lint'i,
bütün testler (`npm test`, kapsam eşiğiyle) ve deponun kendini çevrimdışı taraması (`--deny-copyleft`).

## Konteyner İmajları

- API imajı ve worker imajı üretim katmanında non-root `app` kullanıcısıyla çalışır; dosya izinlerini buna göre planlayın.
- API konteynerinde Docker `HEALTHCHECK` komutu `/v1/health` uç noktasını sorgular ve başarısız olursa kapsayıcıyı unhealthy olarak işaretler.
- Worker konteynerinin sağlık denetimi, yapılandırılan `REDIS_URL` hedefinin TCP bağlantısını doğrular; yanlış yapılandırılmış Redis uçları deployment sırasında hızlıca yakalanır.

## Lisans

MIT, bkz. [LICENSE](./LICENSE). Ek bildirim ve yükümlülükler için [NOTICE](./NOTICE) ve [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) dosyalarına başvurun.
