<!-- SPDX-License-Identifier: MIT -->

# 5 Dakikada İlk Tarama

Bu rehber tek komutla tüm servisleri ayağa kaldırıp örnek bir taramayı tamamlamayı hedefler. Gerekli süre yaklaşık 5 dakikadır.

## 1. Önkoşullar

- Docker ve Docker Compose
- Node.js 20 ve npm 10
- `make` aracı

## 2. Ortam değişkenlerini hazırlayın

`.env.example` dosyasını inceleyin ve ihtiyaç duyulan değerlerle `.env` dosyasını oluşturun:

```bash
cp .env.example .env
```

Lokal geliştirme için varsayılan değerler yeterlidir.

## 3. Servisleri başlatın

PostgreSQL, Redis, API ve worker bileşenlerini tek komutla ayağa kaldırın:

```bash
make up
```

Komut docker-compose aracılığıyla servisleri başlatır ve API'yi `http://localhost:3000` üzerinde dinler.

> Kod değişikliklerini canlı izlemek için `npm run dev` (veya Makefile kısayolu `make dev`) komutu API ve worker watcher'larını aynı anda başlatır; tek terminal oturumunda geliştirme yaparken bu komut tercih edilmelidir.

> Kalıcı feed cache (`airgap/feed-cache`), evidence (`airgap/evidence`) ve cosign anahtarı (`airgap/cosign`) dizinleri otomatik olarak konteynerlere bağlanır. Dosya izinlerini yalnızca yetkili kullanıcıların erişebileceği şekilde sınırlandırın.

## 4. Örnek veriyi yükleyin

Ön tanımlı tenant, proje ve politika kayıtlarını veri tabanına ekleyin:

```bash
make seed
```

Bu adım örnek bir git deposunu işaret eden proje kaydı oluşturur.

## 5. Test ve uyumluluk doğrulamaları

Tek komutla tüm otomatik testleri, lisans denetimini, güvenlik taramasını ve SBOM üretimini çalıştırın:

```bash
make test
make compliance
```

`make test` vitest senaryolarını çalıştırır. `make compliance` ise `npm run compliance` hedefini çağırarak lisans uyumluluğu, Trivy tabanlı güvenlik taraması ve CycloneDX SBOM üretimini tek komutta yürütür.

## 6. İlk taramayı başlatın

API anahtarını elde etmek için seed çıktısındaki `api_keys` tablosunu kullanın veya doğrudan PostgreSQL'den sorgulayın. Ardından aşağıdaki isteği gönderin:

```bash
curl -X POST http://localhost:3000/v1/scans \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"project_id":"prj_demo","policy_id":"pol_default"}'
```

Yanıtta dönen `id` değerini saklayın. Tarama tamamlandığında `GET /v1/scans/{id}` isteği ile özet rapora, `GET /v1/vulns?scan_id={id}` ile zafiyet listesine erişebilirsiniz.

## 7. Durum panelini kontrol edin

`http://localhost:3000/health` adresindeki panel; kuyruk yoğunluğu, worker kapasitesi ve son hata mesajlarını gösterir.

Kurumsal dashboard ve hukuk/operasyon akışlarının düşük sadakat prototipleri `web/` dizininde statik HTML olarak sağlanır. Aşağıdaki dosyaları doğrudan tarayıcıda açarak yeni UI bileşenlerini inceleyebilirsiniz:

- `web/dashboard.html`
- `web/projects.html`
- `web/scans.html`
- `web/findings.html`
- `web/legal-review.html`
- `web/notice-builder.html` ve `web/feeds.html`

### Artefakt deposu kapısını doğrulayın

Artifactory veya Nexus tarafında upload öncesi politika kontrolü yapmak için yeni `/v1/integrations/artifact-gate` uç noktasını kullanın. Uç nokta son başarılı taramanın politika sonucuna göre `allow` veya `deny` kararı döndürür ve denetim kaydına işlenir:

```bash
curl -X POST http://localhost:3000/v1/integrations/artifact-gate \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
        "tenant_id": "<TENANT_UUID>",
        "project_id": "<PROJECT_UUID>",
        "artifact_name": "registry.example.com/app:1.0.0",
        "requested_by": "ci-bot"
      }'
```

Yanıt örneği:

```json
{
  "decision": "allow",
  "policy_result": "pass",
  "scan_id": "scan-pass",
  "completed_at": "2024-01-01T00:00:00.000Z",
  "policy_reasons": ["threshold_ok"]
}
```

Karar `deny` ise `reason` alanı hangi durumun blokladığını açıklar (`no_successful_scan`, `latest_scan_fail` gibi). Bu çıktı doğrudan depo tarafında bloklama veya manuel onay sürecine bağlanabilir.

## 8. Servisleri durdurun

Yerel ortamı temizlemek için:

```bash
docker compose down -v
```

Bu işlem veritabanı ve kuyruk kalıcı verilerini de siler.

> Daha fazla ayrıntı ve gelişmiş kullanım senaryoları için ana [README](../README.md) dosyasını inceleyin.
