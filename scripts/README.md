# Betikler

Bakım, veri temizliği, geriye dönük veri yükleme ve performans testleri bu klasörde yer alacaktır. İlk etapta `make` komutlarını çağıran Node.js tabanlı yardımcılar planlanmaktadır.

`scripts/perf/load.k6.js` betiği premium hedeflerini (`p95<250ms`, hata oranı `<0.5%`) doğrulayan smoke testi içerir; CI'da `npm run perf:test` adımı bu eşiğin aşılması halinde başarısız olur.
- Tüm otomasyon betikleri Alterra-Solutions Proprietary başlığıyla başlamalıdır; `npm run compliance` kontrolü bu banner eksik olduğunda derhal başarısız olur.

## Air-gapped demo başlatma

Atlas SCA bileşenleri air-gapped modda tek komutla ayağa kaldırılabilir. İlk kurulumdan önce aşağıdaki dizinlerin mevcut olduğundan emin olun:

```bash
mkdir -p airgap/feed-cache airgap/evidence airgap/cosign
# cosign açık anahtarınızı airgap/cosign/atlas-feed.pub konumuna kopyalayın
```

Ardından `docker compose` veya mevcut `Makefile` hedefleri aracılığıyla tüm servisleri başlatın:

```bash
make up                # docker compose up --build
```

Bu hedef `docker-compose.yml` içindeki feed cache, evidence ve cosign anahtar volume'larını bağlayarak API ile worker konteynerlerini air-gapped moda alır. Postgres ve Redis servisleri sağlık kontrolleri geçtikten sonra API `/v1/health` uç noktası çalışır hale gelir:

```bash
curl -s http://localhost:3000/v1/health | jq '.status'
```

Bu akış, internete çıkış olmadan feed paketleri (`airgap/feed-cache`), imzalar (`airgap/cosign`) ve Evidence Pack çıktılarını (`airgap/evidence`) kalıcı olarak yönetmenizi sağlar.
