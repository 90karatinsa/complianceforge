<!-- SPDX-License-Identifier: MIT -->

# Güvenlik ve Gizlilik Beyanı

Atlas SCA air-gapped, müşteri tarafından kontrol edilen ortamlarda çalışacak şekilde tasarlanmıştır. Bu doküman platformun güvenlik duruşu, veri işleme politikaları ve operasyonel kontroller hakkında özet bilgi sağlar.

## Veri İşleme İlkeleri

- **Telemetri yok:** Çalışma zamanı metrikleri yalnızca yerel Prometheus uç noktalarına yayınlanır. Ürün hiçbir durumda dış servislere telemetri göndermez.
- **Kalıcı depolama kapsamı:** SBOM kayıtları, tarama bulguları, politika kararları ve Evidence Pack manifestleri kalıcıdır. Kaynak kodu ve geçici tarama çıktıları iş tamamlandıktan sonra çalışma dizininden silinir.
- **Evidence Pack dizini:** `EVIDENCE_EXPORT_DIR` (Docker Compose ve Helm kurulumlarında `/var/lib/atlas/evidence`) yalnızca append-only ZIP paketlerini barındırır; manuel değişikliklere karşı dosya sistemi izinleriyle korunmalıdır.

## Erişim Kontrolleri

- **RBAC ve roller:** API `Admin`, `Security`, `Legal`, `Developer` ve `Auditor` rollerini destekler; her uç nokta rol tabanlı yetkilendirme kontrollerinden geçirilir.
- **SSO entegrasyonu:** SAML veya OIDC sağlayıcılarıyla bütünleşmek için `ssoHandlers` arabirimi sunulur. SSO etkinleştirildiğinde audit log'lara kimlik sağlayıcıya ait subject değeri yazılır.
- **API anahtarları:** Anahtarlar `API_KEYS_SALT` değeri ile SHA-256 üzerinden tuzlanmış şekilde saklanır. Salt değeri Secrets Manager veya çevrimdışı secret store'larından alınabilir.

## Günlükleme ve Denetim

- **Audit Log:** `audit_log_events` tablosu append-only olacak şekilde tasarlanmıştır; tüm kritik işlemler (scan tetikleme, politika kararı, feed aktivasyonu vb.) burada saklanır.
- **İmza ve kanıt:** Hukuk kararları `legal_signoffs` tablosuna imza hash'i ve payload'ıyla birlikte yazılır. Evidence Pack üretimi hem API hem worker tarafından audit log kayıtlarıyla ilişkilendirilir.
- **Maskelenmiş içerik:** Audit payload'ları SHA-256 ile hash'lenir, böylece hassas veriler log'larda düz metin olarak yer almaz.

## Ağ ve Operasyon Güvenliği

- **Air-gapped mod:** Varsayılan docker-compose ve Helm değerleri `AIRGAP_MODE=true` olacak şekilde gelir ve tüm feed/cosign dizinlerini lokal depolamaya yönlendirir. Outbound erişim altyapı seviyesinde kapatılmalıdır.
- **Feed doğrulaması:** Feed manifestleri cosign açık anahtarı (`atlas-feed.pub`) ile doğrulanır; imza doğrulanmadan aktif edilmez.
- **Sağlık kontrolleri:** API `/v1/health` uç noktası, Redis ve Postgres bağlantı durumunu ve aktif feed sürümünü raporlar. Worker konteynerleri Redis bağlantısı üzerinden liveness/readiness kontrolü yapar.

## Olay Müdahale

- **Append-only log saklama:** Audit kayıtları ve Evidence Pack ZIP arşivleri müşteri tarafından belirlenen saklama süresi boyunca değişmeden tutulur.
- **İhlal bildirimi:** Platform harici ağlara çıkmadığından olay bildirimleri kurum içi süreçlere göre yönetilmelidir. Audit log export'u `Admin` ve `Auditor` rolleri tarafından tetiklenebilir.

Bu belge, müşteri güvenlik ekiplerinin Atlas SCA'yı değerlendirme sürecinde referans alabileceği temel kontrolleri özetler. Detaylı tehdit modeli ve hardening kılavuzları için Alterra-Solutions güvenlik ekibiyle iletişime geçiniz.
