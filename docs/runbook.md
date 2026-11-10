<!-- SPDX-License-Identifier: MIT -->

# Operasyonel Runbook

## 1. Servis Sağlığı Doğrulama
- **Kontrol Komutu:** `curl -fsSL "$API_BASE_URL/v1/health" -H "Authorization: Bearer $API_TOKEN" | jq`  
  - `status` alanı `healthy` olmalı; `degraded` ise detay mesajı incelenmeli, `down` ise 2. adıma geç.
- **Kapsayıcı Sağlık Kontrolleri:**
  - API Pod/Konteyneri: Docker/Kubernetes `HEALTHCHECK` çıktısını izle; başarısızsa pod yeniden başlatılır, 2 ardışık hata sonrası on-call bilgilendirilir.
  - Worker Pod/Konteyneri: Redis TCP probu başarısızsa `redis-cli -u $REDIS_URL PING` ile doğrula; arka planda BullMQ kuyruğu kontrol et.
- **Kubernetes Manifesteri:** API dağıtımı `deploy/k8s/api.yaml`, worker dağıtımı `deploy/k8s/worker.yaml` dosyalarıyla yönetilir; güncelleme sonrası `kubectl rollout status deploy/oss-licensing-api` ve `deploy/oss-licensing-worker` çıktıları takip edilmelidir.
- **Metrik Paneli:** Prometheus `http://$PROM_URL/graph?g0.expr=scan_duration_seconds_bucket` grafiğinde p95 gecikmeleri izle.

## 2. Alarm Yanıtı ve SLO/SLA
- **SLO'lar:**
  - API p95 yanıt süresi < **250 ms**.
  - 5xx hata oranı < **0.5%**.
  - Webhook teslim başarısı ≥ **99%** (Prometheus metriği `webhook_deliveries_success_total / webhook_deliveries_total`).
- **Alert Playbook:**
  1. PagerDuty/Lark alarmı geldiğinde ilgili metriğin grafana panelini aç.
  2. `kubectl logs deploy/api -n oss-platform --since=10m` veya `docker logs api` ile hata detaylarını incele.
  3. Degradation durumunda feature flag / rate limit ayarlarını kontrol et (`policies` tablosunda fail artıyorsa politika hatası olabilir).
  4. 5xx artışı API kaynaklıysa `npm run migrate` veya son yayınlanan sürüme rollback planı değerlendir.
  5. SLA ihlali riski varsa müşteri iletişimi için durum raporu hazırla.

## 3. Yedekleme ve Geri Yükleme
- **Veritabanı:**
  - Günlük PITR yedekleri `pg_dump --format=custom --file=backup-$(date +%F).dump $DATABASE_URL` ile alınır.
  - RPO hedefi **15 dakika**, RTO hedefi **30 dakika**.
- **Geri Yükleme:**
  1. Yeni boş PostgreSQL instance oluştur.
  2. `pg_restore --clean --create --dbname=postgres backup-YYYY-MM-DD.dump` komutunu çalıştır.
  3. `ALTER DATABASE oss_compliance RENAME TO oss_compliance_prev;` ardından restore edilen DB'yi asıl isimle yeniden adlandır.
  4. Worker ve API deployment'larını yeni bağlantı dizgesiyle yeniden başlat (`kubectl rollout restart deploy/api deploy/worker`).
- **Objekt Depolama/SBOM:** SBOM çıktıları S3 uyumlu depoda tutulur; lifecycle policy 90 gün.

## 4. Migrasyon Rollback Adımları
1. CI/CD pipeline'ı başarısız migrasyon rapor ettiyse `git revert` ile ilgili migration dosyasını geri al.
2. Üretimde başarısız olduysa: `npm run migrate -- --to <previous_timestamp>` komutuyla schema downgrade et (Knex timestamp'i kullanılır).
3. `npm run seed` sadece geliştirme ortamında çalıştır; üretimde manuel veri doğrulaması yap.
4. Rollback sonrası `make test` ve `npm run compliance` çalıştırarak regresyon kontrolü yap.

## 5. Felaket Kurtarma (DR) Tatbikatı
- **Periyot:** Aylık.
- **Script:** `scripts/dr-drill.sh` (S3'ten son yedeği indirir, staging cluster'ına restore eder, `deploy/k8s/api.yaml` ve `deploy/k8s/worker.yaml` manifestlerini uygular, ardından performans smoke testini çalıştırır).
- **Gerekli Değişkenler:** `DR_DATABASE_URL`, `DR_KUBECONFIG_CONTEXT`, opsiyonel `DR_REDIS_URL`; S3 yolu varsayılan olarak `s3://oss-compliance-backups/latest.dump` fakat `--backup-uri` ile özelleştirilebilir.
- **Adımlar:**
  1. Script'i staging hesabında `bash scripts/dr-drill.sh --env=staging --namespace=oss-platform-dr` komutuyla başlat; yalnızca planı görmek için `--dry-run` ekle.
  2. Script bitiminde `kubectl --context $DR_KUBECONFIG_CONTEXT get pods -n oss-platform-dr` ile pod durumunu doğrula.
  3. `npm run perf:test` otomatik tetiklenir; başarısız olursa olay kaydı aç ve `docs/postmortem-template.md` şablonuyla inceleme başlat.

## 6. On-Call Notları
- İletişim kanalları: PagerDuty (Primary), Slack #oss-alerts (Secondary).
- Eskalasyon zinciri: Primary → Secondary → Platform Manager (15 dakika içinde çözülmezse).
- Olay sonrası rapor şablonu `docs/postmortem-template.md` içinde tutulur; 48 saat içinde doldurulması zorunlu.

## 7. Sık Kullanılan Komutlar
```bash
make up                # Docker Compose ile tüm servisleri ayağa kaldır
npm run migrate        # Şema migrasyonlarını uygula
npm run seed           # Örnek verileri yükle (yalnızca dev/stage)
kubectl apply -f deploy/k8s/api.yaml -n $NAMESPACE    # API deployment'ını güncelle
kubectl apply -f deploy/k8s/worker.yaml -n $NAMESPACE # Worker deployment'ını güncelle
npm run lint           # Kod kalite kontrolleri
npm test               # Birim ve entegrasyon testleri (≥%80 coverage)
npm run perf:test      # k6 ile performans testi (p95<250ms, hata<0.5%)
```

On-call ekibi bu dökümanı Confluence kopyasıyla senkron tutmakla sorumludur; değişiklikler için pull request açın ve runbook versiyonunu sürüm notlarına ekleyin.

## 8. Tarama Kurtarma ve Tutarlılık Kontrolü
- Worker süreçleri SBOM, lisans ve zafiyet kayıtlarını tek bir PostgreSQL transaction'ı içinde saklar; `sboms`, `licenses` ve `vulns` tablolarındaki satırlar kısmi olarak yazılamaz.
- Worker start komutu aktif bir lisans (`scan:execute` özelliği) doğrulanmazsa `Worker license is not active` veya `missing scan entitlement` mesajıyla hata verir; `npx tsx scripts/license-manager.ts status` ile durumu kontrol et ve lisansı yenilemeden prosesi yeniden başlatma.
- API ve worker süreçleri, `LICENSE_PUBLIC_KEY` değeri Secrets Manager URI'si olsa bile çözümlenen anahtarı doğrudan lisans doğrulayıcıya iletir; `secretsmanager://...` kullanıyorsan gizli değerin düz metin Ed25519 public key (base64url) içerdiğini doğrula.
- Partial veri şüphesi varsa `SELECT id, status, findings FROM scans WHERE id = '<scan_id>'` çıktısını doğrula, ardından aynı `scan_id`/`sbom_id` için `sboms`, `licenses`, `vulns` tablolarında kayıt eşleşmelerini kontrol et (`COUNT(*)` sonuçlarının birbirini tamamlaması gerekir).
- Worker COMMIT aşamasında hata alırsa bağlantıyı `release(error)` ile havuza hatalı olarak döndürür; `pg` havuzu bu client'ı kapatır ve aynı bağlantı yeniden kullanılmaz.
- Transaction başarıyla tamamlandıktan sonra webhook bildirimleri gönderilir; `scans.findings.webhooks` alanı COMMIT sonrası ayrı bir `UPDATE` ile teslimat sonuçlarıyla güncellenir, bu yüzden `findings.webhooks.failed` sayacının artması durumda transaction'ın zaten kalıcı olduğunu varsayabilirsin.
- Kuyruğa ekleme (`queue.add('scan', …)`) aşamasında hata alınırsa API 500 döner ve ilgili `scan_requests`/`scans` kayıtları otomatik silinir; istemciye aynı `Idempotency-Key` ile isteği yeniden göndermesini söyle (temizlik tamamlandığından yeni tarama başarıyla sıraya alınacaktır).
- Post-commit webhook güncellemesi başarısız olursa worker loglarında `jsonb_set` sorgu hatası veya ağ kesintisi görülür; aynı scan için `UPDATE scans SET findings = jsonb_set(findings::jsonb, '{webhooks}', $2::jsonb, true) WHERE id = $1` sorgusunu manuel çalıştırıp eksik webhooks listesini yeniden yaz ve ilgili webhooks'u `bullmq` CLI ile tekrar sıraya al (`node scripts/retry-webhook.js <webhook_id>`).
- Postgres `pg_stat_database.xact_rollback` metriğinde ani artış veya worker loglarında yinelenen `Transaction rollback failed` mesajları görülürse transaction kaynaklı bütünlük sorunlarını araştır.
- Uyumsuzluk görülürse transaction dışı bir manuel müdahale yapılmış demektir; problemli kayıtları silmek için `BEGIN; DELETE FROM licenses WHERE sbom_id = '<sbom_id>'; DELETE FROM vulns WHERE scan_id = '<scan_id>'; DELETE FROM sboms WHERE id = '<sbom_id>'; UPDATE scans SET status = 'failed', findings = jsonb_set(findings::jsonb, '{error}', '"resync"', true) WHERE id = '<scan_id>'; COMMIT;` komut setini kullan ve taramayı kuyruktan yeniden tetikle (`bullmq` CLI `queue.add('scan', ...)`).

## 9. Windows Offline Installer EULA Kontrolü
- WiX tabanlı MSI, offline kurulumlarda EULA kabulünü iki kaynaktan doğrular:
  - Kurulumu `msiexec /i AtlasSCA.msi ALTERA_EULA_ACCEPTED=1` parametresiyle çağırmak (CI script'leri bu bayrağı zorunlu kılmalı).
  - `%ProgramData%\Atlas SCA\eula.accepted` marker dosyasını önceden oluşturmak ve yalnızca Administrators ile LocalSystem'e tam erişim verecek şekilde ACL'lemek (`powershell -Command "New-Item -ItemType File -Force '%ProgramData%\Atlas SCA\eula.accepted'; icacls '%ProgramData%\Atlas SCA\eula.accepted' /inheritance:r /grant:r Administrators:F System:F"`).
- Şayet marker dosyası symlink veya geniş erişimli ise installer durur ve `observability/update-log` içinde `result:"blocked"` kaydı üretir; ACL düzeltildikten sonra yeniden denenmelidir.
- Kurulum tekrar denenecekse `%ProgramData%\Atlas SCA` altındaki marker ve log kayıtları korunmalı; manuel silme yalnızca destek onayı ile yapılmalıdır.
