<!-- SPDX-License-Identifier: MIT -->

# Air-Gapped Kurulum Kılavuzu

Bu doküman Atlas SCA platformunu tamamen kapalı bir ağda (internet erişimi olmadan) devreye almak için gereken adımları özetler. Tüm bileşenler Docker konteynerleri ve Kubernetes Helm chart'ları aracılığıyla dağıtılabilir; feed paketleri, imzalar ve Evidence Pack çıktıları ayrı dizinlerde saklanır.

## 1. Önkoşullar

- **İmaj ve paket replikasyonu:** `ghcr.io/alterra/oss-licensing/*` imajlarını çevrimdışı registry'nize aktarın veya `docker save` ile taşınabilir arşivler oluşturun.
- **Kriptografik materyal:** Feed paketlerini doğrulamak için sağlanan `atlas-feed.pub` cosign anahtarını güvenli biçimde saklayın.
- **Altyapı:** Linux tabanlı Docker runtime (Compose) veya Kubernetes 1.26+ kümesi.
- **Dosya sistemi erişimi:** Feed cache (`/var/lib/atlas/feeds`), Evidence Pack (`/var/lib/atlas/evidence`) ve cosign anahtarları (`/var/lib/atlas/cosign`) için kalıcı depolama.

> Not: Kurulum boyunca outbound ağ erişimi engelli olmalıdır. Kubernetes'te `NetworkPolicy` veya altyapı firewall kuralları ile çıkış trafiğini kapatmanız önerilir.

## 2. Docker Compose ile kurulum

1. **Dizinleri oluşturun**

   ```bash
   mkdir -p airgap/feed-cache airgap/evidence airgap/cosign
   cp /path/to/atlas-feed.pub airgap/cosign/
   ```

2. **Çevrimdışı imajları yükleyin** (opsiyonel)

   ```bash
   docker load -i atlas-sca-api.tar
   docker load -i atlas-sca-worker.tar
   ```

3. **Servisleri başlatın**

   ```bash
   make up
   ```

   `docker-compose.yml` dosyası feed cache, evidence ve cosign volume'larını bağlar, Postgres/Redis sağlık kontrolleri hazır hale geldikten sonra API `http://localhost:3000` üzerinde dinlemeye başlar.

4. **Kurulumu doğrulayın**

   ```bash
   curl -s http://localhost:3000/v1/health | jq '.status'
   docker compose ps
   ```

   Sağlık uç noktası `healthy` döndürürken Compose çıktısı tüm konteynerlerin `healthy` durumda olduğunu göstermelidir.

## 3. Kubernetes (Helm) ile kurulum

1. **PersistentVolumeClaim ve Secret hazırlığı**

   ```yaml
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: atlas-feed-cache
   spec:
     accessModes: [ReadWriteOnce]
     resources:
       requests:
         storage: 20Gi
   ---
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: atlas-evidence-packs
   spec:
     accessModes: [ReadWriteOnce]
     resources:
       requests:
         storage: 50Gi
   ---
   apiVersion: v1
   kind: Secret
   metadata:
     name: atlas-cosign-pub
   stringData:
     atlas-feed.pub: |
       -----BEGIN PUBLIC KEY-----
       ...
       -----END PUBLIC KEY-----
   ```

2. **Helm values güncellemesi**

   `deploy/helm/api/values.yaml` ve `deploy/helm/worker/values.yaml` dosyalarındaki `extraEnv`, `volumes` ve `volumeMounts` bölümleri varsayılan olarak `/var/lib/atlas/feeds`, `/var/lib/atlas/evidence` ve `/var/lib/atlas/cosign` yollarını işaret eder. Kendi PVC/secret isimleriniz farklıysa güncelleyin.

3. **Chart'ı uygulayın**

   ```bash
   helm upgrade --install atlas-api deploy/helm/api
   helm upgrade --install atlas-worker deploy/helm/worker
   ```

4. **Health kontrolleri**

   ```bash
   kubectl get pods -l app.kubernetes.io/name=oss-licensing-api
   kubectl port-forward deploy/atlas-api 3000:80
   curl -s http://localhost:3000/v1/health | jq '.status'
   ```

## 4. Feed ve Evidence yönetimi

- Feed `.tgz` paketlerini `airgap/feed-cache` dizinine kopyalayın (veya Kubernetes ortamında ilgili PVC'ye yükleyin).
- API üzerinden `GET /v1/feeds` çağrısı ile import geçmişini, `POST /v1/feeds/activate` ile aktif sürümü güncelleyebilirsiniz. Tüm çağrılar `Admin` rolü gerektirir.
- Evidence Pack çıktıları worker tarafından `/var/lib/atlas/evidence` dizinine yazılır; bu dizin yalnızca yetkili kullanıcılar tarafından okunmalıdır.

## 5. Outbound erişimi test edin

Air-gapped politikasını doğrulamak için konteyner içinde bir dış ağ isteğinin engellendiğini test edin:

```bash
docker compose exec api wget -q --timeout=3 https://example.com || echo "Outbound engellendi"
```

Kurulum tamamlandığında Atlas SCA, feed güncellemelerini imzalı paketler üzerinden, audit kayıtlarını ise Evidence Pack çıktılarıyla kapalı ağda yönetmeye hazırdır.
