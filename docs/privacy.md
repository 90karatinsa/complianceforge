# Telemetri ve Gizlilik Bildirimi

Bu doküman Alterra-Solutions Otomatik OSS Lisans & Güvenlik Uyumluluk Aracı için geçerlidir ve müşteriye sağlanan ilk kurulum paketinin ayrılmaz parçasıdır.

## Varsayılan Davranış

- Ürün, lisans doğrulaması tamamlanana kadar ve **TELEMETRY_ENABLED** ortam değişkeni `true` yapılmadığı sürece herhangi bir kullanım metrik verisi toplamaz, dış servislere çağrı göndermez.
- Varsayılan çalışmada uygulama yalnızca zorunlu altyapı bileşenleri (PostgreSQL, Redis) ile konuşur; müşteri verisi ya da taranan kaynak kodu Alterra-Solutions altyapısına gönderilmez.
- API logları; istek kimliği, tenant kimliği ve hata kodu gibi operasyonel alanları içerir, kişisel veri (PII) veya gizli anahtarlar maskelenir.

## Telemetriyi Etkinleştirme

- Telemetri yalnızca açık rıza ile devreye alınabilir: `TELEMETRY_ENABLED=true` olarak yapılandırılmadığı sürece hiçbir veri gönderilmez.
- Etkinleştirildiğinde aşağıdaki metrikler toplanır ve Alterra-Solutions telemetri uç noktasına TLS üzerinden gönderilir:
  - Ürün versiyonu, lisans kimliği (hashlenmiş), tenant planı.
  - Günlük bazda tarama sayıları, politika ihlalleri (sayısal toplam), ortalama tarama süresi.
  - Kritik hata sinyalleri (worker çökmesi, lisans doğrulama başarısızlığı) – olay sayacı şeklinde.
- Telemetri içeriği hiçbir şekilde taranan projelerin isimlerini, dosya yollarını, PURL listesini veya müşteri tarafından yüklenen artefaktların ham verisini içermez.

## Veri Saklama ve Silme Politikası

- Telemetri kayıtları maksimum 180 gün saklanır ve sonrasında otomatik olarak anonimleştirilmiş toplu istatistikler haricinde kalıcı depodan silinir.
- Müşteri talebi halinde tüm telemetri kayıtları 7 iş günü içerisinde kalıcı olarak silinir; silme işlemi tamamlandığında onay e-postası paylaşılır.
- Üçüncü taraflarla telemetri verisi paylaşılmaz; Alterra-Solutions içindeki yetkili SRE ve ürün ekipleri erişebilir.

## Opt-Out ve İletişim

- Telemetriyi kapatmak için `TELEMETRY_ENABLED` değerini `false` yapmanız veya ilgili ortam değişkenini tamamen kaldırmanız yeterlidir; uygulama yeniden başlatıldığında veri gönderimi durur.
- Gizlilik, veri işleme veya telemetri politikalarıyla ilgili sorularınız için **privacy@alterra-solutions.example** adresine ulaşabilirsiniz.
- Alterra-Solutions, politikada yapılacak değişiklikleri ürün sürüm notlarında ve bu dokümanda tarihçesiyle birlikte duyuracaktır.
