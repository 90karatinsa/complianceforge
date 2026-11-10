<!-- SPDX-License-Identifier: MIT -->

# Politika Kılavuzu

Politikalar, lisans ve zafiyet kurallarının belirlenmesiyle tarama sonuçlarının `pass`, `warn` veya `fail` olarak işaretlenmesini sağlar. Tüm politikalar JSON formatında saklanır ve aşağıdaki alanları destekler:

- `allowed_spdx`: Tarama sonucunda serbestçe kullanılmasına izin verilen SPDX kimlikleri listesi.
- `denied_spdx`: Tespiti halinde taramayı `fail` durumuna çeken lisans kimlikleri.
- `cvss_threshold`: CVSS v3.1 taban puanı eşiği. Bu değerin üzerindeki bulgular politikanın başarısız olmasına neden olur.
- `allowlist_purls`: Belirli bileşen PURL değerleri için lisans ve CVSS kontrollerini atlayan beyaz liste.

## Örnek politika

[`default.json`](./default.json) dosyası başlangıç tenant'ı için yüklenen örnek politikayı temsil eder. Bu politika:

- MIT, Apache-2.0 ve BSD-3-Clause lisanslarını izinli kılar.
- GPL-3.0 ve AGPL-3.0 lisanslarını yasaklar.
- CVSS eşiğini 7.0 olarak belirler.
- Kritik üretim bağımlılığı olarak işaretlenen tek bir PURL değerini beyaz listeye alır.

Politikaları API üzerinden oluşturmak için `POST /v1/policies` uç noktasını kullanın. Tenant'lar politika kurallarını güncelledikten sonra yeni taramalar veya yeniden değerlendirmeler sırasında otomatik olarak uygulanacaktır.

## Kabul Kriterleri

Politika JSON'larının şeması, `schemas/` dizinindeki migrasyonlarla uyumlu olmalıdır. Geçersiz kurallar `VALIDATION` hata kodu ile reddedilir. Yeni politikalar eklendiğinde `docs/policies/` dizininde örneklerin güncellenmesi önerilir.
