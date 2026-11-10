<!-- SPDX-License-Identifier: MIT -->

# Offline Lisans Yönetimi

Bu ürün ilk çalıştırma öncesinde fiziksel veya sanal ortamda çevrimdışı lisanslama adımlarını zorunlu kılar. Aşağıdaki prosedür lisans isteğini oluşturup onaylı lisans paketini doğrulayarak yüklemek için izlenmelidir.

## EULA kabulü

Kurulumdan önce Alterra-Solutions [EULA metnini](./EULA.md) inceleyip kabul etmeniz gerekir. `license-manager` aracının `install` ve `status` alt komutları, komuta `--accept-eula` (opsiyonel olarak sürüm numarasıyla `--accept-eula=<versiyon>`) verilmediği veya daha önce `~/.config/otomatik-oss/eula.json` dosyasında imzalı kabul kaydı bulunmadığı sürece çalışmayı reddeder. İlk çalıştırma senaryosunda aşağıdaki örneği izleyin:

```bash
npm run license:install -- \
  --response ./license-response.json \
  --accept-eula
```

CLI, kabul edilen sürümü lisans loguna işler ve sonraki çağrılarda aynı düğümde saklanan kabul kaydını otomatik olarak kullanır. Yeni bir EULA yayımlandığında komutu `--accept-eula=<yeni-sürüm>` ile tekrar çalıştırarak kaydı güncelleyin.

## Donanım parmak izi isteği oluşturma

1. Çalıştırılacak düğümde gerekli sistem servisleri (TPM, BIOS seri vb.) erişilebilir olmalıdır.
2. Ortam değişkenlerinde `LICENSE_REQUEST_NONCE` tanımlı değilse komut otomatik olarak kriptografik olarak güvenli bir nonce üretir.
3. Aşağıdaki komut lisans isteği JSON'unu standart çıktıya yazar ve `artifacts/license-request.json` dosyasına kaydeder:

```bash
npm run license:request -- \
  --output artifacts/license-request.json
```

Komut çıktısı `license_id`, `product_id`, `hw_fingerprint` ve `request_nonce` alanlarını içerir. Talebi Alterra-Solutions lisans portalına yükleyin.

## Lisans paketini doğrulama ve kurulum

Lisans sağlayıcı tarafından dönen yanıt dosyası `license-response.json` ismiyle sağlanır. Dosyanın aşağıdaki alanları içermesi gerekir:

- `signature`: Ed25519 imzası (base64url).
- `license`: İmzalanmış lisans gövdesi.
- `payload`: AES-GCM ile şifrelenmiş dağıtım paketinin base64url temsilcisi.

Kurulum için önce imzalayanın kamu anahtarını komuta sağlayın. Anahtar base64url kodlu DER biçimindedir ve iki farklı şekilde aktarılabilir:

- Ortam değişkeni: `export LICENSE_PUBLIC_KEY="<base64url-der>"`
- CLI bayrağı: komutlara `--public-key <base64url-der>` ekleyin (örn. havuzlanmış servislerde veya tek seferlik testlerde)

Anahtar belirtilmezse komut `LICENSE_PUBLIC_KEY environment variable is required.` hatası ile sonlanır.

Kurulum için:

```bash
npm run license:install -- \
  --response ./license-response.json
```

Komut:

1. Lisans gövdesinin Ed25519 imzasını doğrular.
2. `hw_fingerprint` alanının yerel makine ile eşleştiğini teyit eder.
3. AES-GCM yükünü çözerek bütünlük kontrolünü gerçekleştirir.
4. Çözülen gizli verileri işletim sistemi kimlik kasasına (`keytar`) yazar.

Başarılı yüklemenin ardından lisansın bitiş tarihi ve etkin özellikleri standart çıktıda listelenir.

## Lisans durumunu kontrol etme

İlgili düğümde lisans durumunu doğrulamak için (çevrimdışı/air-gap senaryolarında yukarıdaki kamu anahtarı temin yöntemlerinden birini tekrar kullanın):

```bash
npm run license:status
```

Komut mevcut lisans meta verisini, geçerlilik tarihlerini, son doğrulama zamanını ve olası uyarıları raporlar. Kamu anahtarı sağlanmazsa aynı `LICENSE_PUBLIC_KEY environment variable is required.` mesajını üretir. Donanım parmak izi uyuşmazlığı, imza geçersizliği veya şifre çözme hatalarında süreç non-zero çıkış kodu ile durur.

## İşletimsel hususlar

- Lisans yüklemesi yalnızca çevrimdışı ortamlarda çalışacak şekilde tasarlanmıştır; ağ erişimine ihtiyaç duymaz.
- Yanlış tarih/saat (ör. geçmişe ayarlı saat) tespit edildiğinde kurulum reddedilir; saat kaynağını düzeltip komutu yeniden çalıştırın.
- Lisansların yenilenmesi için yeni bir `request_nonce` üretip aynı adımları takip edin.
- Komutlar `~/.config/otomatik-oss/license.log` dosyasına işlem özeti yazar; güvenlik politikanız gerektirdiğinde bu logları merkezi sistemlere kopyalayın.

## Kurtarma ve iptal

- Lisans anahtarlarının iptal edilmesi gerektiğinde Alterra-Solutions destek ekibi ile iletişime geçin ve ilgili lisans kimliğini bildirin.
- İptal edilen lisanslar `license:status` komutu çalıştırıldığında "revoked" durumu ile raporlanır ve sistem tarama işlerini başlatmaz.
- Acil durumlarda `npm run license:install -- --purge` komutu lisans kasasını temizleyerek sistemi güvenli moda alır.

## İlgili belgeler

- [Hızlı Başlangıç](./quickstart.md)
- [Politika örnekleri](./policies/README.md)
- [Güvenlik tarama kılavuzu](../README.md#guvenlik-ve-uyumluluk)
