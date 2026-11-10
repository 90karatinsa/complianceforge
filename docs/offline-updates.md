<!-- SPDX-License-Identifier: MIT -->

# Offline Güncelleme ve Rollback Kılavuzu

Bu kılavuz, Atlas SCA platformunun air-gapped ortamlarda güvenli şekilde güncellenmesi için gerekli adımları açıklar. Tüm süreç boyunca ComplianceForge lisans (MIT) hükümleri geçerlidir ve imzalı manifestlerin offline doğrulanması zorunludur.

## 1. Güncelleme Paketi Yapısı

- Güncelleme dosyaları `.altu` uzantılı tek bir arşivdir.
- Arşiv, aşağıdaki öğeleri içerir:
  - `manifest.json`: ürün, sürüm, minimum izin verilen sürüm (`minimum_downgrade_version`), hedef platform/arch ve dosya hash'lerini içeren Canonical JSON.
  - `payload/`: sürümle ilişkili paketler.
  - `SIGNATURE`: manifest'in Ed25519 imzası (base64url).

## 2. İmza Doğrulama

1. Vendor tarafından sağlanan public key'i `/etc/atlas-sca/update-signing.pub` olarak saklayın.
2. `scripts/feed-import.ts` aracı offline ortamda manifesti doğrular. Örnek:

```bash
npm run tsx -- scripts/feed-import.ts verify \
  --manifest ./feeds/2024-07-12/manifest.json \
  --signature ./feeds/2024-07-12/SIGNATURE \
  --public-key "$(cat /etc/atlas-sca/update-signing.pub)"
```

3. İmza doğrulanmadan paket uygulanmaz; hata durumunda işlem denetim loguna "failure" sonucu ile kaydedilir.
4. Doğrulama sonrasında API'ye gönderilecek gövdeyi üretmek için `activate`/`rollback` komutları kullanılır. Örnek:

# aktivasyon isteği için gövde üretir (gerekirse --archive veya --manifest/--signature ile yeniden doğrulayın)
npm run tsx -- scripts/feed-import.ts activate \
  --tenant-id 55555555-5555-4555-8555-555555555555 \
  --manifest-id 66666666-6666-4666-8666-666666666666 \
  --version 2024.07

# rollback isteği için minimal gövde üretir
npm run tsx -- scripts/feed-import.ts rollback \
  --tenant-id 55555555-5555-4555-8555-555555555555 \
  --manifest-id 66666666-6666-4666-8666-666666666666
```

## 3. Anti-Rollback Politikası

- Her manifest `minimum_downgrade_version` alanını içerir. Bu değer, kurulabilecek en düşük sürümü tanımlar.
- `feeds activate` ve `feeds rollback` uç noktaları, hedef sürüm bu eşikten düşükse işlemi reddeder.
- Reddedilen işlemler `observability/update-log.ts` aracılığıyla append-only log'a "blocked" sonucu ile kaydedilir.

## 4. Offline Dağıtım Adımları

1. Güncellemeyi içeren taşınabilir medyayı (örn. USB) offline ortama getirin.
2. Medyanın SHA-256 hash listesini vendor manifestiyle karşılaştırın.
3. `npm run package:deb` veya `npm run package:windows` ile üretilen kurulum paketlerinin hash dosyalarını (`*.sha256`) doğrulayın.
4. Güncellemeyi uygulamadan önce mevcut sürümün Evidence Pack çıktısını arşivleyin.
5. macOS dağıtımlarında, `npm run package:macos` çıktısı olan `.pkg` kurulumunun preinstall betiği EULA onayı olmadan ilerlemez:
   - Offline ortamda `npm run license:status -- --accept-eula` komutunu çalıştırarak hem kullanıcı yapılandırma dizinindeki `eula.json` kaydını hem de `/Library/Application Support/Atlas SCA/eula.accepted` marker dosyasını 0o600 izinleriyle oluşturun.
   - Alternatif olarak marker dosyasını manuel oluştururken (ör. `sudo install -d -m 755 "/Library/Application Support/Atlas SCA"`; `sudo install -m 600 /dev/null "/Library/Application Support/Atlas SCA/eula.accepted"`), dosyanın symlink olmaması ve 0600 izinlerinde kalması gerekir.
   - Bu koşullardan hiçbiri sağlanmazsa installer `EULA acceptance required` mesajı ile sonlanır ve işlem log'a "blocked" sonucu ile yazılır.
6. Windows MSI kurulumunda WiX launch condition aynı EULA onayını bekler:
   - Installer'ı `msiexec /i AtlasSCA.msi ALTERA_EULA_ACCEPTED=1` şeklinde çağırarak oturum bazlı kabul bayrağını geçin **veya**
   - `%ProgramData%\Atlas SCA\eula.accepted` dosyasını kurulumdan önce yalnızca Administrators/LocalSystem erişimi olacak şekilde oluşturun (örn. `powershell -Command "New-Item -ItemType File -Force '%ProgramData%\Atlas SCA\eula.accepted' ; icacls '%ProgramData%\Atlas SCA\eula.accepted' /inheritance:r /grant:r Administrators:F System:F"`).
   - Her iki koşul da sağlanmazsa kurulum durdurulur, `update-log` girdisi "blocked" olarak kaydedilir ve rollback gerektirirse `%ProgramData%\Atlas SCA` altındaki kayıtlar silinmeden yeniden deneme yapılmamalıdır.

## 5. Rollback Prosedürü

1. Önceden imzalı manifest ve payload arşivlerini saklayın.
2. Rollback işlemi öncesinde etkin sürüm `update-log` dosyasında "rollback-requested" kaydıyla belirtilir.
3. `feeds rollback` çağrısı, hedef sürüm `minimum_downgrade_version` değerini sağlamıyorsa reddedilir ve log'a "blocked" sonucu yazılır.
4. Rollback sonrası `npm run license:status -- --accept-eula` komutu ile lisans durumunu tekrar doğrulayın.

## 6. Kanıt ve Arşivleme

- Her güncelleme veya rollback girişimi `observability/update-log` altında dönen JSON satırlarıyla arşivlenir.
- Hash ve imza doğrulama çıktıları Evidence Pack içine eklenmelidir.
- Offline kayıtlar en az beş yıl saklanmalı ve değişime karşı imza veya WORM depolama ile korunmalıdır.

Bu adımlar tamamlanmadan gerçekleştirilen herhangi bir güncelleme, destek kapsamı dışında kalır ve sözleşmeye aykırıdır.
