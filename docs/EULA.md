<!-- SPDX-License-Identifier: MIT -->

# Lisans ve kurulum onayı

ComplianceForge [MIT lisansı](../LICENSE) ile dağıtılır: kullanmak, değiştirmek ve yeniden dağıtmak serbesttir;
yazılım "olduğu gibi" sağlanır, hiçbir garanti verilmez.

## Kurulum paketlerindeki onay

Kurumsal kurulum paketleri (MSI, PKG, DEB) ilk kurulumda ve büyük güncellemelerde lisans metninin okunduğunu
onaylatır. Bu bir kullanım kısıtı değil, kapalı ağ kurulumlarında denetim kaydı içindir:

- Kurulum araçları `--accept-eula` bayrağı ya da önceden hazırlanmış onay kaydı olmadan durur.
- Güncelleme paketleri ve tehdit beslemeleri Ed25519 imzasıyla gelir; offline doğrulama adımları atlanmaz.
  Manifest doğrulaması, hash kontrolü ve sürüm düşürme (anti-rollback) koruması kapatılamaz.

## Gizlilik

- Ürün varsayılan olarak telemetri göndermez.
- Kaynak kodu, tarama girdileri ve lisans yükleri işlendikten sonra temizlenir; yalnız SBOM ve denetim metaverisi
  saklanır.
