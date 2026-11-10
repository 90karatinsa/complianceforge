# Tarayıcı Adaptörleri

Bu klasör, SBOM üretimi, lisans tespiti ve güvenlik açığı taraması için dış araçlara bağlanan adaptörleri içerecektir. Planlanan alt bileşenler:

- `sbom/`: CycloneDX üretimi ve normalizasyonu
- `licenses/`: SPDX eşleme motoru
- `vulns/`: OSV/NVD besleme entegrasyonu

Her adaptör deterministik sonuçlar üretmeli ve aynı girdi için tekrarlanabilirlik garanti etmelidir.
