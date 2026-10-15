# glp1-nobet

Bay GLP-1 iOS uygulamasının nöbetçi eczane listesi için veri hattı.

- GitHub Actions günde iki kez (10.15 ve 19.45, Türkiye saati) nöbetçi eczane listesini veri sağlayıcıdan çeker.
- Liste il başına şifrelenip `yayin` dalına yazılır; GitHub Pages bu daldan sunar. Okunabilir eczane verisi
  bu depoda bulunmaz; dosyaları yalnız uygulama açar.
- Kişisel veri yoktur.

Kaynak: il eczacı odaları (TEB) · veri sağlayıcı: NosyAPI
