#!/usr/bin/env python3
"""Nöbetçi eczane listesini sağlayıcıdan çeker, il başına şifreli dosyalara yazar.

Kaynak: NosyAPI `pharmacies-on-duty/all` (tüm Türkiye ve KKTC; her çekim 81 kredi).
Çıktı: v1/il/01.bin … v1/il/81.bin (şifreli) ve durum.json (şifresiz; eczane bilgisi içermez).
NosyAPI'nin yazılı yanıtı (15 Ekim 2026): liste herkese açık yayınlanırsa kullanım koşulları bozulabilir;
bu yüzden şifreleyip yalnız kendi uygulamamızda kullanıyoruz. Kişisel veri yok; yalnız eczane bilgileri.

İl dosyası: JSON (UTF-8) → ham DEFLATE (zlib, wbits=-15) → AES-256-GCM. Dosya = nonce (12 bayt) +
şifreli metin + etiket (16 bayt), yani CryptoKit'teki `AES.GCM.SealedBox(combined:)` biçimi. Anahtar
32 bayttır; base64 olarak `NOBET_ANAHTAR` ortam değişkeninden okunur. GLP-1 iOS uygulaması bu biçime
bağlıdır: alan adlarını ya da biçimi değiştirmeden önce Mac tarafına haber ver
(docs/Nobetci_Eczane_Talimati_B.md).

Kullanım:
  NOSYAPI_KEY=... NOBET_ANAHTAR=... python3 nobet_cek.py --cikti cikti            # sağlayıcıdan çek
  NOBET_ANAHTAR=... python3 nobet_cek.py --girdi ornek_yanit.json --cikti deneme  # deneme: dosyadan oku
  NOBET_ANAHTAR=... python3 nobet_cek.py --coz deneme/v1/il/06.bin                # şifreli dosyayı aç
  python3 nobet_cek.py --anahtar-uret anahtar.txt                                 # yeni anahtar üret

Python 3.8+ (Windows dahil) ve `cryptography` paketi gerekir: pip install cryptography==44.0.2
"""
import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.request
import zlib

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # --anahtar-uret için gerekmez; diğer işlerde sifre_anahtari() uyarır
    AESGCM = InvalidTag = None

API = "https://www.nosyapi.com/apiv2/service/pharmacies-on-duty/all"
# Türkiye yaz saati uygulamaz: sabit +03.00 (Windows'ta tzdata gerekmesin diye zoneinfo kullanılmadı).
TZ = dt.timezone(dt.timedelta(hours=3), "+03")
KAYNAK = "İl eczacı odaları (TEB) · veri sağlayıcı: NosyAPI"
# Biçim ve anahtar sürümü; dosya yolunda yer alır (v1/il/34.bin). Anahtar değişirse 2 olur.
SURUM = 1

ILLER = {
    "01": "Adana", "02": "Adıyaman", "03": "Afyonkarahisar", "04": "Ağrı", "05": "Amasya", "06": "Ankara",
    "07": "Antalya", "08": "Artvin", "09": "Aydın", "10": "Balıkesir", "11": "Bilecik", "12": "Bingöl",
    "13": "Bitlis", "14": "Bolu", "15": "Burdur", "16": "Bursa", "17": "Çanakkale", "18": "Çankırı",
    "19": "Çorum", "20": "Denizli", "21": "Diyarbakır", "22": "Edirne", "23": "Elazığ", "24": "Erzincan",
    "25": "Erzurum", "26": "Eskişehir", "27": "Gaziantep", "28": "Giresun", "29": "Gümüşhane", "30": "Hakkari",
    "31": "Hatay", "32": "Isparta", "33": "Mersin", "34": "İstanbul", "35": "İzmir", "36": "Kars",
    "37": "Kastamonu", "38": "Kayseri", "39": "Kırklareli", "40": "Kırşehir", "41": "Kocaeli", "42": "Konya",
    "43": "Kütahya", "44": "Malatya", "45": "Manisa", "46": "Kahramanmaraş", "47": "Mardin", "48": "Muğla",
    "49": "Muş", "50": "Nevşehir", "51": "Niğde", "52": "Ordu", "53": "Rize", "54": "Sakarya",
    "55": "Samsun", "56": "Siirt", "57": "Sinop", "58": "Sivas", "59": "Tekirdağ", "60": "Tokat",
    "61": "Trabzon", "62": "Tunceli", "63": "Şanlıurfa", "64": "Uşak", "65": "Van", "66": "Yozgat",
    "67": "Zonguldak", "68": "Aksaray", "69": "Bayburt", "70": "Karaman", "71": "Kırıkkale", "72": "Batman",
    "73": "Şırnak", "74": "Bartın", "75": "Ardahan", "76": "Iğdır", "77": "Yalova", "78": "Karabük",
    "79": "Kilis", "80": "Osmaniye", "81": "Düzce",
}
# Sağlayıcının farklı yazabileceği il adları.
TAKMA = {"afyon": "03", "icel": "33", "kmaras": "46", "kahramanmaras": "46", "maras": "46",
         "urfa": "63", "sanliurfa": "63", "antep": "27", "hakkari": "30"}
# "kibriskktc": sağlayıcı KKTC kayıtlarını "Kıbrıs KKTC" diye yazıyor (ilk gerçek çekim, 15 Ekim 2026).
KKTC = {"lefkosa", "gazimagusa", "magusa", "girne", "guzelyurt", "iskele", "lefke", "kktc", "kibris", "kibriskktc"}


def anahtar(s):
    """Türkçe karakterleri sadeleştirip küçük harfe indirir: 'Şanlıurfa' -> 'sanliurfa'."""
    s = (s or "").replace("İ", "i").replace("I", "ı").lower().replace("ı", "i")
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", s)


IL_ANAHTAR = {anahtar(ad): kod for kod, ad in ILLER.items()}
IL_ANAHTAR.update(TAKMA)


def il_kodu(city):
    k = anahtar(city)
    if not k or k in KKTC:
        return None
    return IL_ANAHTAR.get(k)


def telefon(s):
    """'0 (312) 512-26-12' -> '+903125122612'. Tanınmayan biçimde None döner."""
    d = re.sub(r"\D", "", s or "")
    if len(d) == 11 and d.startswith("0"):
        return "+90" + d[1:]
    if len(d) == 10:
        return "+90" + d
    if len(d) == 12 and d.startswith("90"):
        return "+" + d
    return None


ZAMAN_BICIMLERI = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d.%m.%Y %H:%M:%S", "%d.%m.%Y %H:%M")


def zaman(s):
    """'2024-01-21 09:30:00' -> '2024-01-21T09:30:00+03:00'. Tanınmazsa None.

    Belgedeki biçim ilk satırdaki; ilk gerçek çekimde (15 Ekim 2026) saatlerin hiçbiri bu biçimde
    gelmediği için ISO 8601 (saat dilimli ya da 'Z') ve Unix zaman damgası da kabul edilir."""
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return dt.datetime.fromtimestamp(s, TZ).isoformat()
    if not isinstance(s, str) or not s.strip():
        return None
    s = s.strip()
    for bicim in ZAMAN_BICIMLERI:
        try:
            return dt.datetime.strptime(s, bicim).replace(tzinfo=TZ).isoformat()
        except ValueError:
            pass
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    t = t.replace(tzinfo=TZ) if t.tzinfo is None else t.astimezone(TZ)
    return t.replace(microsecond=0).isoformat()


def sekil(kayit, alan):
    """Tanınmayan değerin biçimini veriyi göstermeden yazar: '15/10/2026 09:00' -> '99/99/9999 99:99'."""
    if alan not in kayit:
        return "<alan yok>"
    d = kayit[alan]
    if d is None:
        return "<null>"
    if not isinstance(d, str):
        return f"<{type(d).__name__}>"
    return re.sub(r"\d", "9", d.strip())[:40] or "<boş>"


def metin(s):
    s = (s or "").strip() if isinstance(s, str) else s
    return s or None


def sifre_anahtari():
    """NOBET_ANAHTAR ortam değişkenindeki base64 metni 32 baytlık anahtara çevirir."""
    deger = os.environ.get("NOBET_ANAHTAR", "").strip()
    if not deger:
        sys.exit("NOBET_ANAHTAR ortam değişkeni tanımlı değil.")
    try:
        gizli = base64.b64decode(deger, validate=True)
    except ValueError:
        sys.exit("NOBET_ANAHTAR geçerli bir base64 metni değil.")
    if len(gizli) != 32:
        sys.exit(f"NOBET_ANAHTAR 32 bayt olmalı; {len(gizli)} bayt geldi.")
    if AESGCM is None:
        sys.exit("cryptography paketi kurulu değil: pip install cryptography==44.0.2")
    return gizli


def sifrele(gizli, veri):
    """Sözlük -> JSON -> ham DEFLATE -> AES-256-GCM. Dönen dizi: nonce + şifreli metin + etiket."""
    duz = json.dumps(veri, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sikistirici = zlib.compressobj(9, zlib.DEFLATED, -15)
    sikisik = sikistirici.compress(duz) + sikistirici.flush()
    nonce = os.urandom(12)
    return nonce + AESGCM(gizli).encrypt(nonce, sikisik, None)


def coz(gizli, icerik):
    """sifrele'nin tersi. Anahtar yanlışsa ya da dosya bozuksa InvalidTag yükseltir."""
    sikisik = AESGCM(gizli).decrypt(icerik[:12], icerik[12:], None)
    return json.loads(zlib.decompress(sikisik, -15).decode("utf-8"))


def cek(key):
    req = urllib.request.Request(API, headers={"X-NSYP": key, "Accept": "application/json",
                                               "User-Agent": "glp1-nobet/1.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def yaz(yol, veri):
    gecici = yol + ".tmp"
    with open(gecici, "w", encoding="utf-8", newline="\n") as f:
        json.dump(veri, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(gecici, yol)


def yaz_bayt(yol, icerik):
    gecici = yol + ".tmp"
    with open(gecici, "wb") as f:
        f.write(icerik)
    os.replace(gecici, yol)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cikti", default=".", help="v1/il/ klasörünün ve durum.json'un yazılacağı yer")
    p.add_argument("--girdi", help="Sağlayıcı yanıtını bu dosyadan oku (deneme için)")
    p.add_argument("--coz", metavar="DOSYA", help="Şifreli il dosyasını açıp JSON olarak yazdır")
    p.add_argument("--anahtar-uret", metavar="DOSYA", help="Yeni anahtarı bu dosyaya yaz (ekrana yazmaz)")
    a = p.parse_args()
    for akis in (sys.stdout, sys.stderr):  # Windows'ta da Türkçe karakterler bozulmasın
        akis.reconfigure(encoding="utf-8")

    if a.anahtar_uret:
        try:
            with open(a.anahtar_uret, "x", encoding="ascii", newline="\n") as f:
                f.write(base64.b64encode(os.urandom(32)).decode("ascii") + "\n")
        except FileExistsError:
            sys.exit(f"{a.anahtar_uret} zaten var; üzerine yazılmadı.")
        print(f"Yeni anahtar {a.anahtar_uret} dosyasına yazıldı.")
        return

    # Anahtar sağlayıcıya gitmeden önce denetlenir: eksik anahtar kredi harcatmasın.
    gizli = sifre_anahtari()

    if a.coz:
        with open(a.coz, "rb") as f:
            icerik = f.read()
        try:
            veri = coz(gizli, icerik)
        except InvalidTag:
            sys.exit("Dosya açılamadı: anahtar yanlış ya da dosya bozuk.")
        print(json.dumps(veri, ensure_ascii=False, indent=1))
        return

    if a.girdi:
        with open(a.girdi, encoding="utf-8") as f:
            yanit = json.load(f)
    else:
        key = os.environ.get("NOSYAPI_KEY", "").strip()  # yapıştırırken gelen boşluk ve satır sonu atılır
        if not key:
            sys.exit("NOSYAPI_KEY ortam değişkeni tanımlı değil.")
        try:
            yanit = cek(key)
        except urllib.error.HTTPError as e:
            sys.exit(f"Sağlayıcı HTTP {e.code} döndürdü: {e.read()[:200]!r}")
        except Exception as e:  # ağ, zaman aşımı, bozuk JSON
            sys.exit(f"Sağlayıcıya ulaşılamadı: {e}")

    kayitlar = yanit.get("data") if isinstance(yanit, dict) else None
    if not isinstance(kayitlar, list) or not kayitlar:
        sys.exit(f"Sağlayıcı kayıt vermedi: status={yanit.get('status')!r} "
                 f"message={yanit.get('messageTR') or yanit.get('message')!r}")

    simdi = dt.datetime.now(TZ).replace(microsecond=0).isoformat()
    iller = {kod: [] for kod in ILLER}
    eslesmeyen = {}
    taninmayan = {}  # (alan, biçim) -> kayıt sayısı
    for r in kayitlar:
        kod = il_kodu(r.get("city"))
        if not kod:
            if anahtar(r.get("city")) not in KKTC:
                eslesmeyen[r.get("city")] = eslesmeyen.get(r.get("city"), 0) + 1
            continue
        tel = telefon(r.get("phone"))
        saat = {}
        for alan in ("pharmacyDutyStart", "pharmacyDutyEnd"):
            saat[alan] = zaman(r.get(alan))
            if saat[alan] is None:
                k = (alan, sekil(r, alan))
                taninmayan[k] = taninmayan.get(k, 0) + 1
        iller[kod].append({
            "kimlik": r.get("pharmacyID"),
            "ad": metin(r.get("pharmacyName")) or "",
            "ilce": metin(r.get("district")) or "",
            "mahalle": metin(r.get("town")),
            "adres": metin(r.get("address")),
            "tarif": metin(r.get("directions")),
            "telefon": tel,
            "telefon2": telefon(r.get("phone2")),
            "telefonHam": None if tel else metin(r.get("phone")),
            "baslangic": saat["pharmacyDutyStart"],
            "bitis": saat["pharmacyDutyEnd"],
            "enlem": r.get("latitude"),
            "boylam": r.get("longitude"),
        })

    durum_yolu = os.path.join(a.cikti, "durum.json")
    onceki = {}
    if os.path.exists(durum_yolu):
        try:
            with open(durum_yolu, encoding="utf-8") as f:
                onceki = json.load(f)
        except (OSError, ValueError):
            onceki = {}

    toplam = sum(len(v) for v in iller.values())
    onceki_toplam = int(onceki.get("toplam") or 0)
    uyarilar = []
    il_durum = dict(onceki.get("iller") or {})

    # Koruma: toplam kayıt yarıdan fazla düştüyse sağlayıcıda bir sorun olabilir; eski dosyalar kalır (N09).
    if onceki_toplam and toplam < onceki_toplam / 2:
        uyarilar.append(f"Toplam kayıt {onceki_toplam} -> {toplam}: yarıdan fazla düştü, il dosyaları değiştirilmedi.")
        os.makedirs(a.cikti, exist_ok=True)
        yaz(durum_yolu, {"surum": SURUM, "guncelleme": onceki.get("guncelleme"), "sonDeneme": simdi,
                         "toplam": onceki_toplam, "kaynak": KAYNAK, "iller": il_durum, "uyari": uyarilar})
        print(uyarilar[0])
        sys.exit(2)

    il_klasoru = os.path.join(a.cikti, f"v{SURUM}", "il")
    os.makedirs(il_klasoru, exist_ok=True)
    yazilan = 0
    for kod, liste in iller.items():
        yol = os.path.join(il_klasoru, f"{kod}.bin")
        if not liste:
            uyarilar.append(f"{kod} {ILLER[kod]}: bu çekimde kayıt yok" +
                            (", eski dosya korundu." if os.path.exists(yol) else "."))
            continue
        liste.sort(key=lambda e: (anahtar(e["ilce"]), anahtar(e["ad"])))
        yaz_bayt(yol, sifrele(gizli, {"il": kod, "ilAdi": ILLER[kod], "guncelleme": simdi,
                                      "kaynak": KAYNAK, "eczaneler": liste}))
        il_durum[kod] = {"ad": ILLER[kod], "guncelleme": simdi, "sayi": len(liste)}
        yazilan += 1
    for ad, n in eslesmeyen.items():
        uyarilar.append(f"Eşleşmeyen il adı: {ad!r} ({n} kayıt atlandı)")
    for (alan, bicim), n in sorted(taninmayan.items(), key=lambda x: -x[1]):
        uyarilar.append(f"Nöbet saati tanınmadı: {alan}, {n} kayıt, biçim {bicim!r}")
    if taninmayan:  # tanı için yalnız günlüğe: alan adları veri içermez
        print("Sağlayıcının alan adları:", ", ".join(sorted(kayitlar[0].keys())))

    yaz(durum_yolu, {"surum": SURUM, "guncelleme": simdi, "sonDeneme": simdi, "toplam": toplam,
                     "kaynak": KAYNAK, "iller": il_durum, "uyari": uyarilar})
    print(f"{toplam} kayıt, {yazilan} il dosyası şifrelenip yazıldı; {len(uyarilar)} uyarı.")
    for u in uyarilar:
        print(" -", u)


if __name__ == "__main__":
    main()
