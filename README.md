# TLS-Audit-Arac-v0.2-oklu-domain-deste-i
Bir çok sitenin TLS auidtini ve headerlarını aynı anda kontrol eden python kodu. Claude ile çalışıldı.

# TLS Audit Tool v0.1 — Kod Açıklaması

Bu belge, `tls_audit.py` dosyasındaki her parçanın ne yaptığını sade bir dille anlatır.

---

## 1. Script Ne Yapıyor? (Büyük Resim)

Bir web sitesine (örneğin google.com) bağlanıp şu soruları cevaplıyor:

- Bu site şifreli bağlantı (HTTPS) kullanıyor mu?
- Şifreleme ne kadar güçlü?
- Sertifikası geçerli mi, ne zaman bitiyor?
- Bilinen güvenlik başlıklarını koymuş mu?

Sonuçları terminalde renkli tablo olarak gösteriyor, istenirse JSON dosyasına da kaydediyor.

---

## 2. Kullanılan Kütüphaneler

```python
import ssl
import socket
import argparse
import json
import sys
from datetime import datetime, timezone
```

Bunların hepsi Python ile birlikte gelir, ekstra kurulum gerekmez.

**ssl** → Python'un SSL/TLS modülü. Bir sunucuya şifreli bağlantı kurmamızı sağlar. Tarayıcın bir siteye `https://` ile bağlandığında arka planda aynı işi yapıyor — bu modül o işi kod olarak yapmamızı sağlıyor.

**socket** → Bilgisayarlar arası ham ağ bağlantısı kurmanın en temel yolu. "Şu IP'nin şu portuna bağlan" demek için kullanılır. Düşün ki telefon hattı çekiyorsun — socket hattı açar, ssl o hattı şifreler.

**argparse** → Terminalde `--domain google.com` gibi parametreleri okuyan modül. Kullanıcıdan girdi almak için `input()` yerine bunu kullanıyoruz çünkü terminal komutlarıyla çalışmak profesyonel araçların standardı.

**json** → Python sözlüğünü (dict) JSON formatına çevirip dosyaya yazıyor. JSON, veriyi saklamanın ve paylaşmanın evrensel formatı — hemen her programlama dili okuyabilir.

**datetime, timezone** → Tarih ve saat işlemleri. Sertifikanın bitiş tarihini bugünle karşılaştırıp "kaç gün kaldı" hesaplamak için kullanıyoruz.

---

## 3. Colors Sınıfı — Renkli Terminal Çıktısı

```python
class Colors:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
```

Terminal normalde beyaz yazı gösterir. Ama `\033[92m` gibi özel kodlar (ANSI escape kodları) yazının rengini değiştirir. Mekanizma şöyle çalışır:

- `\033[` → "dikkat terminal, şimdi bir komut geliyor" demek
- `92` → yeşil renk kodu
- `m` → "komutu uygula"
- `\033[0m` (RESET) → "renklendirmeyi kapat, normale dön"

Yani `"\033[92mMerhaba\033[0m"` yazdığında terminal "Merhaba" kelimesini yeşil gösterir, sonra normale döner.

```python
def colored(text, color):
    return f"{color}{text}{Colors.RESET}"
```

Bu fonksiyon sadece bir kısayol. `colored("GÜVENLI", Colors.GREEN)` dediğinde `"\033[92mGÜVENLİ\033[0m"` string'ini üretir.

---

## 4. check_tls() — Ana Fonksiyon: TLS Bağlantısı

Bu fonksiyon en kritik parça. Bir domain'e SSL/TLS bağlantısı kurup bilgileri topluyor.

### 4.1 Sonuç Sözlüğü (Result Dict)

```python
result = {
    "domain": domain,
    "tls_version": None,
    "cipher_suite": None,
    "cipher_bits": None,
    "certificate": {},
    "cert_days_left": None,
    "headers": {},
    "errors": []
}
```

Bu bir Python sözlüğü (dictionary). Tarama sonuçlarını buraya dolduruyoruz. Başlangıçta her şey `None` (boş) — çünkü henüz tarama yapmadık. Hata olursa `errors` listesine eklenir, başarılıysa diğer alanlar dolar.

### 4.2 SSL Context Oluşturma

```python
context = ssl.create_default_context()
```

"Context" burada "ayarlar paketi" demek. Bu tek satır şunları yapar:

- Hangi TLS versiyonlarının kabul edileceğini belirler (varsayılan: TLS 1.2+)
- Sertifika doğrulamasını açar (sahte sertifika kullanan siteyi yakalar)
- Güvenli cipher'ları seçer

Tarayıcın da arka planda aynı şeyi yapar — sen farkında olmazsın.

### 4.3 TCP Bağlantısı + SSL Sarmalama

```python
with socket.create_connection((domain, port), timeout=10) as sock:
    with context.wrap_socket(sock, server_hostname=domain) as ssock:
```

Bu iki satır, internette bağlantı kurmanın iki katmanını gösterir:

**Katman 1: `socket.create_connection()`** → Hedefe düz bir TCP bağlantısı açar. Bu, şifresiz bir bağlantı — şu an sadece "hat çekildi", üstünde veri akabilir ama herkes okuyabilir. `timeout=10` ise "10 saniye içinde bağlanamazsan vazgeç" demek.

**Katman 2: `context.wrap_socket()`** → O düz bağlantıyı SSL/TLS ile sarar. Bu adımda TLS Handshake gerçekleşir:

1. Client (biz): "Merhaba, şu TLS versiyonlarını ve cipher'ları destekliyorum"
2. Server: "Tamam, TLS 1.3 ve AES-256 kullanalım. İşte sertifikam"
3. Client: Sertifikayı doğrular, ortak bir şifreleme anahtarı oluşturulur
4. Artık bağlantı şifreli

`server_hostname=domain` parametresi SNI (Server Name Indication) için gerekli. Aynı IP'de birden fazla site barınabilir (shared hosting) — bu parametre sunucuya "ben google.com'a bağlanmak istiyorum" diyor, sunucu da doğru sertifikayı gönderiyor.

`with ... as ...` yapısı (context manager) ise "işim bitince bağlantıyı otomatik kapat" demek. Manuel olarak `sock.close()` yazmana gerek kalmaz.

### 4.4 TLS Versiyonunu Okuma

```python
result["tls_version"] = ssock.version()
```

`ssock.version()` bağlantıda kullanılan TLS protokolünü döndürür. Olası değerler:

- `"TLSv1.3"` → En güncel ve güvenli. Handshake daha hızlı, daha az round-trip.
- `"TLSv1.2"` → Hâlâ güvenli ama eski. Çoğu site destekler.
- `"TLSv1.1"` veya `"TLSv1.0"` → Güvensiz, kullanılmamalı. Bilinen açıkları var.
- `"SSLv3"` → Çok eski, POODLE saldırısına açık.

### 4.5 Cipher Suite Bilgisi

```python
cipher_info = ssock.cipher()
result["cipher_suite"] = cipher_info[0]
result["cipher_bits"]  = cipher_info[2]
```

`ssock.cipher()` üç elemanlı bir tuple döndürür, örneğin: `("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)`

**Cipher Suite nedir?** Bağlantıda kullanılan şifreleme algoritmaları kombinasyonu. `TLS_AES_256_GCM_SHA384` ismini parçalarsak:

- **AES_256** → Veriyi şifreleyen algoritma (AES) ve anahtar uzunluğu (256 bit). Bit ne kadar yüksekse kırmak o kadar zor.
- **GCM** → Şifreleme modu. Hem şifreler hem de verinin değiştirilmediğini doğrular (integrity).
- **SHA384** → Hash fonksiyonu. Verinin bütünlüğünü kontrol eden özet algoritması.

**Bit sayısı** şifreleme gücünü gösterir: 256 bit = çok güçlü, 128 bit = yeterli, altı = zayıf.

### 4.6 Sertifika Bilgilerini Okuma

```python
cert = ssock.getpeercert()
not_after = cert.get("notAfter", "")
expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
days_left = (expiry_date - datetime.now(timezone.utc)).days
```

`getpeercert()` sunucunun dijital sertifikasını bir Python sözlüğü olarak döndürür.

**Dijital sertifika nedir?** Bir web sitesinin kimlik kartı. "Ben gerçekten google.com'um" diyor ve bunu bir Sertifika Otoritesi (CA — Certificate Authority, örneğin Let's Encrypt) onaylıyor. İçinde şunlar var:

- **subject (konu)** → Sertifikanın kime ait olduğu. `commonName` alanı genelde domain adını içerir.
- **issuer (veren)** → Sertifikayı hangi CA'nın verdiği. Örneğin Google Trust Services, Let's Encrypt.
- **notBefore / notAfter** → Sertifikanın geçerlilik aralığı. `notAfter`'dan sonra sertifika geçersiz sayılır, tarayıcılar uyarı verir.
- **serialNumber** → Sertifikanın benzersiz numarası.
- **subjectAltName (SAN)** → Sertifikanın geçerli olduğu tüm domain'ler. Örneğin Google'ın bir sertifikası hem `google.com`, hem `*.google.com`, hem `youtube.com` için geçerli olabilir.

`datetime.strptime()` tarih string'ini Python datetime nesnesine çevirir. Sonra bugünden çıkarıp kalan gün sayısını hesaplıyoruz. 30 günden az kaldıysa uyarı (sarı), süresi dolduysa alarm (kırmızı).

### 4.7 Hata Yakalama (try/except)

```python
except ssl.SSLCertVerificationError as e:
    result["errors"].append(f"Sertifika doğrulama hatası: {e}")
except socket.timeout:
    result["errors"].append(f"Bağlantı zaman aşımı (10s)")
except socket.gaierror:
    result["errors"].append(f"DNS çözümlenemedi")
except ConnectionRefusedError:
    result["errors"].append(f"Bağlantı reddedildi")
```

Ağ işlemlerinde her şey ters gidebilir. Her `except` bloğu farklı bir hata türünü yakalar:

- **SSLCertVerificationError** → Sertifika geçersiz veya sahte. Self-signed sertifikalarda olur.
- **socket.timeout** → Sunucu 10 saniye içinde yanıt vermedi. Sunucu kapalı veya firewall engelliyor olabilir.
- **socket.gaierror** → "Get Address Info Error". Domain adı IP'ye çevrilemedi — yani ya yanlış yazmışsın (gogle.com) ya da domain var olmuyordur.
- **ConnectionRefusedError** → Sunucu var ama 443 portunu dinlemiyor (HTTPS aktif değil).

`try/except` olmadan bu hatalardan herhangi biri programı çökertir. Bu yapıyla hata olsa bile program düzgün bir mesaj verip devam eder.

---

## 5. check_headers() — HTTP Güvenlik Başlıkları

```python
import http.client
conn = http.client.HTTPSConnection(domain, timeout=10)
conn.request("HEAD", "/")
response = conn.getresponse()
```

Bu fonksiyon siteye bir HTTP isteği gönderip yanıttaki güvenlik başlıklarını (headers) kontrol ediyor.

**http.client** → Python'un dahili HTTP istemcisi. `requests` kütüphanesi daha popüler ama kurulum gerektirir; `http.client` kurulum gerektirmez.

**HEAD isteği nedir?** Normal bir GET isteği sayfanın tüm içeriğini (HTML, resimler vs.) indirir. HEAD ise sadece başlıkları (headers) getirir, içeriği indirmez. Biz sadece başlıklara bakacağımız için HEAD kullanıyoruz — daha hızlı ve daha az bant genişliği harcar.

**Kontrol edilen güvenlik başlıkları:**

| Başlık | Ne İşe Yarar |
|--------|-------------|
| **Strict-Transport-Security (HSTS)** | Tarayıcıya "bu siteye her zaman HTTPS ile bağlan, HTTP kullanma" der. Kullanıcı `http://site.com` yazsa bile tarayıcı otomatik `https://` yapar. |
| **X-Content-Type-Options** | Tarayıcının dosya türünü tahmin etmesini engeller. Değeri genelde `nosniff`. Saldırgan bir `.jpg` dosyasını `.js` olarak çalıştırmaya çalışırsa bu başlık engeller. |
| **X-Frame-Options** | Sitenin başka bir sitede iframe içinde gösterilmesini engeller. Clickjacking saldırısını önler — saldırgan senin siten üzerine görünmez bir katman koyup tıklamalarını çalamaz. |
| **Content-Security-Policy (CSP)** | Sayfada hangi kaynakların (script, resim, font, iframe) yüklenebileceğini belirler. XSS saldırılarına karşı en güçlü savunma. "Sadece benim domainimden gelen scriptleri çalıştır" gibi kurallar koyabilirsin. |
| **X-XSS-Protection** | Eski tarayıcılarda basit XSS saldırılarını yakalayan dahili filtre. Modern tarayıcılarda CSP daha etkili ama bu hâlâ ek bir katman. |
| **Referrer-Policy** | Kullanıcı sitenden başka bir siteye geçtiğinde, URL bilgisinin ne kadarının paylaşılacağını kontrol eder. Gizlilik için önemli. |
| **Permissions-Policy** | Tarayıcı özelliklerine (kamera, mikrofon, konum, gyroscope) erişimi kısıtlar. "Bu sitede kamera erişimi yok" gibi kurallar koyarsın. |

Bir başlık `None` dönerse → site o başlığı eklemeyi unutmuş demektir. Bu bir güvenlik açığı değil ama eksik bir savunma katmanı.

---

## 6. print_report() — Terminale Renkli Çıktı

Bu fonksiyon topladığımız verileri insanın okuyabileceği formata çevirir. Mantığı basit:

```python
if "1.3" in tls:
    # Yeşil yaz — en güvenli
elif "1.2" in tls:
    # Sarı yaz — kabul edilebilir
else:
    # Kırmızı yaz — tehlikeli
```

Her veri noktası için bir renk mantığı var. Trafik ışığı gibi düşün: yeşil = iyi, sarı = dikkat, kırmızı = sorun var. Güvenlik başlıkları için de aynı mantık: başlık varsa yeşil ✓, yoksa kırmızı ✗.

---

## 7. save_json() — JSON Dosyasına Kaydetme

```python
def save_json(result, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
```

**json.dump()** → Python sözlüğünü JSON formatına çevirip doğrudan dosyaya yazar.

- `indent=2` → JSON'u düzgün girintili (okunabilir) yazar. Bu olmadan her şey tek satırda olur.
- `ensure_ascii=False` → Türkçe karakterlerin (ö, ü, ş, ç) düzgün yazılmasını sağlar. Bu olmadan `\u00f6` gibi kodlarla yazar.

JSON çıktısını Fiverr'daki müşterine rapor olarak verebilirsin — veya başka araçlarla (Splunk, ELK, Grafana) işleyebilirsin.

---

## 8. main() — Programın Giriş Noktası

### 8.1 argparse — Komut Satırı Argümanları

```python
parser = argparse.ArgumentParser(description="...")
parser.add_argument("--domain", "-d", type=str, required=True, help="...")
parser.add_argument("--json", "-j", type=str, default=None, help="...")
args = parser.parse_args()
```

**argparse nedir?** Terminalde çalıştırılan programlara parametre geçmenin standart yolu.

`python tls_audit.py --domain google.com --json rapor.json` yazdığında argparse şunları yapar:

1. `--domain` ve `--json` flag'lerini tanır
2. Değerlerini `args.domain` ve `args.json` olarak saklar
3. `--domain` verilmediyse hata mesajı gösterip çıkar (çünkü `required=True`)
4. `-d` ve `-j` kısa yol olarak da çalışır: `python tls_audit.py -d google.com`
5. `--help` veya `-h` yazılırsa otomatik yardım metni gösterir

### 8.2 Domain Temizleme

```python
domain = args.domain.strip().replace("https://", "").replace("http://", "").rstrip("/")
```

Kullanıcı `https://google.com/` yazabilir. Ama socket bağlantısı sadece domain adı ister (`google.com`). Bu satır gereksiz kısımları temizler:

- `strip()` → baştaki ve sondaki boşlukları siler
- `replace("https://", "")` → protokolü kaldırır
- `rstrip("/")` → sondaki slash'ı kaldırır

### 8.3 Çalıştırma Sırası

```python
result = check_tls(domain)        # TLS taraması
result["headers"] = check_headers(domain)  # Header taraması
result["scan_time"] = datetime.now(timezone.utc).isoformat()  # Zaman damgası
print_report(result)              # Ekrana yazdır
if args.json:
    save_json(result, args.json)  # JSON kaydet (istenirse)
```

Program sırayla şunları yapar:

1. TLS bağlantısı kur, versiyon/cipher/sertifika bilgilerini topla
2. Eğer TLS bağlantısı başarılıysa HTTP güvenlik başlıklarını kontrol et
3. Tarama zamanını UTC olarak kaydet (raporun ne zaman yapıldığını gösterir)
4. Her şeyi terminale renkli olarak yazdır
5. Kullanıcı `--json rapor.json` verdiyse dosyaya da kaydet

### 8.4 if __name__ == "__main__"

```python
if __name__ == "__main__":
    main()
```

Bu Python'un "bu dosya doğrudan çalıştırıldığında main()'i çağır" kalıbı. Eğer bu dosyayı başka bir dosyadan `import tls_audit` olarak çağırırsan, `main()` otomatik çalışmaz — sadece fonksiyonları kullanabilirsin. Ama `python tls_audit.py` diye çalıştırırsan `main()` çalışır.

---

## Terimler Sözlüğü

| Terim | Açıklama |
|-------|----------|
| **TLS (Transport Layer Security)** | İnternet trafiğini şifreleyen protokol. HTTPS'in arkasındaki teknoloji. Eski adı SSL. |
| **SSL (Secure Sockets Layer)** | TLS'in eski versiyonu. Artık kullanılmıyor ama isim hâlâ yaygın ("SSL sertifikası" gibi). |
| **Handshake** | Client ve server'ın şifreleme yönteminde anlaştığı ilk iletişim. El sıkışma gibi — "nasıl konuşacağız" kararı. |
| **Cipher Suite** | Şifreleme, anahtar değişimi ve hash algoritmasının kombinasyonu. "Hangi kilitle kilitleyeceğiz" kararı. |
| **Sertifika (Certificate)** | Bir web sitesinin dijital kimlik kartı. Bir CA tarafından imzalanır. |
| **CA (Certificate Authority)** | Sertifika veren güvenilir kuruluş. Kimlik kartındaki noterlik gibi. |
| **SAN (Subject Alternative Name)** | Bir sertifikanın geçerli olduğu tüm domain listesi. |
| **HSTS** | Tarayıcıya "sadece HTTPS kullan" diyen güvenlik başlığı. |
| **CSP (Content Security Policy)** | Hangi kaynakların yüklenebileceğini belirleyen güvenlik başlığı. XSS'e karşı koruma. |
| **XSS (Cross-Site Scripting)** | Saldırganın siteye zararlı JavaScript enjekte etmesi. |
| **Clickjacking** | Görünmez katman ile kullanıcıyı istemediği yere tıklatma saldırısı. |
| **ANSI Escape Codes** | Terminalde yazı rengini, kalınlığını değiştiren özel karakter dizileri. |
| **Context Manager (with)** | Kaynağı (dosya, bağlantı) otomatik açıp kapatan Python yapısı. |
| **SNI (Server Name Indication)** | TLS handshake'te "hangi domain'e bağlanmak istiyorum" bilgisini gönderen mekanizma. |
| **Port 443** | HTTPS trafiğinin varsayılan portu. HTTP ise 80. |
