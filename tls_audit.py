#!/usr/bin/env python3
"""
TLS Audit Tool v0.1
Tek bir domain için TLS/HTTPS güvenlik denetimi yapar.

Kontroller:
  - TLS versiyonu
  - Cipher suite
  - Sertifika bilgileri ve son kullanma tarihi
  - HTTP güvenlik başlıkları (headers)

Kullanım:
  python3 tls_audit.py --domain example.com
  python3 tls_audit.py --domain example.com --json rapor.json
"""

import ssl
import socket
import argparse
import json
import sys
from datetime import datetime, timezone

# ── Renkli terminal çıktısı ──────────────────────────────────────
# ANSI renk kodları — terminalde renkli tablo yazdırmak için kullanılır.
# Her renk bir escape sequence: \033[XXm formatında.
class Colors:
    GREEN  = "\033[92m"   # Güvenli / iyi sonuç
    YELLOW = "\033[93m"   # Uyarı
    RED    = "\033[91m"   # Tehlikeli / kötü sonuç
    CYAN   = "\033[96m"   # Başlık / bilgi
    BOLD   = "\033[1m"    # Kalın yazı
    RESET  = "\033[0m"    # Rengi sıfırla (normal yazıya dön)


def colored(text, color):
    """Metni verilen renkle sarar."""
    return f"{color}{text}{Colors.RESET}"


# ── TLS Bağlantısı ───────────────────────────────────────────────
def check_tls(domain, port=443):
    """
    Domain'e SSL/TLS bağlantısı kurar ve bilgileri döndürür.

    ssl.create_default_context() → Python'un yerleşik SSL modülünü kullanarak
    güvenli bir bağlantı bağlamı (context) oluşturur. Bu context, hangi TLS
    versiyonlarının kabul edileceğini ve sertifika doğrulamasını yönetir.

    wrap_socket() → normal bir TCP soketini SSL/TLS katmanıyla sarar.
    Böylece bağlantı şifreli hale gelir ve sertifika bilgilerine erişiriz.
    """
    result = {
        "domain": domain,
        "port": port,
        "tls_version": None,
        "cipher_suite": None,
        "cipher_bits": None,
        "certificate": {},
        "cert_days_left": None,
        "headers": {},
        "errors": []
    }

    try:
        # SSL context oluştur — sertifika doğrulaması varsayılan olarak açık
        context = ssl.create_default_context()

        # TCP soketi aç (timeout 10 saniye — sunucu yanıt vermezse beklemekten kurtarır)
        with socket.create_connection((domain, port), timeout=10) as sock:
            # Soketi SSL ile sar — TLS handshake burada gerçekleşir
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                # ── TLS Versiyonu ──
                # ssock.version() → bağlantıda kullanılan protokolü döndürür
                # Örnek: "TLSv1.3", "TLSv1.2"
                result["tls_version"] = ssock.version()

                # ── Cipher Suite ──
                # ssock.cipher() → (cipher_adı, protokol, bit_sayısı) tuple döndürür
                # Cipher suite = şifreleme algoritması + anahtar değişim yöntemi kombinasyonu
                cipher_info = ssock.cipher()
                result["cipher_suite"] = cipher_info[0]  # ör: "TLS_AES_256_GCM_SHA384"
                result["cipher_bits"]  = cipher_info[2]   # ör: 256

                # ── Sertifika Bilgileri ──
                # getpeercert() → sunucunun X.509 sertifikasını dict olarak döndürür
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "")  # Sertifikanın bitiş tarihi (string)

                # Tarihi parse et — ssl modülü "%b %d %H:%M:%S %Y GMT" formatında verir
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                days_left   = (expiry_date - datetime.now(timezone.utc)).days

                result["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "serial": cert.get("serialNumber", ""),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": not_after,
                    "san": [entry[1] for entry in cert.get("subjectAltName", ())]
                }
                result["cert_days_left"] = days_left

    except ssl.SSLCertVerificationError as e:
        result["errors"].append(f"Sertifika doğrulama hatası: {e}")
    except socket.timeout:
        result["errors"].append(f"{domain}:{port} bağlantı zaman aşımı (10s)")
    except socket.gaierror:
        result["errors"].append(f"{domain} DNS çözümlenemedi")
    except ConnectionRefusedError:
        result["errors"].append(f"{domain}:{port} bağlantı reddedildi")
    except Exception as e:
        result["errors"].append(f"Beklenmeyen hata: {e}")

    return result


# ── HTTP Güvenlik Başlıkları ──────────────────────────────────────
def check_headers(domain):
    """
    HTTPS üzerinden HTTP güvenlik başlıklarını kontrol eder.

    http.client kullanıyoruz (requests yerine) çünkü:
    - Python standart kütüphanesinde — ekstra kurulum gerektirmez
    - Sadece header'lara bakıyoruz, sayfa içeriğiyle işimiz yok
    - Hafif ve hızlı

    Kontrol edilen başlıklar:
    - Strict-Transport-Security (HSTS): Tarayıcıya "bu siteye sadece HTTPS ile bağlan" der
    - X-Content-Type-Options: MIME type sniffing saldırısını engeller
    - X-Frame-Options: Clickjacking saldırısını engeller (iframe'de gösterimi kısıtlar)
    - Content-Security-Policy (CSP): Hangi kaynakların yüklenebileceğini belirler (XSS koruması)
    - X-XSS-Protection: Eski tarayıcılarda XSS filtresi (modern tarayıcılarda CSP tercih edilir)
    - Referrer-Policy: Sayfa geçişlerinde referrer bilgisinin ne kadar paylaşılacağını kontrol eder
    - Permissions-Policy: Tarayıcı API'lerine (kamera, mikrofon, konum) erişimi kısıtlar
    """
    import http.client

    # Kontrol edilecek güvenlik başlıkları
    security_headers = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    headers_result = {}

    try:
        # HTTPS bağlantısı kur ve HEAD isteği gönder
        # HEAD = sadece başlıkları getir, sayfa içeriğini indirme
        conn = http.client.HTTPSConnection(domain, timeout=10)
        conn.request("HEAD", "/")
        response = conn.getresponse()

        # Her güvenlik başlığını kontrol et
        for header in security_headers:
            value = response.getheader(header)
            headers_result[header] = value if value else None

        conn.close()

    except Exception as e:
        for header in security_headers:
            headers_result[header] = f"HATA: {e}"

    return headers_result


# ── Terminal Çıktısı (Renkli Tablo) ──────────────────────────────
def print_report(result):
    """Sonuçları terminalde renkli tablo olarak yazdırır."""
    print()
    print(colored("=" * 60, Colors.CYAN))
    print(colored(f"  TLS Audit Raporu — {result['domain']}", Colors.BOLD))
    print(colored("=" * 60, Colors.CYAN))

    # Hatalar varsa önce onları göster
    if result["errors"]:
        for err in result["errors"]:
            print(colored(f"  ✗ {err}", Colors.RED))
        print()
        return

    # ── TLS Bilgileri ──
    print(colored("\n  [ TLS Bağlantısı ]", Colors.BOLD))

    # TLS versiyonu — 1.3 yeşil, 1.2 sarı, altı kırmızı
    tls = result["tls_version"]
    if tls and "1.3" in tls:
        print(f"    Protokol       : {colored(tls, Colors.GREEN)}")
    elif tls and "1.2" in tls:
        print(f"    Protokol       : {colored(tls, Colors.YELLOW)}")
    else:
        print(f"    Protokol       : {colored(tls or 'Bilinmiyor', Colors.RED)}")

    # Cipher suite ve bit gücü
    print(f"    Cipher Suite   : {result['cipher_suite']}")
    bits = result["cipher_bits"]
    if bits and bits >= 256:
        print(f"    Bit Gücü       : {colored(f'{bits} bit', Colors.GREEN)}")
    elif bits and bits >= 128:
        print(f"    Bit Gücü       : {colored(f'{bits} bit', Colors.YELLOW)}")
    else:
        print(f"    Bit Gücü       : {colored(f'{bits} bit' if bits else 'Bilinmiyor', Colors.RED)}")

    # ── Sertifika ──
    cert = result["certificate"]
    days = result["cert_days_left"]
    print(colored("\n  [ Sertifika ]", Colors.BOLD))
    print(f"    Konu (CN)      : {cert.get('subject', {}).get('commonName', 'N/A')}")
    print(f"    Veren (Issuer) : {cert.get('issuer', {}).get('organizationName', 'N/A')}")
    print(f"    Bitiş Tarihi   : {cert.get('not_after', 'N/A')}")

    if days is not None:
        if days > 30:
            print(f"    Kalan Gün      : {colored(f'{days} gün', Colors.GREEN)}")
        elif days > 0:
            print(f"    Kalan Gün      : {colored(f'{days} gün ⚠ yakında bitiyor!', Colors.YELLOW)}")
        else:
            print(f"    Kalan Gün      : {colored(f'SÜRESİ DOLMUŞ ({abs(days)} gün önce)', Colors.RED)}")

    # SAN listesi (Subject Alternative Names)
    san = cert.get("san", [])
    if san:
        print(f"    SAN            : {', '.join(san[:5])}")
        if len(san) > 5:
            print(f"                     ... ve {len(san) - 5} tane daha")

    # ── Güvenlik Başlıkları ──
    print(colored("\n  [ HTTP Güvenlik Başlıkları ]", Colors.BOLD))
    for header, value in result["headers"].items():
        if value and not value.startswith("HATA"):
            status = colored("✓ VAR", Colors.GREEN)
            print(f"    {status}  {header}")
            print(f"           {colored(value, Colors.CYAN)}")
        else:
            status = colored("✗ YOK", Colors.RED)
            print(f"    {status}  {header}")

    print(colored("\n" + "=" * 60, Colors.CYAN))
    print()


# ── JSON Çıktısı ─────────────────────────────────────────────────
def save_json(result, filepath):
    """Sonuçları JSON dosyasına kaydeder."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(colored(f"  ✓ JSON rapor kaydedildi: {filepath}", Colors.GREEN))


# ── Ana Program ──────────────────────────────────────────────────
def main():
    # argparse → komut satırı argümanlarını yöneten standart kütüphane modülü.
    # Script'e terminalde flag'ler (--domain, --json) ile parametre geçmeni sağlar.
    # Hatalı kullanımda otomatik hata mesajı ve yardım metni gösterir.
    parser = argparse.ArgumentParser(
        description="TLS Audit Tool v0.1 — Tek domain TLS/HTTPS güvenlik denetimi"
    )
    parser.add_argument(
        "--domain", "-d",
        type=str,
        required=True,
        help="Taranacak domain (ör: example.com)"
    )
    parser.add_argument(
        "--json", "-j",
        type=str,
        default=None,
        help="Sonuçları JSON dosyasına kaydet (ör: rapor.json)"
    )

    args = parser.parse_args()
    domain = args.domain.strip().replace("https://", "").replace("http://", "").rstrip("/")

    print(colored(f"\n  ⏳ {domain} taranıyor...\n", Colors.CYAN))

    # 1) TLS kontrolü
    result = check_tls(domain)

    # 2) HTTP header kontrolü (TLS bağlantısı başarılıysa)
    if not result["errors"]:
        result["headers"] = check_headers(domain)

    # 3) Zaman damgası ekle
    result["scan_time"] = datetime.now(timezone.utc).isoformat()

    # 4) Terminale yazdır
    print_report(result)

    # 5) İstenirse JSON kaydet
    if args.json:
        save_json(result, args.json)


if __name__ == "__main__":
    main()
