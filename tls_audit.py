#!/usr/bin/env python3
"""
TLS Audit Tool v0.3
Bir veya birden fazla domain için TLS/HTTPS güvenlik denetimi yapar.

Kontroller:
  - TLS versiyonu
  - Cipher suite
  - Sertifika bilgileri ve son kullanma tarihi
  - HTTP güvenlik başlıkları (headers) — v0.2: `requests` ile tespit,
    eksik kritik başlıklar "uyarı" olarak işaretlenir
  - v0.3: Çoklu domain — aynı anda birden fazla site taranır (paralel),
    sonda karşılaştırmalı özet tablo yazdırılır

Gereksinim:
  pip install requests   (yalnızca header taraması için)

Kullanım:
  python3 tls_audit.py --domain example.com
  python3 tls_audit.py --domain example.com --json rapor.json
  python3 tls_audit.py -d example.com github.com google.com
  python3 tls_audit.py --file domains.txt --workers 10 --json rapor.json

Çıkış kodu: tüm domainler taranabildiyse 0, en az birinde hata varsa 1.
"""

import ssl
import socket
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

__version__ = "0.3"

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
        "headers": {},           # v0.2: her başlık için {present, value, status, ...}
        "header_warnings": [],   # v0.2: eksik kritik başlıkların listesi
        "header_error": None,    # v0.2: header taramasında oluşan hata (varsa)
        "final_url": None,       # v0.2: yönlendirmeler sonrası ulaşılan URL
        "http_status": None,     # v0.2: HTTP yanıt kodu
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
# İncelenen güvenlik başlıkları ve kısa açıklamaları.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — tarayıcıyı yalnızca HTTPS kullanmaya zorlar",
    "Content-Security-Policy":   "CSP — XSS ve veri enjeksiyonuna karşı kaynak kısıtlaması",
    "X-Frame-Options":           "Clickjacking (iframe) koruması",
    "X-Content-Type-Options":    "MIME type sniffing koruması",
    "X-XSS-Protection":          "Eski tarayıcılarda XSS filtresi (modern tarayıcıda CSP tercih edilir)",
    "Referrer-Policy":           "Referrer bilgisinin paylaşım politikası",
    "Permissions-Policy":        "Tarayıcı API erişim kısıtlaması (kamera, mikrofon, konum)",
}

# Eksikliği "uyarı" sayılan kritik başlıklar (v0.2 görev kapsamı):
# HSTS, CSP, X-Frame-Options, X-Content-Type-Options
CRITICAL_HEADERS = {
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
}


def check_headers(domain, port=443):
    """
    HTTPS üzerinden HTTP güvenlik başlıklarını çeker ve değerlendirir. (v0.2)

    v0.1'de http.client kullanılıyordu; v0.2 ile `requests` kütüphanesine geçildi:
    - Yönlendirmeleri (301/302) otomatik takip eder → son yanıtın başlıklarını okur
    - Başlık erişimi büyük/küçük harfe duyarsız (CaseInsensitiveDict)
    - Zaman aşımı, SSL ve bağlantı hatalarını tek çatı altında yönetir

    Her başlık için sonuç:
      present : başlık yanıtta var mı (bool)
      value   : başlığın değeri (yoksa None)
      status  : "ok"    → başlık mevcut
                "uyarı" → kritik başlık eksik (HSTS/CSP/X-Frame-Options/X-Content-Type-Options)
                "eksik" → kritik olmayan başlık eksik (bilgi amaçlı)

    Dönüş: mevcut JSON raporuna entegre edilmek üzere yapılandırılmış dict.
    """
    import requests

    out = {
        "headers": {},        # başlık adı -> değerlendirme dict'i
        "warnings": [],       # eksik kritik başlıkların adları
        "final_url": None,    # yönlendirmeler sonrası nihai URL
        "http_status": None,  # HTTP yanıt kodu
        "error": None,        # tarama sırasında oluşan hata mesajı
    }

    try:
        # 443 dışında bir port verilmişse URL'ye ekle
        base = f"https://{domain}" if port == 443 else f"https://{domain}:{port}"
        # GET + allow_redirects → yönlendirme yapan siteler için nihai başlıkları alırız.
        resp = requests.get(
            f"{base}/",
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": f"TLS-Audit-Tool/{__version__}"},
        )
        out["final_url"] = resp.url
        out["http_status"] = resp.status_code

        # Her güvenlik başlığını değerlendir
        for header, description in SECURITY_HEADERS.items():
            value = resp.headers.get(header)   # yoksa None döner
            present = value is not None
            is_critical = header in CRITICAL_HEADERS

            if present:
                status = "ok"
            elif is_critical:
                status = "uyarı"
                out["warnings"].append(header)
            else:
                status = "eksik"

            out["headers"][header] = {
                "present": present,
                "value": value,
                "status": status,
                "critical": is_critical,
                "description": description,
            }

    except requests.exceptions.SSLError as e:
        out["error"] = f"Header taraması — SSL hatası: {e}"
    except requests.exceptions.Timeout:
        out["error"] = f"Header taraması — {domain} zaman aşımı (10s)"
    except requests.exceptions.ConnectionError:
        out["error"] = f"Header taraması — {domain} bağlantı hatası"
    except requests.exceptions.RequestException as e:
        out["error"] = f"Header taraması — istek hatası: {e}"

    return out


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

    # Header taraması tamamen başarısızsa (bağlantı/SSL hatası) sebebi göster
    if result.get("header_error"):
        print(colored(f"    ✗ {result['header_error']}", Colors.RED))
    else:
        for header, info in result["headers"].items():
            if info["present"]:
                print(f"    {colored('✓ VAR  ', Colors.GREEN)} {header}")
                print(f"             {colored(info['value'], Colors.CYAN)}")
            elif info["status"] == "uyarı":
                # Kritik başlık eksik → uyarı
                print(f"    {colored('⚠ UYARI', Colors.YELLOW)} {header} "
                      f"{colored('(eksik — eklenmesi önerilir)', Colors.YELLOW)}")
            else:
                # Kritik olmayan başlık eksik → bilgi
                print(f"    {colored('✗ YOK  ', Colors.RED)} {header}")

        # Özet: kaç kritik başlık eksik
        warnings = result.get("header_warnings", [])
        if warnings:
            print(colored(
                f"\n    ⚠ {len(warnings)} kritik güvenlik başlığı eksik: {', '.join(warnings)}",
                Colors.YELLOW))
        else:
            print(colored("\n    ✓ Tüm kritik güvenlik başlıkları mevcut", Colors.GREEN))

    print(colored("\n" + "=" * 60, Colors.CYAN))
    print()


# ── JSON Çıktısı ─────────────────────────────────────────────────
def save_json(result, filepath):
    """Sonuçları JSON dosyasına kaydeder."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(colored(f"  ✓ JSON rapor kaydedildi: {filepath}", Colors.GREEN))


# ── Çoklu Domain (v0.3) ──────────────────────────────────────────
def normalize_domain(raw):
    """
    Kullanıcının yazdığı değeri çıplak domain'e çevirir.
    "https://Example.com/path" → "example.com"
    Boş satır veya yorum (#) ise None döner.
    """
    value = raw.strip()
    if not value or value.startswith("#"):
        return None
    for prefix in ("https://", "http://"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
    # Yol (path) kısmını at: "example.com/login" → "example.com"
    value = value.split("/", 1)[0]
    return value.lower() or None


def load_domains_from_file(path):
    """
    Her satırda bir domain olan metin dosyasını okur.
    Boş satırlar ve # ile başlayan yorumlar atlanır; satır sonu
    yorumları da desteklenir ("example.com  # ana site").
    """
    domains = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            domain = normalize_domain(line.split(" #", 1)[0])
            if domain:
                domains.append(domain)
    return domains


def unique_domains(domains):
    """Tekrarları sırayı bozmadan temizler (dict anahtarları sırayı korur)."""
    return list(dict.fromkeys(d for d in domains if d))


def scan_domain(domain):
    """Tek bir domain için TLS + header taramasını yapıp sonucu döndürür."""
    # 1) TLS kontrolü
    result = check_tls(domain)

    # 2) HTTP header kontrolü (TLS bağlantısı başarılıysa)
    #    Header hatası TLS raporunu gizlememesi için ayrı alanda tutulur.
    if not result["errors"]:
        header_data = check_headers(domain)
        result["headers"]         = header_data["headers"]
        result["header_warnings"] = header_data["warnings"]
        result["final_url"]       = header_data["final_url"]
        result["http_status"]     = header_data["http_status"]
        result["header_error"]    = header_data["error"]

    # 3) Zaman damgası
    result["scan_time"] = datetime.now(timezone.utc).isoformat()
    return result


def scan_domains(domains, workers=5):
    """
    Domainleri paralel tarar; sonuçları VERİLEN SIRAYLA döndürür.

    ThreadPoolExecutor → ağ beklemesi (I/O) yoğun işlerde birden fazla
    bağlantıyı aynı anda açmamızı sağlar. executor.map sonuçları giriş
    sırasıyla verdiği için rapor her çalıştırmada aynı düzende çıkar.
    """
    workers = max(1, min(workers, len(domains)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(scan_domain, domains))


def domain_status(result):
    """Özet tablo için tek kelimelik durum: HATA / UYARI / İYİ."""
    if result["errors"]:
        return "HATA"
    days = result.get("cert_days_left")
    if (result.get("header_error") or result.get("header_warnings")
            or (days is not None and days <= 30)):
        return "UYARI"
    return "İYİ"


def build_summary(results):
    """Çoklu tarama için sayısal özet (JSON raporuna da yazılır)."""
    statuses = [domain_status(r) for r in results]
    return {
        "total": len(results),
        "ok": statuses.count("İYİ"),
        "warning": statuses.count("UYARI"),
        "error": statuses.count("HATA"),
    }


def print_summary(results):
    """Birden fazla domain tarandığında karşılaştırmalı özet tablo."""
    status_colors = {"İYİ": Colors.GREEN, "UYARI": Colors.YELLOW, "HATA": Colors.RED}
    width = max(len("Domain"), *(len(r["domain"]) for r in results))

    print(colored("=" * 60, Colors.CYAN))
    print(colored(f"  Özet — {len(results)} domain", Colors.BOLD))
    print(colored("=" * 60, Colors.CYAN))
    print(f"  {'Domain':<{width}}  {'TLS':<8} {'Gün':>5}  {'Eksik':>5}  Durum")
    for r in results:
        status = domain_status(r)
        tls = (r.get("tls_version") or "-").replace("TLSv", "")
        days = r.get("cert_days_left")
        days_txt = str(days) if days is not None else "-"
        missing = len(r.get("header_warnings") or []) if not r["errors"] else "-"
        print(f"  {r['domain']:<{width}}  {tls:<8} {days_txt:>5}  {missing!s:>5}  "
              f"{colored(status, status_colors[status])}")

    summary = build_summary(results)
    print(f"\n  {colored(str(summary['ok']) + ' iyi', Colors.GREEN)}, "
          f"{colored(str(summary['warning']) + ' uyarı', Colors.YELLOW)}, "
          f"{colored(str(summary['error']) + ' hata', Colors.RED)}")
    print()


def build_report(results):
    """
    JSON'a yazılacak rapor.
    Tek domain → v0.2 ile birebir aynı biçim (geriye dönük uyumluluk).
    Çoklu domain → özet + sonuç listesi.
    """
    if len(results) == 1:
        return results[0]
    return {
        "tool_version": __version__,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "summary": build_summary(results),
        "results": results,
    }


# ── Ana Program ──────────────────────────────────────────────────
def parse_args(argv=None):
    # argparse → komut satırı argümanlarını yöneten standart kütüphane modülü.
    parser = argparse.ArgumentParser(
        description=f"TLS Audit Tool v{__version__} — Çoklu domain TLS/HTTPS güvenlik denetimi"
    )
    parser.add_argument(
        "--domain", "-d",
        nargs="+",
        default=[],
        metavar="DOMAIN",
        help="Taranacak domain(ler) (ör: -d example.com github.com)"
    )
    parser.add_argument(
        "--file", "-f",
        type=str,
        default=None,
        help="Her satırda bir domain olan dosya (# ile yorum yazılabilir)"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=5,
        help="Aynı anda taranacak domain sayısı (varsayılan: 5)"
    )
    parser.add_argument(
        "--json", "-j",
        type=str,
        default=None,
        help="Sonuçları JSON dosyasına kaydet (ör: rapor.json)"
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args(argv)
    if not args.domain and not args.file:
        parser.error("en az bir --domain veya --file vermelisin")
    if args.workers < 1:
        parser.error("--workers en az 1 olmalı")
    return args


def main(argv=None):
    args = parse_args(argv)

    domains = [normalize_domain(d) for d in args.domain]
    if args.file:
        try:
            domains += load_domains_from_file(args.file)
        except OSError as e:
            print(colored(f"  ✗ Domain dosyası okunamadı: {e}", Colors.RED))
            return 1
    domains = unique_domains(domains)
    if not domains:
        print(colored("  ✗ Taranacak geçerli domain bulunamadı", Colors.RED))
        return 1

    print(colored(f"\n  ⏳ {len(domains)} domain taranıyor: {', '.join(domains)}\n", Colors.CYAN))

    results = scan_domains(domains, workers=args.workers)

    for result in results:
        print_report(result)
    if len(results) > 1:
        print_summary(results)

    if args.json:
        save_json(build_report(results), args.json)

    return 1 if any(r["errors"] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
