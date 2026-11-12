# Değişiklik Günlüğü

## v0.3 — Çoklu domain desteği

```bash
# Tek domain (v0.2 ile aynı)
python3 tls_audit.py -d example.com

# Birden fazla domain — paralel taranır, sonda özet tablo çıkar
python3 tls_audit.py -d example.com github.com google.com

# Dosyadan oku (her satıra bir domain, # ile yorum) + JSON rapor
python3 tls_audit.py -f domains.example.txt -w 10 -j rapor.json
```

| Seçenek | Açıklama |
|---------|----------|
| `-d, --domain` | Bir veya daha fazla domain (`https://` ve yol kısmı otomatik temizlenir) |
| `-f, --file` | Domain listesi dosyası; boş satırlar ve `#` yorumları atlanır |
| `-w, --workers` | Aynı anda taranacak domain sayısı (varsayılan 5) |
| `-j, --json` | JSON rapor. Tek domainde v0.2 biçimi; çoklu taramada `summary` + `results` listesi |
| `-V, --version` | Sürümü gösterir |

Özet tablodaki durumlar: **İYİ** (sorun yok), **UYARI** (kritik başlık eksik, header taraması başarısız ya da sertifikanın bitmesine ≤30 gün), **HATA** (TLS bağlantısı kurulamadı). Herhangi bir domain HATA verirse program `1` çıkış koduyla biter; böylece CI veya cron içinde kullanılabilir.

Testler ağ bağlantısı gerektirmez: `pip install pytest && python -m pytest -q`.

## v0.2
- HTTP güvenlik başlıkları `requests` ile taranıyor; eksik kritik başlıklar "uyarı" olarak işaretleniyor.

## v0.1
- Tek domain için TLS versiyonu, cipher suite, sertifika ve başlık kontrolü.
