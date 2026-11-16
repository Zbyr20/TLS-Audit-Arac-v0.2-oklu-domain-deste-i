"""tls_audit.py için ağ bağlantısı gerektirmeyen birim testleri.

Çalıştırma:  python -m pytest -q
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tls_audit  # noqa: E402


# ── normalize_domain ─────────────────────────────────────────────
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("https://example.com/", "example.com"),
        ("HTTP://example.com/login?x=1", "example.com"),
        ("", None),
        ("   ", None),
        ("# yorum satırı", None),
    ],
)
def test_normalize_domain(raw, expected):
    assert tls_audit.normalize_domain(raw) == expected


def test_unique_domains_keeps_first_order():
    assert tls_audit.unique_domains(["b.com", "a.com", "b.com", None, "c.com"]) == [
        "b.com",
        "a.com",
        "c.com",
    ]


def test_load_domains_from_file_skips_comments_and_blanks(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text(
        "# hedefler\n\nexample.com\nhttps://github.com/  # kod\n   \nGOOGLE.com\n",
        encoding="utf-8",
    )
    assert tls_audit.load_domains_from_file(f) == ["example.com", "github.com", "google.com"]


# ── Durum / özet ─────────────────────────────────────────────────
def make_result(domain, *, errors=(), warnings=(), days=200, header_error=None):
    return {
        "domain": domain,
        "tls_version": "TLSv1.3",
        "cert_days_left": days,
        "errors": list(errors),
        "header_warnings": list(warnings),
        "header_error": header_error,
    }


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, "İYİ"),
        ({"warnings": ["Content-Security-Policy"]}, "UYARI"),
        ({"days": 10}, "UYARI"),
        ({"header_error": "zaman aşımı"}, "UYARI"),
        ({"errors": ["DNS çözümlenemedi"]}, "HATA"),
    ],
)
def test_domain_status(kwargs, expected):
    assert tls_audit.domain_status(make_result("x.com", **kwargs)) == expected


def test_build_report_single_domain_keeps_v02_shape():
    r = make_result("a.com")
    assert tls_audit.build_report([r]) is r


def test_build_report_multi_domain_has_summary():
    results = [
        make_result("a.com"),
        make_result("b.com", warnings=["X-Frame-Options"]),
        make_result("c.com", errors=["bağlantı reddedildi"]),
    ]
    report = tls_audit.build_report(results)
    assert report["tool_version"] == tls_audit.__version__
    assert report["summary"] == {"total": 3, "ok": 1, "warning": 1, "error": 1}
    assert [r["domain"] for r in report["results"]] == ["a.com", "b.com", "c.com"]


# ── Argümanlar ve main() (ağ çağrıları sahte) ────────────────────
def test_parse_args_requires_a_source():
    with pytest.raises(SystemExit):
        tls_audit.parse_args([])


def test_parse_args_rejects_zero_workers():
    with pytest.raises(SystemExit):
        tls_audit.parse_args(["-d", "a.com", "-w", "0"])


@pytest.fixture
def fake_network(monkeypatch):
    """check_tls / check_headers yerine ağsız sahte fonksiyonlar."""
    calls = []

    def fake_check_tls(domain, port=443):
        calls.append(domain)
        result = make_result(domain)
        result.update({"port": port, "cipher_suite": "TLS_AES_256_GCM_SHA384",
                       "cipher_bits": 256, "certificate": {}, "headers": {},
                       "final_url": None, "http_status": None})
        if domain.startswith("bad"):
            result["errors"] = [f"{domain} DNS çözümlenemedi"]
        return result

    def fake_check_headers(domain, port=443):
        return {"headers": {}, "warnings": [], "final_url": f"https://{domain}/",
                "http_status": 200, "error": None}

    monkeypatch.setattr(tls_audit, "check_tls", fake_check_tls)
    monkeypatch.setattr(tls_audit, "check_headers", fake_check_headers)
    return calls


def test_main_scans_domains_and_file_in_order_without_duplicates(tmp_path, fake_network, capsys):
    f = tmp_path / "list.txt"
    f.write_text("b.com\na.com\n", encoding="utf-8")
    out = tmp_path / "rapor.json"

    code = tls_audit.main(["-d", "https://a.com/", "c.com", "-f", str(f), "-j", str(out)])

    assert code == 0
    assert sorted(fake_network) == ["a.com", "b.com", "c.com"]
    report = json.loads(out.read_text(encoding="utf-8"))
    assert [r["domain"] for r in report["results"]] == ["a.com", "c.com", "b.com"]
    assert report["summary"]["ok"] == 3
    assert "Özet — 3 domain" in capsys.readouterr().out


def test_main_returns_1_when_a_domain_fails(fake_network):
    assert tls_audit.main(["-d", "good.com", "bad.com"]) == 1


def test_main_single_domain_json_matches_v02_shape(tmp_path, fake_network):
    out = tmp_path / "tek.json"
    assert tls_audit.main(["-d", "a.com", "-j", str(out)]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["domain"] == "a.com"
    assert "results" not in report


def test_main_reports_missing_file(tmp_path, capsys):
    assert tls_audit.main(["-f", str(tmp_path / "yok.txt")]) == 1
    assert "okunamadı" in capsys.readouterr().out
