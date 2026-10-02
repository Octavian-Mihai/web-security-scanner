"""One vulnerable fixture (and, where meaningful, one clean fixture) per rule.

Every rule in the catalog must be exercised here or elsewhere in the suite; the
meta-test at the bottom fails if a new rule is added without a test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from conftest import HARDENED, Site
from websec.checks import CHECKS
from websec.rules import RULES
from websec.scanner import ScanOptions, scan

GOOD_COOKIE = "sid=1; Secure; HttpOnly; SameSite=Lax; Path=/"
HSTS = ("Strict-Transport-Security", "max-age=31536000; includeSubDomains")


def without(*names: str):
    return [h for h in HARDENED if h[0] not in names]


def found(site: Site, groups: list[str]) -> set[str]:
    result = scan(site.url, {g: CHECKS[g] for g in groups}, ScanOptions())
    assert not result.errors, result.errors
    return {f.rule.id for f in result.findings}


def page(body: str = "<html></html>", headers=None):
    return (200, headers if headers is not None else HARDENED, body)


# (rule, groups, https?, vulnerable route, clean route)
HTTP_CASES = [
    ("WSS001", ["headers"], page(headers=[]), page()),
    ("WSS002", ["headers"],
     page(headers=without("Content-Security-Policy")
          + [("Content-Security-Policy", "script-src 'unsafe-inline'; frame-ancestors 'self'")]),
     page()),
    ("WSS005", ["headers"], page(headers=without("Content-Security-Policy")), page()),
    ("WSS006", ["headers"], page(headers=without("X-Content-Type-Options")), page()),
    ("WSS007", ["headers"], page(headers=without("Referrer-Policy")), page()),
    ("WSS008", ["headers"], page(headers=without("Permissions-Policy")), page()),
    ("WSS009", ["headers"], page(headers=HARDENED + [("Server", "nginx/1.18.0")]), page()),
    ("WSS010", ["cors"], page(headers=[("Access-Control-Allow-Origin", "*")]), page()),
    ("WSS021", ["cookies"], page(headers=[("Set-Cookie", "sid=1; Secure; SameSite=Lax")]),
     page(headers=[("Set-Cookie", GOOD_COOKIE)])),
    ("WSS022", ["cookies"], page(headers=[("Set-Cookie", "sid=1; Secure; HttpOnly")]),
     page(headers=[("Set-Cookie", GOOD_COOKIE)])),
    ("WSS023", ["cookies"],
     page(headers=[("Set-Cookie", "__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Domain=x.com")]),
     page(headers=[("Set-Cookie", "__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/")])),
    ("WSS050", ["content"],
     page('<script src="https://cdn.example.net/lib.js"></script>'),
     page('<script src="https://cdn.example.net/lib.js" integrity="sha384-abc" '
          'crossorigin="anonymous"></script><script src="/local.js"></script>')),
    ("WSS053", ["content"],
     page('<a href="/cb?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig_nature">x</a>'),
     page('<a href="/cb?page=2">x</a>')),
    ("WSS040", ["exposure"], None, None),
    ("WSS041", ["exposure"], None, None),
    ("WSS042", ["exposure"], None, None),
    ("WSS044", ["exposure"], None, None),
    ("WSS052", ["exposure"], None, None),
    ("WSS043", ["exposure"], None, None),
]

EXPOSURE_VULN = {
    "WSS040": {"/.git/HEAD": page("ref: refs/heads/main\n")},
    "WSS041": {"/.env": page("DB_PASSWORD=hunter2\n")},
    "WSS042": {"/backup/": page("<html><title>Index of /backup</title></html>")},
    "WSS044": {"/metrics": page("# HELP up gauge\n# TYPE up gauge\nup 1\n"),
               "/actuator/env": page('{"propertySources": []}', [("Content-Type",
                                                                    "application/json")])},
    "WSS052": {},
    "WSS043": {
        "/": page('<script src="/app.js"></script>'),
        "/app.js": page("var a=1;\n//# sourceMappingURL=app.js.map", []),
        "/app.js.map": page('{"version":3,"sources":["a.ts"],"mappings":"AAAA"}', []),
    },
}
SECURITY_TXT = {"/.well-known/security.txt": page("Contact: mailto:sec@example.com\n", [])}


@pytest.mark.parametrize("rule,groups,vuln,clean", HTTP_CASES, ids=[c[0] for c in HTTP_CASES])
def test_rule_fires_and_clean_twin_does_not(make_site, rule, groups, vuln, clean):
    vulnerable = make_site()
    if rule in EXPOSURE_VULN:
        vulnerable.routes.update({"*": page("<html>app</html>"), **EXPOSURE_VULN[rule]})
        if rule != "WSS052":
            vulnerable.routes.update(SECURITY_TXT)  # keep the fixture otherwise clean
        assert rule in found(vulnerable, groups)
        if rule == "WSS052":  # twin: add the file
            vulnerable.routes.update(SECURITY_TXT)
            assert rule not in found(vulnerable, groups)
        return
    vulnerable.routes["*"] = vuln
    assert rule in found(vulnerable, groups)
    twin = make_site()
    twin.routes["*"] = clean
    assert rule not in found(twin, groups)


def test_wss011_cors_reflection_with_credentials(make_site):
    s = make_site()
    s.routes["*"] = page()
    assert "WSS011" not in found(s, ["cors"])
    s.reflect_origin = True
    assert "WSS011" in found(s, ["cors"])


# ---- rules that need HTTPS ------------------------------------------------

def test_wss003_wss004_hsts(https_site):
    https_site.routes["*"] = page()
    assert "WSS003" in found(https_site, ["headers"])
    https_site.routes["*"] = page(headers=HARDENED + [("Strict-Transport-Security", "max-age=60")])
    ids = found(https_site, ["headers"])
    assert "WSS004" in ids and "WSS003" not in ids
    https_site.routes["*"] = page(headers=HARDENED + [HSTS])
    assert not {"WSS003", "WSS004"} & found(https_site, ["headers"])


def test_wss020_secure_flag_only_on_https(https_site, site):
    https_site.routes["*"] = page(headers=[("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax")])
    assert "WSS020" in found(https_site, ["cookies"])
    site.routes["*"] = page(headers=[("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax")])
    assert "WSS020" not in found(site, ["cookies"])  # browsers ignore Secure on HTTP


def test_wss051_mixed_content(https_site, site):
    body = '<img src="http://insecure.example.net/a.png"><img src="https://ok.example.net/b.png">'
    https_site.routes["*"] = page(body)
    result = scan(https_site.url, {"content": CHECKS["content"]}, ScanOptions())
    hits = [f for f in result.findings if f.rule.id == "WSS051"]
    assert [f.key for f in hits] == ["http://insecure.example.net/a.png"]
    site.routes["*"] = page(body)  # plain-HTTP page: mixed content is not applicable
    assert "WSS051" not in found(site, ["content"])


# ---- TLS rules, against real servers with deliberately flawed certificates -

@pytest.mark.parametrize("rule,cert_kwargs", [
    ("WSS033", {"started_days_ago": 60, "days_valid": 30}),
    ("WSS034", {"started_days_ago": 1, "days_valid": 6}),
    ("WSS036", {"key_bits": 1024}),
])
def test_certificate_rules(make_site, tmp_path, rule, cert_kwargs):
    from conftest import make_cert

    s = make_site(make_cert(tmp_path, **cert_kwargs))
    s.routes["*"] = page()
    assert rule in found(s, ["tls"])


def test_wss037_weak_signature_algorithm(https_site, monkeypatch):
    from websec.checks import tls

    real = tls.inspect_certificate

    def fake(host, port, timeout):
        info = real(host, port, timeout)
        info.signature_hash = "sha1"  # cryptography >= 50 refuses to *create* SHA-1 certs
        return info

    monkeypatch.setattr(tls, "inspect_certificate", fake)
    assert "WSS037" in found(https_site, ["tls"])


def test_describe_certificate_reads_sha1_cert_made_by_openssl(tmp_path):
    import shutil
    import subprocess

    from websec.checks.tls import describe_certificate

    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI needed")
    cert = tmp_path / "c.pem"
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha1", "-days", "5",
         "-keyout", str(tmp_path / "k.pem"), "-out", str(cert), "-subj", "/CN=localhost"],
        capture_output=True, check=False)
    if proc.returncode != 0:
        pytest.skip("this openssl refuses to create SHA-1 certificates")
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    der = x509.load_pem_x509_certificate(cert.read_bytes()).public_bytes(Encoding.DER)
    info = describe_certificate(der)
    assert info.signature_hash == "sha1" and info.key_bits == 2048 and 4 < info.days_left < 6


def test_healthy_cert_has_no_cert_quality_findings(https_site):
    ids = found(https_site, ["tls"])
    assert not {"WSS033", "WSS034", "WSS036", "WSS037", "WSS032"} & ids
    assert "WSS035" in ids  # but it is self-signed, so untrusted


def test_wss032_legacy_protocol(https_site, monkeypatch):
    monkeypatch.setattr("websec.checks.tls.accepts_protocol", lambda *a, **k: True)
    assert "WSS032" in found(https_site, ["tls"])


def test_wss031_http_does_not_redirect(site, https_site, monkeypatch):
    site.routes["*"] = page()
    monkeypatch.setattr("websec.checks.tls._tls_endpoint",
                        lambda ctx: ("127.0.0.1", https_site.port))
    assert "WSS031" in found(site, ["tls"])


def test_wss030_vs_wss038(site, monkeypatch):
    site.routes["*"] = page()
    assert found(site, ["tls"]) == {"WSS038"}
    monkeypatch.setattr("websec.checks.tls.is_loopback", lambda h: False)
    assert found(site, ["tls"]) == {"WSS030"}


# ---- meta -----------------------------------------------------------------

def test_every_rule_has_a_test():
    tests_dir = Path(__file__).parent
    source = "\n".join(p.read_text() for p in tests_dir.glob("test_*.py")
                       if p.name != "test_rules_golden_meta.py")
    untested = [rid for rid in RULES if not re.search(rf"\b{rid}\b", source)]
    assert not untested, f"rules without any test: {untested}"


def test_catalog_integrity():
    ids = list(RULES)
    assert len(ids) == len(set(ids))
    for rule in RULES.values():
        assert rule.cwe > 0 and rule.owasp[:1] == "A" and rule.remediation
        assert json.dumps(rule.cwe_uri)
