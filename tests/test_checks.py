from __future__ import annotations

from conftest import HARDENED
from websec.checks import CHECKS
from websec.checks.cookies import parse_set_cookie
from websec.checks.headers import csp_weaknesses, parse_csp
from websec.scanner import ScanOptions, scan


def rule_ids(site_url, groups, **kw):
    result = scan(site_url, {g: CHECKS[g] for g in groups}, ScanOptions(**kw))
    return {f.rule.id for f in result.findings}, result


def test_bare_page_flags_missing_headers(site):
    site.routes["*"] = (200, [], "<html></html>")
    ids, _ = rule_ids(site.url, ["headers"])
    assert {"WSS001", "WSS005", "WSS006", "WSS007", "WSS008"} <= ids
    assert "WSS003" not in ids  # HSTS is meaningless over plain HTTP


def test_hardened_page_is_clean(site):
    site.routes["*"] = (200, HARDENED, "<html></html>")
    ids, _ = rule_ids(site.url, ["headers"])
    assert ids == set()


def test_version_disclosure(site):
    site.routes["*"] = (200, HARDENED + [("Server", "nginx/1.18.0"), ("X-Powered-By", "Express")],
                        "")
    ids, result = rule_ids(site.url, ["headers"])
    assert ids == {"WSS009"}
    assert "nginx/1.18.0" in result.findings[0].evidence


def test_server_without_version_not_flagged(site):
    site.routes["*"] = (200, HARDENED + [("Server", "nginx")], "")
    assert rule_ids(site.url, ["headers"])[0] == set()


def test_csp_weakness_detection():
    assert csp_weaknesses(parse_csp("script-src 'self' 'unsafe-inline'")) == [
        "'unsafe-inline' in script sources"]
    assert csp_weaknesses(parse_csp("script-src 'nonce-abc' 'unsafe-inline'")) == []
    assert csp_weaknesses(parse_csp("default-src *")) == ["'*' allowed as a script source"]
    assert csp_weaknesses(parse_csp("img-src 'self'")) != []
    assert csp_weaknesses(parse_csp("default-src 'self'")) == []


def test_weak_csp_reported(site):
    site.routes["*"] = (200, [h for h in HARDENED if h[0] != "Content-Security-Policy"] + [
        ("Content-Security-Policy", "script-src 'unsafe-eval'; frame-ancestors 'none'")], "")
    assert rule_ids(site.url, ["headers"])[0] == {"WSS002"}


def test_cookie_parsing():
    c = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert (c.name, c.secure, c.httponly, c.samesite) == ("sid", True, True, "lax")
    assert parse_set_cookie("garbage") is None


def test_cookie_flags_over_http(site):
    site.routes["*"] = (200, [("Set-Cookie", "sid=1; Path=/"),
                              ("Set-Cookie", "ok=1; HttpOnly; SameSite=Strict")], "")
    ids, result = rule_ids(site.url, ["cookies"])
    # Secure is not demanded on HTTP (browsers ignore it there).
    assert ids == {"WSS021", "WSS022"}
    assert {f.key for f in result.findings} == {"sid"}


def test_cookies_on_redirect_hop_are_seen(site):
    site.routes["/"] = (302, [("Location", "/home"), ("Set-Cookie", "hop=1")], "")
    site.routes["/home"] = (200, [], "")
    ids, _ = rule_ids(site.url + "/", ["cookies"])
    assert "WSS021" in ids


def test_cors_wildcard(site):
    site.routes["*"] = (200, [("Access-Control-Allow-Origin", "*")], "")
    assert rule_ids(site.url, ["cors"])[0] == {"WSS010"}


def test_cors_reflection_with_credentials_is_high(site):
    site.routes["*"] = (200, [], "")
    site.reflect_origin = True
    ids, result = rule_ids(site.url, ["cors"])
    assert ids == {"WSS011"}
    assert result.findings[0].severity.label == "high"


def test_exposure_validates_content_not_status(site):
    # SPA-style catch-all: 200 + HTML for everything must NOT produce findings.
    site.routes["*"] = (200, [], "<html><body>app</body></html>")
    # Only WSS052: the HTML catch-all must not be mistaken for a real security.txt.
    assert rule_ids(site.url, ["exposure"])[0] == {"WSS052"}


def test_exposure_detects_real_leaks(site):
    site.routes["/.git/HEAD"] = (200, [], "ref: refs/heads/main\n")
    site.routes["/.env"] = (200, [], "DB_PASSWORD=hunter2\nAPI_KEY=abc\n")
    site.routes["/ftp/"] = (200, [], "<html><head><title>listing directory /ftp</title>")
    site.routes["*"] = (200, [], "<html>app</html>")
    ids, result = rule_ids(site.url, ["exposure"])
    assert ids == {"WSS040", "WSS041", "WSS042", "WSS052"}
    assert all("hunter2" not in f.evidence for f in result.findings)  # never echo secrets


def test_ignore_suppresses_rule(site):
    site.routes["*"] = (200, [], "")
    ids, _ = rule_ids(site.url, ["headers"], ignore=frozenset({"WSS001"}))
    assert "WSS001" not in ids and "WSS005" in ids


def test_plain_http_loopback_is_low_not_high(site):
    site.routes["*"] = (200, HARDENED, "")
    # An explicit non-443 port has no discoverable HTTPS endpoint; loopback => WSS038.
    ids, result = rule_ids(site.url, ["tls"])
    assert ids == {"WSS038"}
    assert result.findings[0].severity.label == "low"


def test_plain_http_non_loopback_is_high(site, monkeypatch):
    site.routes["*"] = (200, HARDENED, "")
    monkeypatch.setattr("websec.checks.tls.is_loopback", lambda host: False)
    assert rule_ids(site.url, ["tls"])[0] == {"WSS030"}
