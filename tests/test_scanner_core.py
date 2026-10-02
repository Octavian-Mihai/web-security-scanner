from __future__ import annotations

import time

import pytest

from conftest import HARDENED
from websec.checks import CHECKS
from websec.scanner import RateLimiter, ScanError, ScanOptions, Scope, scan

HEADERS_ONLY = {"headers": CHECKS["headers"], "cookies": CHECKS["cookies"]}


def html(*links: str) -> tuple[int, list[tuple[str, str]], str]:
    return 200, [], "<html>" + "".join(f'<a href="{href}">x</a>' for href in links) + "</html>"


# ---- crawler -----------------------------------------------------------------

def test_crawl_follows_same_origin_links_to_depth(site):
    site.routes.update({"/": html("/a", "/b"), "/a": html("/c"), "/b": html(), "/c": html()})
    one = scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=1))
    two = scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=2))
    assert one.pages_scanned == 3  # /, /a, /b
    assert two.pages_scanned == 4  # + /c


def test_crawl_respects_max_pages(site):
    site.routes["/"] = html(*[f"/p{i}" for i in range(10)])
    site.routes["*"] = html()
    result = scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=1, max_pages=4))
    assert result.pages_scanned == 4


def test_crawl_skips_assets_fragments_and_foreign_hosts(site):
    site.routes["/"] = html("/logo.png", "/#top", "http://other.invalid/x", "/real")
    site.routes["/real"] = html()
    scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=1))
    assert "/logo.png" not in site.hits
    assert site.hits.count("/") >= 1 and "/real" in site.hits


def test_crawl_honours_robots_txt(site):
    site.routes["/robots.txt"] = (200, [], "User-agent: *\nDisallow: /private\n")
    site.routes["/"] = html("/private", "/public")
    site.routes["*"] = html()
    scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=1))
    assert "/private" not in site.hits and "/public" in site.hits
    scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=1, respect_robots=False))
    assert "/private" in site.hits


def test_crawl_collapses_site_wide_findings(site):
    site.routes["/"] = html("/a", "/b")
    site.routes["*"] = html()
    result = scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=1))
    csp = [f for f in result.findings if f.rule.id == "WSS001"]
    assert len(csp) == 1  # one finding, not one per page
    assert "also on 2 other pages" in csp[0].message


def test_origin_level_checks_run_once_not_per_page(site):
    site.routes["/"] = html("/a", "/b")
    site.routes["*"] = html()
    scan(site.url + "/", {"exposure": CHECKS["exposure"], "headers": CHECKS["headers"]},
         ScanOptions(crawl_depth=1))
    assert site.hits.count("/.git/HEAD") == 1


def test_crawl_skips_error_and_non_html_pages(site):
    site.routes["/"] = html("/missing", "/data")
    site.routes["/data"] = (200, [("Content-Type", "application/json")], "{}")
    result = scan(site.url + "/", HEADERS_ONLY, ScanOptions(crawl_depth=1))
    assert result.pages_scanned == 1 and not result.errors


# ---- scope safety ---------------------------------------------------------------

def test_out_of_scope_redirect_is_refused_before_requesting(make_site):
    target, other = make_site(), make_site()
    target.routes["*"] = (302, [("Location", f"http://localhost:{other.port}/x")], "")
    other.routes["*"] = html()
    with pytest.raises(ScanError, match="outside the scan scope"):
        scan(target.url, HEADERS_ONLY)
    assert other.hits == []  # the out-of-scope host was never contacted


def test_allow_host_permits_redirect(make_site):
    target, other = make_site(), make_site()
    target.routes["*"] = (302, [("Location", f"http://localhost:{other.port}/x")], "")
    other.routes["*"] = (200, HARDENED, "<html></html>")
    result = scan(target.url, HEADERS_ONLY, ScanOptions(allow_hosts=("localhost",)),
                  Scope.for_urls([target.url], ["localhost"]))
    assert other.hits == ["/x"] and not result.errors


def test_scope_glob_matching():
    scope = Scope(["example.com", "*.example.org"])
    assert scope.allows("EXAMPLE.com") and scope.allows("a.example.org")
    assert not scope.allows("evil.com") and not scope.allows("example.com.evil.com")


def test_redirect_loop_is_an_error(site):
    site.routes["*"] = (302, [("Location", "/")], "")
    with pytest.raises(ScanError, match="too many redirects"):
        scan(site.url, HEADERS_ONLY)


def test_invalid_url():
    with pytest.raises(ScanError):
        scan("ftp://example.com", HEADERS_ONLY)


# ---- rate limiting -------------------------------------------------------------

def test_rate_limiter_spaces_requests():
    limiter = RateLimiter(0.05)
    start = time.monotonic()
    for _ in range(5):
        limiter.wait()
    assert time.monotonic() - start >= 0.18  # four enforced gaps


def test_rate_limiter_disabled_by_default():
    limiter = RateLimiter(0)
    start = time.monotonic()
    for _ in range(100):
        limiter.wait()
    assert time.monotonic() - start < 0.1


def test_delay_applies_to_scan_requests(site):
    site.routes["*"] = (200, HARDENED, "<html></html>")
    start = time.monotonic()
    scan(site.url, {"exposure": CHECKS["exposure"]}, ScanOptions(delay=0.02))
    assert time.monotonic() - start >= 0.02 * 8  # exposure makes well over 8 requests


def test_check_failure_is_isolated(site):
    from websec.scanner import CheckSpec

    def boom(ctx):
        raise RuntimeError("kaput")

    site.routes["*"] = (200, [], "")
    result = scan(site.url, {"boom": CheckSpec(boom, True), **HEADERS_ONLY})
    assert any("kaput" in e for e in result.errors)
    assert any(f.rule.id == "WSS001" for f in result.findings)  # other checks still ran
