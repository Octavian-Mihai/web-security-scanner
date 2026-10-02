from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from fnmatch import fnmatch
from functools import cached_property
from typing import Any
from urllib.parse import urldefrag, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import requests
import urllib3

from . import __version__
from .htmlinfo import PageInfo, parse_html
from .models import Finding

USER_AGENT = f"websec-scanner/{__version__} (+passive security scan)"
MAX_REDIRECTS = 10
_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".js", ".map", ".json",
    ".pdf", ".zip", ".gz", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".xml", ".txt",
)


class ScanError(Exception):
    """The target could not be scanned at all (unreachable, out of scope, invalid URL)."""


@dataclass(frozen=True)
class ScanOptions:
    timeout: float = 10.0
    verify: bool = True
    ignore: frozenset[str] = frozenset()
    crawl_depth: int = 0
    max_pages: int = 20
    workers: int = 4
    delay: float = 0.0  # minimum seconds between any two requests (global)
    allow_hosts: tuple[str, ...] = ()
    respect_robots: bool = True


class Scope:
    """Hosts the scanner may contact. Anything else is refused *before* a request is made."""

    def __init__(self, patterns: Iterable[str]) -> None:
        self.patterns = [p.lower() for p in patterns]

    @classmethod
    def for_urls(cls, urls: Iterable[str], extra: Iterable[str] = ()) -> Scope:
        hosts = [urlsplit(u).hostname or "" for u in urls]
        return cls([h for h in hosts if h] + list(extra))

    def allows(self, host: str) -> bool:
        return any(fnmatch(host.lower(), p) for p in self.patterns)


class RateLimiter:
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.delay
        if start > now:
            time.sleep(start - now)


class ThrottledSession(requests.Session):
    def __init__(self, limiter: RateLimiter) -> None:
        super().__init__()
        self._limiter = limiter

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        self._limiter.wait()
        return super().request(*args, **kwargs)


@dataclass
class ScanContext:
    url: str
    session: requests.Session
    options: ScanOptions
    response: requests.Response  # final response after redirects
    chain: list[requests.Response]  # every hop, in order
    tls_verify_failed: bool = False

    @property
    def timeout(self) -> float:
        return self.options.timeout

    @property
    def verify(self) -> bool:
        return self.options.verify and not self.tls_verify_failed

    @property
    def origin(self) -> str:
        p = urlsplit(self.response.url)
        return f"{p.scheme}://{p.netloc}"

    @property
    def is_https(self) -> bool:
        return urlsplit(self.response.url).scheme == "https"

    @property
    def headers(self) -> Any:
        return self.response.headers

    @cached_property
    def page(self) -> PageInfo:
        """Parsed HTML of the final response (empty for non-HTML content)."""
        if "html" not in self.response.headers.get("Content-Type", "").lower():
            return PageInfo()
        return parse_html(self.response.text)


Check = Callable[[ScanContext], Iterable[Finding]]


@dataclass(frozen=True)
class CheckSpec:
    fn: Check
    per_page: bool  # True: run on every crawled page; False: once per origin


@dataclass
class ScanResult:
    url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    pages_scanned: int = 0


def _fetch_chain(
    url: str, session: requests.Session, timeout: float, verify: bool, scope: Scope
) -> list[requests.Response]:
    """Follow redirects by hand so an out-of-scope hop is never requested."""
    chain: list[requests.Response] = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        host = urlsplit(current).hostname or ""
        if not scope.allows(host):
            raise ScanError(
                f"{current} is outside the scan scope (host '{host}'); "
                "add it with --allow-host if scanning it is intended")
        resp = session.get(current, timeout=timeout, verify=verify, allow_redirects=False)
        chain.append(resp)
        location = resp.headers.get("Location")
        if resp.is_redirect and location:
            current = urljoin(current, location)
            continue
        return chain
    raise ScanError(f"too many redirects starting from {url}")


def build_context(
    url: str, options: ScanOptions, scope: Scope, limiter: RateLimiter
) -> ScanContext:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ScanError(f"invalid URL {url!r}: expected http:// or https:// with a host")

    session = ThrottledSession(limiter)
    session.headers["User-Agent"] = USER_AGENT
    tls_verify_failed = False
    try:
        try:
            chain = _fetch_chain(url, session, options.timeout, options.verify, scope)
        except requests.exceptions.SSLError:
            # Still scan the page so header/cookie findings aren't lost; the TLS
            # check reports the certificate problem itself.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            tls_verify_failed = True
            chain = _fetch_chain(url, session, options.timeout, False, scope)
    except requests.RequestException as exc:
        raise ScanError(f"could not fetch {url}: {exc}") from exc

    return ScanContext(url=url, session=session, options=options, response=chain[-1],
                       chain=chain, tls_verify_failed=tls_verify_failed)


def _run_checks(
    ctx: ScanContext, checks: dict[str, CheckSpec], per_page_only: bool
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for name, spec in checks.items():
        if per_page_only and not spec.per_page:
            continue
        try:
            findings += list(spec.fn(ctx))
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            errors.append(f"check '{name}' failed: {type(exc).__name__}: {exc}")
    return findings, errors


def _normalize(url: str) -> str:
    return urldefrag(url)[0]


def _crawlable(url: str, origin: str) -> bool:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or f"{p.scheme}://{p.netloc}" != origin:
        return False
    return not p.path.lower().endswith(_ASSET_EXTENSIONS)


def _load_robots(ctx: ScanContext) -> RobotFileParser | None:
    try:
        resp = ctx.session.get(ctx.origin + "/robots.txt", timeout=ctx.timeout,
                               verify=ctx.verify, allow_redirects=False)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    parser = RobotFileParser()
    parser.parse(resp.text.splitlines())
    return parser


def collapse(findings: list[Finding]) -> list[Finding]:
    """Merge identical findings repeated across crawled pages into one."""
    merged: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        key = (f.rule.id, f.key, f.message)
        first = merged.get(key)
        if first is None:
            merged[key] = f
        else:
            first.extra.setdefault("also_on", []).append(f.url)
    for f in merged.values():
        extra = f.extra.get("also_on", [])
        if extra:
            f.message += f" (also on {len(extra)} other page{'s' if len(extra) != 1 else ''})"
    return list(merged.values())


def scan(
    url: str,
    checks: dict[str, CheckSpec],
    options: ScanOptions | None = None,
    scope: Scope | None = None,
    limiter: RateLimiter | None = None,
) -> ScanResult:
    options = options or ScanOptions()
    scope = scope or Scope.for_urls([url], options.allow_hosts)
    limiter = limiter or RateLimiter(options.delay)

    root = build_context(url, options, scope, limiter)
    result = ScanResult(url=url, pages_scanned=1)
    raw, errors = _run_checks(root, checks, per_page_only=False)
    result.errors += errors

    if options.crawl_depth > 0:
        raw += _crawl(root, checks, options, scope, limiter, result)

    seen: set[str] = set()
    for f in collapse(raw):
        if f.rule.id in options.ignore or f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        result.findings.append(f)
    return result


def _crawl(
    root: ScanContext,
    checks: dict[str, CheckSpec],
    options: ScanOptions,
    scope: Scope,
    limiter: RateLimiter,
    result: ScanResult,
) -> list[Finding]:
    robots = _load_robots(root) if options.respect_robots else None
    visited = {_normalize(root.url), _normalize(root.response.url)}
    frontier = [root]
    collected: list[Finding] = []

    def visit(target: str) -> tuple[ScanContext | None, list[Finding], list[str]]:
        try:
            ctx = build_context(target, options, scope, limiter)
        except ScanError as exc:
            return None, [], [f"skipped {target}: {exc}"]
        if ctx.response.status_code >= 400 or "html" not in ctx.headers.get(
                "Content-Type", "").lower():
            return None, [], []
        found, errs = _run_checks(ctx, checks, per_page_only=True)
        return ctx, found, errs

    for _ in range(options.crawl_depth):
        budget = options.max_pages - result.pages_scanned
        candidates: list[str] = []
        for ctx in frontier:
            for href in ctx.page.links:
                target = _normalize(urljoin(ctx.response.url, href))
                if len(candidates) >= budget:
                    break
                if target in visited or not _crawlable(target, root.origin):
                    continue
                if not scope.allows(urlsplit(target).hostname or ""):
                    continue
                if robots is not None and not robots.can_fetch(USER_AGENT, target):
                    continue
                visited.add(target)
                candidates.append(target)
        if not candidates:
            break
        with ThreadPoolExecutor(max_workers=max(1, options.workers)) as pool:
            outcomes = list(pool.map(visit, candidates))
        frontier = []
        for page_ctx, found, errs in outcomes:
            result.warnings += [e for e in errs if e.startswith("skipped")]
            result.errors += [e for e in errs if not e.startswith("skipped")]
            if page_ctx is not None:
                result.pages_scanned += 1
                collected += found
                frontier.append(page_ctx)
    return collected
