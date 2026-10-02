from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests
import urllib3

from . import __version__
from .models import Finding

USER_AGENT = f"websec-scanner/{__version__} (+passive security scan)"


class ScanError(Exception):
    """The target could not be scanned at all (unreachable, invalid URL, ...)."""


@dataclass
class ScanContext:
    url: str
    session: requests.Session
    timeout: float
    verify: bool
    response: requests.Response  # final response after redirects
    chain: list[requests.Response]  # every response, redirects first
    tls_verify_failed: bool = False

    @property
    def parts(self):
        return urlsplit(self.response.url)

    @property
    def origin(self) -> str:
        p = self.parts
        return f"{p.scheme}://{p.netloc}"

    @property
    def is_https(self) -> bool:
        return self.parts.scheme == "https"

    @property
    def headers(self):
        return self.response.headers


Check = Callable[[ScanContext], Iterable[Finding]]


@dataclass
class ScanResult:
    url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _fetch(url: str, session: requests.Session, timeout: float, verify: bool):
    return session.get(url, timeout=timeout, verify=verify, allow_redirects=True)


def build_context(url: str, timeout: float = 10.0, verify: bool = True) -> ScanContext:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ScanError(f"invalid URL {url!r}: expected http:// or https:// with a host")

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    tls_verify_failed = False
    try:
        try:
            resp = _fetch(url, session, timeout, verify)
        except requests.exceptions.SSLError:
            # Still scan the page so header/cookie findings aren't lost; the TLS
            # check reports the certificate problem itself.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            tls_verify_failed = True
            resp = _fetch(url, session, timeout, False)
    except requests.RequestException as exc:
        raise ScanError(f"could not fetch {url}: {exc}") from exc

    return ScanContext(
        url=url,
        session=session,
        timeout=timeout,
        verify=verify and not tls_verify_failed,
        response=resp,
        chain=[*resp.history, resp],
        tls_verify_failed=tls_verify_failed,
    )


def scan(
    url: str,
    checks: dict[str, Check],
    timeout: float = 10.0,
    verify: bool = True,
    ignore: frozenset[str] = frozenset(),
) -> ScanResult:
    ctx = build_context(url, timeout=timeout, verify=verify)
    result = ScanResult(url=url)
    seen: set[str] = set()
    for name, check in checks.items():
        try:
            found = list(check(ctx))
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            result.errors.append(f"check '{name}' failed: {type(exc).__name__}: {exc}")
            continue
        for f in found:
            if f.rule.id in ignore or f.fingerprint in seen:
                continue
            seen.add(f.fingerprint)
            result.findings.append(f)
    return result
