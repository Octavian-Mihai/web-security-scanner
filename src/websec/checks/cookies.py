from __future__ import annotations

from dataclasses import dataclass, field

from .. import rules
from ..models import Finding
from ..scanner import ScanContext


@dataclass
class Cookie:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)  # lower-cased attribute -> value

    @property
    def secure(self) -> bool:
        return "secure" in self.attrs

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attrs

    @property
    def samesite(self) -> str | None:
        value = self.attrs.get("samesite")
        return value.lower() if value is not None else None


def parse_set_cookie(header: str) -> Cookie | None:
    first, *rest = header.split(";")
    if "=" not in first:
        return None
    cookie = Cookie(name=first.split("=", 1)[0].strip())
    for part in rest:
        key, _, value = part.strip().partition("=")
        if key:
            cookie.attrs[key.lower()] = value.strip()
    return cookie


def _set_cookie_headers(resp) -> list[str]:
    # requests folds repeated headers into one string; urllib3 keeps them separate.
    return resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []


def check_cookies(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    for resp in ctx.chain:
        https = resp.url.startswith("https://")
        for raw in _set_cookie_headers(resp):
            cookie = parse_set_cookie(raw)
            if cookie is None:
                continue
            name = cookie.name
            evidence = raw
            # Browsers ignore Secure cookies set over HTTP, so only flag on HTTPS.
            if https and not cookie.secure:
                out.append(Finding(rules.get("WSS020"), resp.url,
                                   f"Cookie '{name}' is set without the Secure flag.",
                                   evidence=evidence, key=name))
            if not cookie.httponly:
                out.append(Finding(rules.get("WSS021"), resp.url,
                                   f"Cookie '{name}' is set without the HttpOnly flag.",
                                   evidence=evidence, key=name))
            if (cookie.samesite or "none").lower() == "none":
                out.append(Finding(rules.get("WSS022"), resp.url,
                                   f"Cookie '{name}' has no SameSite restriction.",
                                   evidence=evidence, key=name))
    return out
