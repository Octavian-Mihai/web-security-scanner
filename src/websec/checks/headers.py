from __future__ import annotations

import re

from .. import rules
from ..models import Finding
from ..scanner import ScanContext

_VERSIONED_SERVER = re.compile(r"[A-Za-z][\w.\-]*/\d")
_DISCLOSURE_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")
_SIX_MONTHS = 15552000


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return directives


def csp_weaknesses(csp: dict[str, list[str]]) -> list[str]:
    script_src = csp.get("script-src") or csp.get("default-src")
    if script_src is None:
        return ["no script-src or default-src directive"]
    sources = [s.lower() for s in script_src]
    problems = []
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            for s in sources)
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        problems.append("'unsafe-inline' in script sources")
    if "'unsafe-eval'" in sources:
        problems.append("'unsafe-eval' in script sources")
    for wild in ("*", "http:", "https:", "data:"):
        if wild in sources:
            problems.append(f"'{wild}' allowed as a script source")
    return problems


def _hsts_max_age(value: str) -> int | None:
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    return int(m.group(1)) if m else None


def check_headers(ctx: ScanContext) -> list[Finding]:
    h, url, out = ctx.headers, ctx.response.url, []

    csp_raw = h.get("Content-Security-Policy")
    csp = parse_csp(csp_raw) if csp_raw else {}
    if not csp_raw:
        out.append(Finding(rules.get("WSS001"), url, "No Content-Security-Policy header."))
    else:
        problems = csp_weaknesses(csp)
        if problems:
            out.append(Finding(rules.get("WSS002"), url,
                               "Content-Security-Policy is weak: " + "; ".join(problems) + ".",
                               evidence=csp_raw))

    if ctx.is_https:
        hsts = h.get("Strict-Transport-Security")
        if not hsts:
            out.append(Finding(rules.get("WSS003"), url,
                               "HTTPS response has no Strict-Transport-Security header."))
        else:
            age = _hsts_max_age(hsts)
            if age is None or age < _SIX_MONTHS:
                shown = "missing" if age is None else str(age)
                out.append(Finding(rules.get("WSS004"), url,
                                   f"HSTS max-age is {shown}; expected at least {_SIX_MONTHS}.",
                                   evidence=hsts))

    if "X-Frame-Options" not in h and "frame-ancestors" not in csp:
        out.append(Finding(rules.get("WSS005"), url,
                           "Neither X-Frame-Options nor CSP frame-ancestors is set."))

    if h.get("X-Content-Type-Options", "").strip().lower() != "nosniff":
        out.append(Finding(rules.get("WSS006"), url,
                           "X-Content-Type-Options: nosniff is not set.",
                           evidence=h.get("X-Content-Type-Options", "")))

    if "Referrer-Policy" not in h:
        out.append(Finding(rules.get("WSS007"), url, "No Referrer-Policy header."))

    if "Permissions-Policy" not in h and "Feature-Policy" not in h:
        out.append(Finding(rules.get("WSS008"), url, "No Permissions-Policy header."))

    disclosed = []
    server = h.get("Server", "")
    if _VERSIONED_SERVER.search(server):
        disclosed.append(f"Server: {server}")
    disclosed += [f"{name}: {h[name]}" for name in _DISCLOSURE_HEADERS if name in h]
    if disclosed:
        out.append(Finding(rules.get("WSS009"), url,
                           "Response discloses server technology: " + ", ".join(disclosed) + ".",
                           evidence="; ".join(disclosed)))
    return out
