from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from .. import rules
from ..models import Finding
from ..scanner import ScanContext

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def _redact(token: str) -> str:
    return token[:12] + "..."  # never echo a whole credential into a report


def _foreign(page_url: str, resource_url: str) -> bool:
    page_host = urlsplit(page_url).hostname
    res_host = urlsplit(urljoin(page_url, resource_url)).hostname
    return res_host is not None and res_host != page_host


def check_content(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    page_url = ctx.response.url
    page = ctx.page

    for res in page.resources:
        if res.integrity is None and _foreign(page_url, res.url):
            absolute = urljoin(page_url, res.url)
            out.append(Finding(rules.get("WSS050"), page_url,
                               f"{'Script' if res.tag == 'script' else 'Stylesheet'} "
                               f"{absolute} is loaded without an integrity attribute.",
                               evidence=absolute, key=absolute))

    if ctx.is_https:
        for ref in page.refs:
            absolute = urljoin(page_url, ref.url)
            if absolute.lower().startswith("http://"):
                out.append(Finding(rules.get("WSS051"), page_url,
                                   f"<{ref.tag} {ref.attr}> loads {absolute} over plain HTTP.",
                                   evidence=absolute, key=absolute))

    candidates = [page_url]
    candidates += [r.headers.get("Location", "") for r in ctx.chain]
    candidates += [urljoin(page_url, href) for href in page.links]
    candidates += [urljoin(page_url, r.url) for r in page.refs]
    reported: set[str] = set()
    for candidate in candidates:
        parts = urlsplit(candidate)
        match = _JWT.search(parts.query + "&" + parts.fragment + "&" + parts.path)
        if match and match.group(0) not in reported:
            reported.add(match.group(0))
            out.append(Finding(rules.get("WSS053"), page_url,
                               f"A JWT appears in a URL ({_redact(match.group(0))}).",
                               evidence=_redact(match.group(0)), key=_redact(match.group(0))))
    return out
