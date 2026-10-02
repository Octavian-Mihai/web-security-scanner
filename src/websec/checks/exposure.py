from __future__ import annotations

import json
import re
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

import requests

from .. import rules
from ..models import Finding
from ..scanner import ScanContext

MAX_BYTES = 8192
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_SCRIPTS = 5
_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", re.MULTILINE)
_DIR_LISTING = re.compile(r"<title>\s*(index of|listing directory)|<h1>\s*index of", re.IGNORECASE)
_SOURCE_MAP_REF = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_PROMETHEUS = re.compile(r"^# (HELP|TYPE) \w+", re.MULTILINE)
# Directories commonly left browsable. Single-page apps often answer 200 for any
# path, so every match below is content-validated, never status-code only.
_LISTING_PATHS = ("/ftp/", "/backup/", "/uploads/", "/files/")


def _is_json_with(body: str, *keys: str) -> bool:
    try:
        data = json.loads(body)
    except ValueError:
        return False
    return isinstance(data, dict) and any(k in data for k in keys)


# (path, description, validator on the body)
_MANAGEMENT: list[tuple[str, str, Callable[[str], bool]]] = [
    ("/actuator/env", "Spring Boot Actuator /actuator/env",
     lambda b: _is_json_with(b, "propertySources", "activeProfiles")),
    ("/actuator", "Spring Boot Actuator index", lambda b: _is_json_with(b, "_links")),
    ("/server-status", "Apache mod_status /server-status",
     lambda b: "Apache Server Status" in b),
    ("/metrics", "Prometheus /metrics", lambda b: bool(_PROMETHEUS.search(b))),
    ("/phpinfo.php", "phpinfo() page", lambda b: "phpinfo()" in b or "PHP Version" in b),
]


def _get(ctx: ScanContext, url: str, limit: int = MAX_BYTES) -> str | None:
    """GET and return up to `limit` bytes of a 200 response body, else None."""
    try:
        resp = ctx.session.get(url, timeout=ctx.timeout, verify=ctx.verify,
                               allow_redirects=False, stream=True)
        body = resp.raw.read(limit, decode_content=True).decode("utf-8", "replace")
        resp.close()
    except (requests.RequestException, OSError):
        return None
    return body if resp.status_code == 200 else None


def _same_origin(ctx: ScanContext, url: str) -> bool:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" == ctx.origin


def _source_maps(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    scripts = [urljoin(ctx.response.url, r.url) for r in ctx.page.resources if r.tag == "script"]
    for script in [s for s in scripts if _same_origin(ctx, s)][:MAX_SCRIPTS]:
        body = _get(ctx, script, MAX_SCRIPT_BYTES)
        match = _SOURCE_MAP_REF.search(body[-4096:]) if body else None
        if not match or match.group(1).startswith("data:"):
            continue
        map_url = urljoin(script, match.group(1))
        if not _same_origin(ctx, map_url):
            continue
        map_body = _get(ctx, map_url, MAX_SCRIPT_BYTES)
        if map_body and _is_json_with(map_body, "mappings") and "sources" in map_body:
            out.append(Finding(rules.get("WSS043"), map_url,
                               f"Source map for {script} is publicly readable.",
                               evidence=map_url, key=map_url))
    return out


def check_exposure(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    origin = ctx.origin

    body = _get(ctx, origin + "/.git/HEAD")
    if body and re.match(r"ref:\s*refs/", body):
        out.append(Finding(rules.get("WSS040"), origin + "/.git/HEAD",
                           "/.git/HEAD is publicly readable.", evidence=body.strip()[:80]))

    body = _get(ctx, origin + "/.env")
    if body and "<html" not in body.lower() and _ENV_LINE.search(body):
        out.append(Finding(rules.get("WSS041"), origin + "/.env",
                           "/.env is publicly readable and contains KEY=value pairs.",
                           evidence="(contents withheld)"))

    for path in _LISTING_PATHS:
        body = _get(ctx, origin + path)
        match = _DIR_LISTING.search(body) if body else None
        if match:
            out.append(Finding(rules.get("WSS042"), origin + path,
                               f"Directory listing is enabled at {path}",
                               evidence=match.group(0)))

    for path, label, valid in _MANAGEMENT:
        body = _get(ctx, origin + path)
        if body and valid(body):
            out.append(Finding(rules.get("WSS044"), origin + path,
                               f"{label} is publicly readable.", evidence=path, key=path))

    body = _get(ctx, origin + "/.well-known/security.txt")
    if not (body and "<html" not in body.lower() and re.search(r"^Contact:", body, re.MULTILINE)):
        out.append(Finding(rules.get("WSS052"), origin + "/.well-known/security.txt",
                           "No valid /.well-known/security.txt (needs a Contact field)."))

    out += _source_maps(ctx)
    return out
