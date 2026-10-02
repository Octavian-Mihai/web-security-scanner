from __future__ import annotations

import re

import requests

from .. import rules
from ..models import Finding
from ..scanner import ScanContext

MAX_BYTES = 8192
_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", re.MULTILINE)
_DIR_LISTING = re.compile(r"<title>\s*(index of|listing directory)|<h1>\s*index of", re.IGNORECASE)
# Directories commonly left browsable. Single-page apps often answer 200 for any
# path, so every match below is content-validated, never status-code only.
_LISTING_PATHS = ("/ftp/", "/backup/", "/uploads/", "/files/")


def _get(ctx: ScanContext, path: str) -> tuple[requests.Response, str] | None:
    try:
        resp = ctx.session.get(ctx.origin + path, timeout=ctx.timeout, verify=ctx.verify,
                               allow_redirects=False, stream=True)
        body = resp.raw.read(MAX_BYTES, decode_content=True).decode("utf-8", "replace")
        resp.close()
    except (requests.RequestException, OSError):
        return None
    return (resp, body) if resp.status_code == 200 else None


def check_exposure(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []

    hit = _get(ctx, "/.git/HEAD")
    if hit and re.match(r"ref:\s*refs/", hit[1]):
        out.append(Finding(rules.get("WSS040"), ctx.origin + "/.git/HEAD",
                           "/.git/HEAD is publicly readable.", evidence=hit[1].strip()[:80]))

    hit = _get(ctx, "/.env")
    if hit and "<html" not in hit[1].lower() and _ENV_LINE.search(hit[1]):
        out.append(Finding(rules.get("WSS041"), ctx.origin + "/.env",
                           "/.env is publicly readable and contains KEY=value pairs.",
                           evidence="(contents withheld)"))

    for path in _LISTING_PATHS:
        hit = _get(ctx, path)
        if hit and _DIR_LISTING.search(hit[1]):
            out.append(Finding(rules.get("WSS042"), ctx.origin + path,
                               f"Directory listing is enabled at {path}",
                               evidence=_DIR_LISTING.search(hit[1]).group(0)))
    return out
