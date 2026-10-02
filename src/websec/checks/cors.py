from __future__ import annotations

import requests

from .. import rules
from ..models import Finding
from ..scanner import ScanContext

PROBE_ORIGIN = "https://websec-probe.invalid"


def check_cors(ctx: ScanContext) -> list[Finding]:
    url = ctx.response.url
    try:
        resp = ctx.session.get(url, headers={"Origin": PROBE_ORIGIN}, timeout=ctx.timeout,
                               verify=ctx.verify, allow_redirects=False)
    except requests.RequestException:
        return []

    acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
    creds = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
    evidence = f"Access-Control-Allow-Origin: {acao}"

    if acao == PROBE_ORIGIN:
        if creds:
            return [Finding(rules.get("WSS011"), url,
                            "Server reflected an arbitrary Origin and allows credentials.",
                            evidence=evidence + "; Access-Control-Allow-Credentials: true")]
        return [Finding(rules.get("WSS010"), url,
                        "Server reflects arbitrary Origin values (no credentials allowed).",
                        evidence=evidence)]
    if acao == "*":
        return [Finding(rules.get("WSS010"), url,
                        "Access-Control-Allow-Origin is '*'; any site can read this response.",
                        evidence=evidence)]
    return []
