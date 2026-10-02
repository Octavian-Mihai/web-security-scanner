from __future__ import annotations

import html
import json
from collections import Counter
from typing import Any

from . import __version__
from .baseline import Suppression
from .models import Finding, Severity

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"

Suppressed = list[tuple[Finding, Suppression]]


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.rule.id, f.url))


def counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity.label for f in findings)
    return {s.label: c.get(s.label, 0) for s in sorted(Severity, reverse=True)}


def _summary_line(findings: list[Finding], suppressed: Suppressed) -> str:
    summary = ", ".join(f"{n} {k}" for k, n in counts(findings).items() if n)
    line = f"{len(findings)} finding(s)" + (f": {summary}" if summary else "")
    if suppressed:
        line += f" ({len(suppressed)} suppressed by baseline)"
    new = sum(1 for f in findings if f.is_new)
    if any(f.is_new is not None for f in findings):
        line += f" [{new} new since comparison scan]"
    return line


def render_console(
    findings: list[Finding],
    colour: bool = False,
    suppressed: Suppressed | None = None,
    errors: list[str] | None = None,
) -> str:
    suppressed = suppressed or []
    lines: list[str] = []
    for f in sorted_findings(findings):
        tag = f"{f.severity.label.upper():<8}"
        if colour:
            tag = f"{_COLOURS[f.severity]}{tag}{_RESET}"
        new = " [NEW]" if f.is_new else ""
        lines.append(f"{tag} {f.rule.id}  {f.rule.name}{new}")
        lines.append(f"         {f.message}")
        lines.append(f"         {f.rule.cwe_id} | OWASP {f.rule.owasp} | {f.url}")
    if errors:
        # A failed scan must never read as a clean one.
        lines.append("")
        lines.append(f"SCAN INCOMPLETE: {len(errors)} error(s); results above are partial."
                     if findings else
                     f"SCAN FAILED: {len(errors)} error(s); no results were produced.")
    elif not findings:
        lines.append("No findings." + (f" ({len(suppressed)} suppressed by baseline)"
                                       if suppressed else ""))
    if findings:
        lines += ["", _summary_line(findings, suppressed)]
    return "\n".join(lines)


def render_markdown(
    findings: list[Finding],
    fail_on: Severity | None,
    suppressed: Suppressed | None = None,
    errors: list[str] | None = None,
    fixed: int | None = None,
) -> str:
    suppressed = suppressed or []
    out = ["## Web security scan", ""]
    if errors:
        out += [f"> :warning: **Scan incomplete** ({len(errors)} error(s)). Results are partial.",
                ""]
    if not findings:
        out.append("No findings. :white_check_mark:" if not errors else "No results produced.")
    else:
        out += ["| Severity | Rule | Finding | CWE | OWASP |", "|---|---|---|---|---|"]
        for f in sorted_findings(findings):
            msg = f.message.replace("|", "\\|") + (" **(new)**" if f.is_new else "")
            out.append(f"| {f.severity.label} | `{f.rule.id}` | {msg} | "
                       f"[{f.rule.cwe_id}]({f.rule.cwe_uri}) | {f.rule.owasp} |")
        gate = f" Build gate: `{fail_on.label}` or above." if fail_on is not None else ""
        out += ["", f"**{_summary_line(findings, suppressed)}.**{gate}"]
    if fixed is not None:
        out += ["", f"Fixed since comparison scan: **{fixed}**."]
    if suppressed:
        out += ["", "<details><summary>Suppressed by baseline</summary>", ""]
        out += [f"- `{f.rule.id}` {f.url} (reason: {s.reason})" for f, s in suppressed]
        out += ["", "</details>"]
    return "\n".join(out)


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "rule": f.rule.id, "name": f.rule.name, "severity": f.severity.label,
        "cwe": f.rule.cwe_id, "owasp": f.rule.owasp, "url": f.url, "message": f.message,
        "evidence": f.evidence, "fingerprint": f.fingerprint, "new": f.is_new,
    }


def render_json(
    findings: list[Finding], suppressed: Suppressed, errors: list[str], targets: list[str]
) -> str:
    return json.dumps({
        "tool": "websec-scanner", "version": __version__, "targets": targets,
        "counts": counts(findings),
        "findings": [finding_dict(f) for f in sorted_findings(findings)],
        "suppressed": [{**finding_dict(f), "reason": s.reason} for f, s in suppressed],
        "errors": errors,
    }, indent=2)


def render_html(
    findings: list[Finding], suppressed: Suppressed, errors: list[str], targets: list[str]
) -> str:
    e = html.escape
    rows = "".join(
        f"<tr class='{f.severity.label}'><td>{f.severity.label}</td><td>{f.rule.id}</td>"
        f"<td>{e(f.message)}<br><small>{e(f.url)}</small></td>"
        f"<td><a href='{f.rule.cwe_uri}'>{f.rule.cwe_id}</a></td><td>{e(f.rule.owasp)}</td></tr>"
        for f in sorted_findings(findings))
    err = "".join(f"<li>{e(x)}</li>" for x in errors)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>websec report</title><style>
body{{font:14px system-ui,sans-serif;margin:2rem;color:#1b1f23}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #d0d7de;padding:6px 10px;
text-align:left;vertical-align:top}}th{{background:#f6f8fa}}
.critical td:first-child,.high td:first-child{{color:#cf222e;font-weight:600}}
.medium td:first-child{{color:#9a6700;font-weight:600}}.low td:first-child{{color:#0969da}}
</style></head><body><h1>Web security scan</h1>
<p>Targets: {e(', '.join(targets))} &middot; websec {__version__}</p>
<p>{e(_summary_line(findings, suppressed))}</p>
{f'<p><strong>Scan incomplete:</strong></p><ul>{err}</ul>' if errors else ''}
<table><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>CWE</th><th>OWASP</th></tr>{rows}
</table></body></html>"""
