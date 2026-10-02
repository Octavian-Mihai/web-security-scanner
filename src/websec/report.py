from __future__ import annotations

from collections import Counter

from .models import Finding, Severity

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.rule.id, f.url))


def counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity.label for f in findings)
    return {s.label: c.get(s.label, 0) for s in sorted(Severity, reverse=True)}


def render_console(findings: list[Finding], colour: bool = False) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in sorted_findings(findings):
        tag = f"{f.severity.label.upper():<8}"
        if colour:
            tag = f"{_COLOURS[f.severity]}{tag}{_RESET}"
        lines.append(f"{tag} {f.rule.id}  {f.rule.name}")
        lines.append(f"         {f.message}")
        lines.append(f"         {f.rule.cwe_id} | OWASP {f.rule.owasp} | {f.url}")
    summary = ", ".join(f"{n} {k}" for k, n in counts(findings).items() if n)
    lines.append("")
    lines.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def render_markdown(findings: list[Finding], fail_on: Severity | None) -> str:
    out = ["## Web security scan", ""]
    if not findings:
        return "\n".join(out + ["No findings. :white_check_mark:"])
    out += ["| Severity | Rule | Finding | CWE | OWASP |", "|---|---|---|---|---|"]
    for f in sorted_findings(findings):
        msg = f.message.replace("|", "\\|")
        out.append(f"| {f.severity.label} | `{f.rule.id}` | {msg} | "
                   f"[{f.rule.cwe_id}]({f.rule.cwe_uri}) | {f.rule.owasp} |")
    gate = f" Build gate: `{fail_on.label}` or above." if fail_on is not None else ""
    out += ["", f"**{len(findings)} finding(s).**{gate}"]
    return "\n".join(out)
