from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from pathlib import Path

from . import __version__
from .checks import CHECKS
from .models import Finding, Severity
from .report import counts, render_console, render_markdown
from .rules import RULES
from .sarif import build_sarif
from .scanner import ScanError, scan

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _fail_on(value: str) -> Severity | None:
    return None if value.lower() == "none" else Severity.parse(value)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="websec", description="Passive web security scanner.")
    p.add_argument("--version", action="version", version=f"websec {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan one or more URLs")
    s.add_argument("urls", nargs="+", metavar="URL")
    s.add_argument("--sarif", metavar="PATH", help="write SARIF 2.1.0 results to PATH")
    s.add_argument("--sarif-anchor", default="README.md", metavar="FILE",
                   help="repo file SARIF results are attached to (default: README.md)")
    s.add_argument("--fail-on", type=_fail_on, default=Severity.HIGH, metavar="LEVEL",
                   help="exit 1 if any finding is at/above LEVEL: "
                        "critical|high|medium|low|info|none (default: high)")
    s.add_argument("--ignore", type=_csv, default=[], metavar="IDS",
                   help="comma-separated rule IDs to suppress, e.g. WSS030,WSS008")
    s.add_argument("--checks", type=_csv, default=list(CHECKS), metavar="NAMES",
                   help=f"comma-separated check groups (default: all of {','.join(CHECKS)})")
    s.add_argument("--timeout", type=float, default=10.0, metavar="SECONDS")
    s.add_argument("--insecure", action="store_true",
                   help="do not verify TLS certificates when fetching pages")
    s.add_argument("--no-colour", action="store_true")

    sub.add_parser("rules", help="list every rule with its CWE/OWASP mapping")
    return p


def _cmd_rules() -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.severity.label:<8} {r.cwe_id:<9} {r.owasp:<42} {r.name}")
    return EXIT_OK


def _write_github_outputs(findings: list[Finding], fail_on: Severity | None, failed: bool) -> None:
    """Expose results to later workflow steps and the run summary when on Actions."""
    if out := os.environ.get("GITHUB_OUTPUT"):
        highest = max((f.severity for f in findings), default=None)
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"findings={len(findings)}\n")
            fh.write(f"highest-severity={highest.label if highest is not None else 'none'}\n")
            fh.write(f"counts={json.dumps(counts(findings))}\n")
            fh.write(f"failed={'true' if failed else 'false'}\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(render_markdown(findings, fail_on) + "\n")


def _cmd_scan(args: argparse.Namespace) -> int:
    unknown = [c for c in args.checks if c not in CHECKS]
    if unknown:
        print(f"error: unknown check group(s): {', '.join(unknown)}", file=sys.stderr)
        return EXIT_ERROR
    bad_rules = [r for r in args.ignore if r not in RULES]
    if bad_rules:
        print(f"error: unknown rule id(s): {', '.join(bad_rules)}", file=sys.stderr)
        return EXIT_ERROR

    checks = {name: CHECKS[name] for name in args.checks}
    findings: list[Finding] = []
    errors: list[str] = []
    for url in args.urls:
        print(f"Scanning {url} ...", file=sys.stderr)
        try:
            result = scan(url, checks, timeout=args.timeout, verify=not args.insecure,
                          ignore=frozenset(args.ignore))
        except ScanError as exc:
            errors.append(str(exc))
            continue
        findings += result.findings
        errors += [f"{url}: {e}" for e in result.errors]

    colour = sys.stdout.isatty() and not args.no_colour
    print(render_console(findings, colour=colour))
    for e in errors:
        print(f"error: {e}", file=sys.stderr)

    if args.sarif:
        path = Path(args.sarif)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(build_sarif(findings, errors, args.sarif_anchor), indent=2))
        print(f"SARIF written to {path}", file=sys.stderr)

    gated = args.fail_on is not None and any(f.severity >= args.fail_on for f in findings)
    _write_github_outputs(findings, args.fail_on, gated)

    if errors:
        return EXIT_ERROR
    if gated:
        print(f"FAILED: findings at or above '{args.fail_on.label}' severity.", file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    warnings.simplefilter("ignore", DeprecationWarning)
    args = build_parser().parse_args(argv)
    return _cmd_rules() if args.command == "rules" else _cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
