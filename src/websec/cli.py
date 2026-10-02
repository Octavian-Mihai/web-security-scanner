from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from pathlib import Path

from . import __version__, baseline
from .checks import CHECKS
from .models import Finding, Severity
from .report import (
    counts,
    render_console,
    render_html,
    render_json,
    render_markdown,
)
from .rules import RULES
from .sarif import build_sarif
from .scanner import RateLimiter, ScanError, ScanOptions, Scope, scan

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
DEFAULT_CONFIG = ".websec.toml"
_FP_KEY = "websecFinding/v1"


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
    out = s.add_argument_group("output")
    out.add_argument("--sarif", metavar="PATH", help="write SARIF 2.1.0 results to PATH")
    out.add_argument("--sarif-anchor", default="README.md", metavar="FILE",
                     help="repo file SARIF results are attached to (default: README.md)")
    out.add_argument("--json", metavar="PATH", help="write a JSON report to PATH")
    out.add_argument("--html", metavar="PATH", help="write a standalone HTML report to PATH")
    out.add_argument("--markdown", metavar="PATH", help="write a markdown summary to PATH")
    out.add_argument("--compare-with", metavar="SARIF",
                     help="earlier SARIF report; findings are marked new/fixed against it")
    out.add_argument("--no-colour", action="store_true")

    gate = s.add_argument_group("gating and suppression")
    gate.add_argument("--fail-on", type=_fail_on, default=Severity.HIGH, metavar="LEVEL",
                      help="exit 1 if any finding is at/above LEVEL: "
                           "critical|high|medium|low|info|none (default: high)")
    gate.add_argument("--ignore", type=_csv, default=[], metavar="IDS",
                      help="comma-separated rule IDs to drop entirely, e.g. WSS030,WSS008")
    gate.add_argument("--config", metavar="PATH",
                      help=f"suppression file (default: ./{DEFAULT_CONFIG} if present)")

    scope = s.add_argument_group("coverage and politeness")
    scope.add_argument("--checks", type=_csv, default=list(CHECKS), metavar="NAMES",
                       help=f"comma-separated check groups (default: {','.join(CHECKS)})")
    scope.add_argument("--crawl-depth", type=int, default=0, metavar="N",
                       help="follow same-origin links N levels deep (default: 0 = given URLs only)")
    scope.add_argument("--max-pages", type=int, default=20, metavar="N")
    scope.add_argument("--workers", type=int, default=4, metavar="N",
                       help="concurrent page fetches while crawling")
    scope.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
                       help="minimum delay between any two requests")
    scope.add_argument("--allow-host", type=_csv, default=[], metavar="HOSTS",
                       help="extra host globs the scan may contact (e.g. www.example.com); "
                            "by default only hosts of the given URLs are in scope")
    scope.add_argument("--no-robots", action="store_true", help="ignore robots.txt when crawling")
    scope.add_argument("--timeout", type=float, default=10.0, metavar="SECONDS")
    scope.add_argument("--insecure", action="store_true",
                       help="do not verify TLS certificates when fetching pages")

    sub.add_parser("rules", help="list every rule with its CWE/OWASP mapping")
    return p


def _cmd_rules() -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.severity.label:<8} {r.cwe_id:<9} {r.owasp:<46} {r.name}")
    return EXIT_OK


def _load_fingerprints(path: str) -> set[str]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        r["partialFingerprints"][_FP_KEY]
        for run in doc.get("runs", []) for r in run.get("results", [])
        if _FP_KEY in r.get("partialFingerprints", {})
    }


def _write(path: str, text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _write_github_outputs(
    findings: list[Finding], suppressed: int, fail_on: Severity | None, failed: bool,
    markdown: str,
) -> None:
    """Expose results to later workflow steps and the run summary when on Actions."""
    if out := os.environ.get("GITHUB_OUTPUT"):
        highest = max((f.severity for f in findings), default=None)
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"findings={len(findings)}\n")
            fh.write(f"suppressed={suppressed}\n")
            fh.write(f"highest-severity={highest.label if highest is not None else 'none'}\n")
            fh.write(f"counts={json.dumps(counts(findings))}\n")
            fh.write(f"failed={'true' if failed else 'false'}\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


def _cmd_scan(args: argparse.Namespace) -> int:
    unknown = [c for c in args.checks if c not in CHECKS]
    if unknown:
        print(f"error: unknown check group(s): {', '.join(unknown)}", file=sys.stderr)
        return EXIT_ERROR
    bad_rules = [r for r in args.ignore if r not in RULES]
    if bad_rules:
        print(f"error: unknown rule id(s): {', '.join(bad_rules)}", file=sys.stderr)
        return EXIT_ERROR

    config_path = args.config or (DEFAULT_CONFIG if Path(DEFAULT_CONFIG).is_file() else None)
    try:
        suppressions = baseline.load(Path(config_path)) if config_path else []
        previous = _load_fingerprints(args.compare_with) if args.compare_with else None
    except (baseline.ConfigError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    options = ScanOptions(
        timeout=args.timeout, verify=not args.insecure, ignore=frozenset(args.ignore),
        crawl_depth=args.crawl_depth, max_pages=args.max_pages, workers=args.workers,
        delay=args.delay, allow_hosts=tuple(args.allow_host), respect_robots=not args.no_robots)
    checks = {name: CHECKS[name] for name in args.checks}
    scope = Scope.for_urls(args.urls, args.allow_host)
    limiter = RateLimiter(args.delay)

    raw: list[Finding] = []
    errors: list[str] = []
    for url in args.urls:
        print(f"Scanning {url} ...", file=sys.stderr)
        try:
            result = scan(url, checks, options, scope, limiter)
        except ScanError as exc:
            errors.append(str(exc))
            continue
        raw += result.findings
        errors += [f"{url}: {e}" for e in result.errors]
        for w in result.warnings:
            print(f"warning: {w}", file=sys.stderr)
        if args.crawl_depth:
            print(f"  crawled {result.pages_scanned} page(s)", file=sys.stderr)

    applied = baseline.apply(raw, suppressions)
    findings, suppressed = applied.active, applied.suppressed
    for w in applied.warnings:
        print(f"warning: {w}", file=sys.stderr)

    fixed: int | None = None
    if previous is not None:
        for f in findings:
            f.is_new = f.fingerprint not in previous
        fixed = len(previous - {f.fingerprint for f in [*findings, *(x for x, _ in suppressed)]})

    colour = sys.stdout.isatty() and not args.no_colour
    print(render_console(findings, colour=colour, suppressed=suppressed, errors=errors))
    for e in errors:
        print(f"error: {e}", file=sys.stderr)

    markdown = render_markdown(findings, args.fail_on, suppressed, errors, fixed)
    if args.sarif:
        _write(args.sarif, json.dumps(build_sarif(findings, errors, args.sarif_anchor), indent=2))
        print(f"SARIF written to {args.sarif}", file=sys.stderr)
    if args.json:
        _write(args.json, render_json(findings, suppressed, errors, args.urls))
    if args.html:
        _write(args.html, render_html(findings, suppressed, errors, args.urls))
    if args.markdown:
        _write(args.markdown, markdown)

    gated = args.fail_on is not None and any(f.severity >= args.fail_on for f in findings)
    _write_github_outputs(findings, len(suppressed), args.fail_on, gated, markdown)

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
