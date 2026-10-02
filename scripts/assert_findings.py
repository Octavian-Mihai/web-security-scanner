#!/usr/bin/env python3
"""Regression check for a scan of a known target (OWASP Juice Shop in CI).

usage: assert_findings.py REPORT.sarif RULE_ID [RULE_ID ...] [--forbid RULE_ID ...]
Also validates the report against the official SARIF 2.1.0 schema.
"""

from __future__ import annotations

import json
import sys

SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


def main(argv: list[str]) -> int:
    path, rest = argv[0], argv[1:]
    forbid = []
    if "--forbid" in rest:
        i = rest.index("--forbid")
        rest, forbid = rest[:i], rest[i + 1:]
    expected = set(rest)

    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    try:
        import jsonschema
        import requests

        jsonschema.validate(doc, requests.get(SCHEMA_URL, timeout=30).json())
        print("SARIF schema: valid")
    except ImportError:
        print("jsonschema not installed; skipping schema validation")

    found = {r["ruleId"] for r in doc["runs"][0]["results"]}
    print("found:", ", ".join(sorted(found)) or "(none)")
    missing, unexpected = expected - found, set(forbid) & found
    if missing:
        print(f"FAIL: expected findings missing: {sorted(missing)}")
    if unexpected:
        print(f"FAIL: findings that should not appear: {sorted(unexpected)}")
    return 1 if (missing or unexpected) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
