"""SARIF 2.1.0 output, shaped for GitHub code scanning.

GitHub specifics worth knowing:
  * `properties.security-severity` (a CVSS-like number) drives the
    critical/high/medium/low badge in the Security tab; `level` alone does not.
  * Tags of the form `external/cwe/cwe-NNN` are rendered as CWE links.
  * Results need a file location, but web findings have none. We anchor them to a
    real repo file (configurable) and keep the scanned URL as a logical location.
  * `partialFingerprints` lets GitHub track an alert across runs instead of
    closing and re-opening it whenever line numbers shift.
"""

from __future__ import annotations

import os
import re

from . import __version__
from .models import Finding, Rule, Severity
from .rules import RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


def _pascal(name: str) -> str:
    return "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", name) if w)


def _rule_descriptor(rule: Rule) -> dict:
    owasp_tag = "owasp-" + rule.owasp.split(" ")[0].lower().replace(":", "-")
    return {
        "id": rule.id,
        "name": _pascal(rule.name),
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": f"{rule.description}\n\nRemediation: {rule.remediation}\n\n"
                    f"{rule.cwe_id} | OWASP {rule.owasp}",
            "markdown": f"{rule.description}\n\n**Remediation:** {rule.remediation}\n\n"
                        f"- [{rule.cwe_id}]({rule.cwe_uri})\n"
                        f"- [OWASP {rule.owasp}]({rule.owasp_uri})",
        },
        "helpUri": rule.cwe_uri,
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", f"external/cwe/cwe-{rule.cwe}", owasp_tag],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "precision": "high",
            "problem.severity": _LEVEL[rule.severity],
        },
    }


def build_sarif(
    findings: list[Finding],
    errors: list[str] | None = None,
    anchor: str = "README.md",
) -> dict:
    rule_ids = list(RULES)
    index = {rid: i for i, rid in enumerate(rule_ids)}

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.message} [{f.url}]"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": anchor, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f.url, "kind": "url"}],
            }],
            "partialFingerprints": {"websecFinding/v1": f.fingerprint},
            "properties": {
                "url": f.url,
                "evidence": f.evidence,
                "cwe": f.rule.cwe_id,
                "owasp": f.rule.owasp,
                "severity": f.severity.label,
            },
        })

    notifications = [
        {"level": "error", "message": {"text": e}} for e in (errors or [])
    ]
    driver = {
        "name": "websec-scanner",
        "version": __version__,
        "rules": [_rule_descriptor(RULES[r]) for r in rule_ids],
    }
    if repo := os.environ.get("GITHUB_REPOSITORY"):
        driver["informationUri"] = f"https://github.com/{repo}"
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "invocations": [{
                "executionSuccessful": not errors,
                "toolExecutionNotifications": notifications,
            }],
            "results": results,
        }],
    }
