from __future__ import annotations

import json

from websec import rules
from websec.cli import main
from websec.models import Finding, Severity
from websec.sarif import build_sarif


def _finding(rule_id="WSS001", url="http://x/", key=""):
    return Finding(rules.get(rule_id), url, "msg", evidence="ev", key=key)


def test_sarif_structure():
    doc = build_sarif([_finding("WSS030"), _finding("WSS006")], anchor="README.md")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))
    for res in run["results"]:
        assert ids[res["ruleIndex"]] == res["ruleId"]  # index must point at the same rule
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "README.md"
        assert loc["region"]["startLine"] == 1
        assert res["partialFingerprints"]["websecFinding/v1"]
    high = next(r for r in run["results"] if r["ruleId"] == "WSS030")
    assert high["level"] == "error"


def test_sarif_rules_carry_cwe_and_owasp_and_severity():
    driver = build_sarif([])["runs"][0]["tool"]["driver"]
    r = next(r for r in driver["rules"] if r["id"] == "WSS030")
    assert "external/cwe/cwe-319" in r["properties"]["tags"]
    assert r["properties"]["security-severity"] == "8.0"
    assert "owasp.org/Top10/A02_2021-Cryptographic_Failures" in r["help"]["markdown"]


def test_fingerprint_stable_and_distinguishes_keys():
    assert _finding().fingerprint == _finding().fingerprint
    assert _finding(key="a").fingerprint != _finding(key="b").fingerprint


def test_errors_mark_invocation_unsuccessful():
    inv = build_sarif([], errors=["boom"])["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    assert inv["toolExecutionNotifications"][0]["message"]["text"] == "boom"


def test_severity_parse():
    assert Severity.parse("High") is Severity.HIGH


def test_cli_exit_codes_and_sarif(site, tmp_path, capsys):
    site.routes["*"] = (200, [], "")
    out = tmp_path / "r" / "out.sarif"
    # Loopback plain HTTP => WSS038 (low) => trips a "low" gate, not the default "high" one.
    assert main(["scan", site.url, "--sarif", str(out), "--checks", "tls",
                 "--fail-on", "low"]) == 1
    assert json.loads(out.read_text())["runs"][0]["results"][0]["ruleId"] == "WSS038"
    assert main(["scan", site.url, "--checks", "tls"]) == 0
    assert main(["scan", site.url, "--checks", "tls", "--fail-on", "none"]) == 0
    assert main(["scan", site.url, "--checks", "tls", "--fail-on", "low",
                 "--ignore", "WSS038"]) == 0


def test_cli_unreachable_target_is_error_not_pass(tmp_path):
    out = tmp_path / "o.sarif"
    assert main(["scan", "http://127.0.0.1:1", "--sarif", str(out), "--timeout", "2"]) == 2
    inv = json.loads(out.read_text())["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False


def test_cli_rejects_bad_input(capsys):
    assert main(["scan", "http://x", "--checks", "nope"]) == 2
    assert main(["scan", "http://x", "--ignore", "WSS999"]) == 2
    assert main(["scan", "ftp://x"]) == 2


def test_github_outputs_written(site, tmp_path, monkeypatch):
    site.routes["*"] = (200, [], "")
    gh_out, gh_sum = tmp_path / "out", tmp_path / "sum"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(gh_sum))
    main(["scan", site.url, "--checks", "tls", "--fail-on", "low"])
    text = gh_out.read_text()
    assert "findings=1" in text and "highest-severity=low" in text and "failed=true" in text
    assert "WSS038" in gh_sum.read_text()
