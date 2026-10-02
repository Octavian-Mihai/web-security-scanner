from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from websec import baseline, rules
from websec.cli import main
from websec.models import Finding

TODAY = date(2026, 6, 1)


def finding(rule="WSS008", url="https://staging.example.com/"):
    return Finding(rules.get(rule), url, "msg")


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / ".websec.toml"
    p.write_text(text)
    return p


def test_load_valid(tmp_path):
    p = write(tmp_path, '''
[[ignore]]
rule = "WSS008"
reason = "tracked in SEC-1"
url = "https://staging.example.com/*"
expires = 2027-01-01
''')
    (sup,) = baseline.load(p)
    assert (sup.rule, sup.url, sup.expires) == ("WSS008", "https://staging.example.com/*",
                                                 date(2027, 1, 1))


@pytest.mark.parametrize("body,msg", [
    ('[[ignore]]\nrule = "WSS008"\n', "reason"),
    ('[[ignore]]\nrule = "WSS008"\nreason = "  "\n', "reason"),
    ('[[ignore]]\nrule = "WSS999"\nreason = "x"\n', "known rule"),
    ('[[ignore]]\nrule = "WSS008"\nreason = "x"\nbogus = 1\n', "unknown key"),
    ('[[ignore]]\nrule = "WSS008"\nreason = "x"\nexpires = "soon"\n', "TOML date"),
    ('ignore = "nope"\n', "array of tables"),
    ("this is not toml", "tomllib|Expected|Invalid|value"),
])
def test_load_rejects_bad_config(tmp_path, body, msg):
    with pytest.raises(baseline.ConfigError, match=msg):
        baseline.load(write(tmp_path, body))


def test_apply_matches_rule_and_glob():
    sups = [baseline.Suppression("WSS008", "r", "https://staging.example.com/*")]
    result = baseline.apply([finding(), finding(url="https://prod.example.com/"),
                             finding("WSS007")], sups, TODAY)
    assert sorted((f.rule.id, f.url) for f in result.active) == [
        ("WSS007", "https://staging.example.com/"), ("WSS008", "https://prod.example.com/")]
    assert len(result.suppressed) == 1


def test_expired_suppression_is_not_applied_and_warns():
    sups = [baseline.Suppression("WSS008", "r", expires=date(2026, 1, 1))]
    result = baseline.apply([finding()], sups, TODAY)
    assert len(result.active) == 1 and not result.suppressed
    assert any("expired" in w for w in result.warnings)


def test_expiry_day_itself_still_applies():
    sups = [baseline.Suppression("WSS008", "r", expires=TODAY)]
    assert baseline.apply([finding()], sups, TODAY).suppressed


def test_unused_suppression_warns():
    result = baseline.apply([], [baseline.Suppression("WSS008", "r")], TODAY)
    assert any("matched nothing" in w for w in result.warnings)


def test_cli_suppression_removes_finding_from_gate_and_sarif(site, tmp_path, capsys):
    site.routes["*"] = (200, [], "")
    cfg = write(tmp_path, '[[ignore]]\nrule = "WSS038"\nreason = "local dev target"\n')
    sarif = tmp_path / "o.sarif"
    argv = ["scan", site.url, "--checks", "tls", "--fail-on", "low", "--sarif", str(sarif)]
    assert main(argv) == 1  # without config the low finding trips the gate
    assert main([*argv, "--config", str(cfg)]) == 0
    assert json.loads(sarif.read_text())["runs"][0]["results"] == []
    assert "1 suppressed by baseline" in capsys.readouterr().out


def test_cli_autodiscovers_default_config(site, tmp_path, monkeypatch):
    site.routes["*"] = (200, [], "")
    write(tmp_path, '[[ignore]]\nrule = "WSS038"\nreason = "local"\n')
    monkeypatch.chdir(tmp_path)
    assert main(["scan", site.url, "--checks", "tls", "--fail-on", "low"]) == 0


def test_cli_bad_config_is_exit_2(site, tmp_path):
    cfg = write(tmp_path, '[[ignore]]\nrule = "WSS008"\n')
    assert main(["scan", site.url, "--config", str(cfg)]) == 2
