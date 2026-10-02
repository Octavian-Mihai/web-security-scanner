"""Accepted-risk suppressions, loaded from a TOML file (default: .websec.toml).

    [[ignore]]
    rule    = "WSS008"                            # required
    reason  = "Tracked in SEC-123"                # required: no silent suppressions
    url     = "https://staging.example.com/*"     # optional glob; default "*"
    expires = 2027-03-01                          # optional; after this the entry stops applying

Expired entries are *not* applied (the finding comes back) and are reported, so a
suppression can't quietly outlive the reason for it.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from fnmatch import fnmatch
from pathlib import Path

from .models import Finding
from .rules import RULES

_ALLOWED_KEYS = {"rule", "reason", "url", "expires"}


class ConfigError(Exception):
    pass


@dataclass
class Suppression:
    rule: str
    reason: str
    url: str = "*"
    expires: date | None = None
    matched: int = 0

    def expired(self, today: date) -> bool:
        return self.expires is not None and today > self.expires

    def matches(self, finding: Finding) -> bool:
        return finding.rule.id == self.rule and fnmatch(finding.url, self.url)

    def describe(self) -> str:
        return f"{self.rule} @ {self.url}"


@dataclass
class Applied:
    active: list[Finding]
    suppressed: list[tuple[Finding, Suppression]]
    warnings: list[str]


def load(path: Path) -> list[Suppression]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    entries = data.get("ignore", [])
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: 'ignore' must be an array of tables ([[ignore]])")
    out: list[Suppression] = []
    for i, entry in enumerate(entries, 1):
        where = f"{path}: [[ignore]] #{i}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: must be a table")
        unknown = set(entry) - _ALLOWED_KEYS
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
        rule = entry.get("rule")
        if rule not in RULES:
            raise ConfigError(f"{where}: 'rule' must be a known rule id, got {rule!r}")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ConfigError(f"{where}: a non-empty 'reason' is required")
        url = entry.get("url", "*")
        if not isinstance(url, str):
            raise ConfigError(f"{where}: 'url' must be a string glob")
        expires = entry.get("expires")
        if expires is not None and not isinstance(expires, date):
            raise ConfigError(f"{where}: 'expires' must be a TOML date, e.g. 2027-03-01")
        out.append(Suppression(rule, reason.strip(), url, expires))
    return out


def apply(
    findings: list[Finding], suppressions: list[Suppression], today: date | None = None
) -> Applied:
    today = today or date.today()  # noqa: DTZ011 - expiry is a calendar date
    warnings: list[str] = []
    live = []
    for sup in suppressions:
        if sup.expired(today):
            warnings.append(f"suppression for {sup.describe()} expired on {sup.expires}; "
                            "it is no longer applied")
        else:
            live.append(sup)

    active: list[Finding] = []
    suppressed: list[tuple[Finding, Suppression]] = []
    for finding in findings:
        hit = next((s for s in live if s.matches(finding)), None)
        if hit is None:
            active.append(finding)
        else:
            hit.matched += 1
            suppressed.append((finding, hit))

    warnings += [f"suppression for {s.describe()} matched nothing; consider removing it"
                 for s in live if s.matched == 0]
    return Applied(active, suppressed, warnings)
