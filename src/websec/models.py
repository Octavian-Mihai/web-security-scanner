from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {names})") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    cwe: int
    owasp: str  # OWASP Top 10 2021 category, e.g. "A05:2021 Security Misconfiguration"

    @property
    def cwe_id(self) -> str:
        return f"CWE-{self.cwe}"

    @property
    def cwe_uri(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.cwe}.html"

    @property
    def owasp_uri(self) -> str:
        # "A05:2021 Security Misconfiguration" -> A05_2021-Security_Misconfiguration
        code, title = self.owasp.split(" ", 1)
        return f"https://owasp.org/Top10/{code.replace(':', '_')}-{title.replace(' ', '_')}/"


@dataclass
class Finding:
    rule: Rule
    url: str
    message: str
    evidence: str = ""
    # Disambiguates multiple findings of one rule on one URL (e.g. one per cookie).
    key: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule.id}|{self.url}|{self.key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
