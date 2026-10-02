# Design decisions and trade-offs

## Why passive, and what that costs

The scanner reads what a server volunteers (headers, cookies, certificates, HTML) and makes a
small, fixed set of extra GETs (`exposure` group). It sends no payloads, so it is safe to run
against staging on every pull request and can't corrupt data. The price is coverage: it cannot
find injection, broken authentication or logic flaws. It is a fast **guardrail** against
regressions in configuration, not a replacement for a DAST tool or a pen test.

## Findings are data; the catalog is the source of truth

Every rule lives once in `rules.py` (id, severity, CWE, OWASP category, remediation). The
console report, markdown, SARIF rule metadata and `websec rules` are all derived from it, so
the CWE/OWASP mapping can't drift between outputs. Severity is **per rule, not per finding**:
GitHub's Security tab takes severity from the rule's `security-severity`, so a per-finding
override would show one severity in our report and another in GitHub. That is why plain HTTP
on localhost is its own rule (WSS038, low) rather than a downgraded WSS030.

## SARIF for GitHub

- `security-severity` (not `level`) drives the critical/high/medium/low badge.
- Web findings have no source file, but GitHub wants a file location. Results are anchored to a
  real repo file (default `README.md`) with the URL as a logical location and in the message.
  Trade-off: no inline PR annotations, which a web finding couldn't honestly have.
- `partialFingerprints` (hash of rule + URL + key) let GitHub track an alert across runs.
- Suppressed findings are **omitted** from SARIF rather than marked with SARIF `suppressions`:
  omission makes GitHub close the alert on the next upload, which is the behaviour teams expect.
  They remain visible in the console, markdown and JSON output with their reasons.

## Exit codes: 0 / 1 / 2

1 means "the gate tripped", 2 means "the scan did not produce trustworthy results". An outage
or a misconfigured URL must never pass a build as clean, so errors never exit 0.

## False positives cost more than misses

A scanner that cries wolf gets its job disabled. Hence: exposure checks validate **content**
(`ref: refs/` in `/.git/HEAD`, KEY=value lines in `.env`, a real index title), because SPAs
answer 200 to everything; secrets are never echoed; cookie `Secure` is only demanded on HTTPS
(browsers ignore it on HTTP); legacy-TLS detection is "inconclusive, not a finding" when the
local OpenSSL can't speak the old protocol. A hand-written corpus of well-configured sites
(`tests/corpus/`) must scan clean.

## Scope safety

A scanner is a tool you can point at things. Only hosts of the given URLs (plus explicit
`--allow-host`) are contactable. Redirects are followed manually so an off-scope hop is refused
**before** a request is made; `requests` would have followed it. The crawler is same-origin,
asset-skipping and honours robots.txt.

## Baselines with a conscience

A gate nobody can tune gets turned off. `.websec.toml` suppressions need a **reason**, can
**expire**, and an expired or never-matching entry is reported so suppressions can't quietly
outlive their justification.

## TLS

The leaf certificate is fetched *unvalidated* and parsed (`cryptography`) so expiry, key size
and signature algorithm are reported even for an untrusted certificate; validation is a second,
separate handshake against `certifi`'s trust store (the same one `requests` uses). Known gaps:
leaf only (no chain or OCSP stapling analysis), no cipher-suite enumeration.

## Concurrency

Only crawling is concurrent (a thread pool over one BFS level at a time), with a single global
rate limiter shared by all sessions so `--delay` is a hard minimum across threads. Results are
merged on the main thread, so no shared mutable state is touched by workers.

## Supply chain (this is a security tool)

Actions are pinned to commit SHAs and kept current by Dependabot; Action inputs reach the shell
only through `env:`; CI runs CodeQL, bandit and pip-audit on this repo; the release workflow
supports PyPI trusted publishing so no long-lived token exists.

## What I would do next

Authenticated scanning (a session cookie or bearer header supplied via secret), per-rule
configuration of thresholds, OCSP/chain analysis, a `--diff-base` mode that fetches the base
branch's alerts for true "new findings only" PR gating, and a plugin interface for custom rules.
