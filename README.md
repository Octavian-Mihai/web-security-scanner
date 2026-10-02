# websec-scanner

A passive web security scanner built for CI. It checks security headers, cookie flags,
TLS configuration and CORS, maps every finding to a **CWE** and an **OWASP Top 10 (2021)**
category, writes **SARIF 2.1.0** so results show up in GitHub's **Security tab**, and ships
as a **GitHub Action** that fails the build above a severity threshold.

```
HIGH     WSS030  Site served over plain HTTP
         Target is served over plain HTTP and no HTTPS endpoint was found.
         CWE-319 | OWASP A02:2021 Cryptographic Failures | http://localhost:3000
MEDIUM   WSS001  Missing Content-Security-Policy
         CWE-693 | OWASP A05:2021 Security Misconfiguration | http://localhost:3000/
MEDIUM   WSS042  Directory listing enabled at /ftp/
         CWE-548 | OWASP A05:2021 Security Misconfiguration | http://localhost:3000/ftp/
```

## Use it as a GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # needed to upload SARIF

steps:
  - uses: actions/checkout@v4
  - uses: Octavian-Mihai/web-security-scanner@v1
    with:
      url: https://staging.example.com
      fail-on: high          # critical | high | medium | low | info | none
      ignore: WSS008         # optional: suppress rule IDs
```

The SARIF upload runs under `always()`, so findings reach the Security tab even when the
gate fails the build. Outputs: `findings`, `highest-severity`, `sarif-file`. A markdown
table is added to the run summary.

## Use it as a CLI

```bash
pip install -e .
websec scan https://example.com --sarif out.sarif --fail-on medium
websec rules          # every rule with severity, CWE, OWASP
```

| Exit code | Meaning |
|---|---|
| 0 | Scan completed; nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` (the CI gate) |
| 2 | Scan error (unreachable target, bad arguments). Deliberately **not** 0, so an outage can't pass a build as "clean" |

## Checks

| Group | Rules | What it does |
|---|---|---|
| `headers` | WSS001-009 | CSP (missing/weak), HSTS (missing/short), clickjacking, nosniff, Referrer-Policy, Permissions-Policy, version disclosure |
| `cookies` | WSS020-022 | Secure / HttpOnly / SameSite, across every hop of a redirect chain |
| `cors` | WSS010-011 | Wildcard origin; reflected origin + credentials |
| `tls` | WSS030-035 | Plain HTTP, no HTTP-to-HTTPS redirect, TLS 1.0/1.1 accepted, expired / soon-to-expire / untrusted certificate |
| `exposure` | WSS040-042 | `/.git/HEAD`, `/.env`, directory listings. **Light probing**: a handful of GETs; drop it with `--checks headers,cookies,cors,tls` |

Severity is fixed per rule in [`rules.py`](src/websec/rules.py), the single source of truth
for the CWE/OWASP mapping, SARIF rule metadata and the console report.

## Design notes

- **SARIF for GitHub.** `security-severity` is set per rule (that, not `level`, drives the
  critical/high/medium/low badge). CWE tags use GitHub's `external/cwe/cwe-N` form.
  `partialFingerprints` keep alerts stable across runs. Web findings have no source file, so
  results are anchored to a real repo file (`--sarif-anchor`, default `README.md`) and the
  scanned URL is kept as a logical location and in the message.
- **No false positives from SPAs.** Single-page apps return `200` for every path, so exposure
  checks validate *content* (`ref: refs/` in `.git/HEAD`, `KEY=value` lines in `.env`, a real
  directory-index title), never status codes. Secrets are never echoed into reports.
- **TLS without extra dependencies.** Standard-library `ssl` plus `certifi` (the same trust
  store as `requests`). A certificate failure doesn't abort the scan: the page is still
  fetched so header and cookie findings aren't lost.
- **One broken check can't hide the rest.** Check failures are recorded as SARIF
  `toolExecutionNotifications` and force exit code 2.
- **Action inputs go through `env:`**, never interpolated into the shell script.

## Testing against OWASP Juice Shop

```bash
docker compose up -d juice-shop
websec scan http://localhost:3000 --sarif results/juice.sarif
python scripts/assert_findings.py results/juice.sarif WSS030 WSS001 WSS010 WSS042 --forbid WSS006 WSS005
```

The assert script also validates the SARIF against the official 2.1.0 schema. CI
([`ci.yml`](.github/workflows/ci.yml)) runs the Action itself against a Juice Shop service
container twice: with `fail-on: critical` (must pass and upload SARIF) and `fail-on: high`
(must fail the build; the job asserts that it did). Unit tests (`pytest`) use local HTTP and
self-signed HTTPS servers; no external network needed.

## Limitations

- Passive and shallow by design: no crawling, no authentication, no payload injection. It
  checks the URLs you give it. It complements, not replaces, a DAST tool such as ZAP.
- Legacy-TLS detection pins a handshake to TLS 1.0/1.1. If the local OpenSSL can't speak
  them, the result is "inconclusive" (no finding) rather than a false alarm.
- Plain-HTTP detection on a URL with an explicit port assumes no HTTPS counterpart exists.
- Certificate checks use the leaf certificate only (no chain or key-strength analysis).

## Ideas for next steps

Baseline files for accepted risks, a crawler for per-page cookie/header checks, SRI and
mixed-content checks, a cipher-suite check, publishing the Action with a floating `v1` tag.
