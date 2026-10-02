# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[SemVer](https://semver.org/). The release workflow publishes the section matching the tag.

## [1.1.1] - 2026-10-02

### Changed
- The Action now uses `actions/setup-python` v7 (it was v6), picking up the Node 24 runtime;
  the repository's workflows are updated to match (checkout v7, upload-artifact v7,
  download-artifact v8). All pinned to commit SHAs. No scanner behaviour changes.

## [1.1.0] - 2026-10-02

### Added
- **Baseline file** (`.websec.toml`): per-rule, per-URL suppressions that require a reason and
  can expire. Expired and unused entries are reported.
- **Crawler** (`--crawl-depth`, `--max-pages`, `--workers`): same-origin, robots.txt-aware;
  site-wide findings are collapsed into one.
- **Scope safety**: only hosts of the given URLs (plus `--allow-host`) may be contacted;
  redirects are followed by hand and an off-scope hop aborts before it is requested.
- **Rate limiting** (`--delay`).
- **Ten new rules** (33 total): SRI (WSS050), mixed content (WSS051), cookie prefix misuse
  (WSS023), `security.txt` (WSS052), JWT in URL (WSS053), exposed source maps (WSS043),
  exposed management endpoints (WSS044), weak certificate key (WSS036), weak certificate
  signature (WSS037), loopback plain HTTP (WSS038).
- **TLS depth**: certificate is parsed directly, so expiry, key size and signature algorithm
  are reported even for untrusted certificates.
- **Outputs**: JSON, HTML and markdown reports; `--compare-with` marks findings new/fixed
  against an earlier SARIF; Action inputs for all of the above plus an optional PR comment.
- Typed package (`py.typed`, `mypy --strict`), 90% coverage gate, property-based tests,
  a per-rule golden suite and a false-positive corpus.
- CI: SHA-pinned actions, Dependabot, CodeQL, bandit, pip-audit, package build check, and a
  consumer test that runs the published Action from outside the repository.
- Release workflow: builds, creates the GitHub Release from this file, moves the `v1` tag and
  optionally publishes to PyPI via trusted publishing.

### Changed
- Plain HTTP on a loopback host is now **WSS038 (low)** instead of WSS030 (high), so local and
  CI-service targets don't fail the default gate. Non-loopback plain HTTP is still high.
- Requires Python 3.11+ (stdlib `tomllib`).
- A failed scan now prints `SCAN FAILED`/`SCAN INCOMPLETE` instead of "No findings.".
- `cryptography` is now a dependency.

### Fixed
- TLS checks no longer depend on the host Python shipping CA certificates.

## [1.0.0] - 2026-10-02

- Initial release: 23 passive rules mapped to CWE and OWASP Top 10 (2021), SARIF 2.1.0 output,
  composite GitHub Action with a severity gate, CI against OWASP Juice Shop.
