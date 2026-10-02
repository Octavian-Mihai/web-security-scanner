# Security policy

## Reporting a vulnerability in websec-scanner

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security tab -> "Report a vulnerability"** on this repository. Include the version
(`websec --version`), what you observed, and a minimal reproduction.

You can expect an acknowledgement within a few days. Fixes ship as a patch release and are
credited in the changelog unless you prefer otherwise.

## Scope

In scope: the scanner's own code, the GitHub Action (`action.yml`), and the release workflow,
for example command injection through Action inputs, unsafe handling of scanned content,
secret leakage into reports, or scope-guard bypasses (the scanner contacting a host it was not
asked to).

Out of scope: findings the scanner reports about *other* sites; those belong to their owners.

## Responsible use

Only scan systems you own or are explicitly authorised to test. The default checks are passive
(plus a few dozen harmless GET requests for the `exposure` group), but unauthorised scanning
can still be illegal. Use `--delay` and `--allow-host` to keep scans polite and in scope.
