# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && mypy && pytest        # the same gates CI runs
```

## Adding a rule

1. Add it to `src/websec/rules.py` with a severity, **CWE** and **OWASP Top 10 (2021)**
   category. Pick the CWE that best names the *weakness*, not the symptom.
2. Implement the detection in the matching `src/websec/checks/*.py` group.
3. Add a vulnerable fixture **and a clean twin** in `tests/test_rules_golden.py`.
   `test_every_rule_has_a_test` fails if a rule ID appears in no test.
4. If the rule could plausibly fire on normal sites, add a case to `tests/corpus/` so it can't
   regress into a false positive.
5. Add a line to `CHANGELOG.md`.

## Principles

- **False positives cost more than missed findings.** Validate response *content*, not status
  codes (SPAs return 200 for everything). Never echo secrets into reports.
- **Stay passive.** New checks should read what the server volunteers; any extra request needs
  a justification and must honour the scope guard and rate limiter.
- **A broken check must not hide the others** and a failed scan must never look clean.

## Releases

Bump `version` in `pyproject.toml` and `src/websec/__init__.py`, add the changelog section,
then push a tag `vX.Y.Z`. The release workflow does the rest.
