from __future__ import annotations

import json
from pathlib import Path

import pytest

from websec.checks import CHECKS
from websec.scanner import ScanOptions, scan

CORPUS = sorted((Path(__file__).parent / "corpus").glob("*.json"))


@pytest.mark.parametrize("path", CORPUS, ids=[p.stem for p in CORPUS])
def test_well_configured_site_is_clean(path, make_site, tmp_path):
    from conftest import make_cert

    spec = json.loads(path.read_text())
    site = make_site(make_cert(tmp_path) if spec["https"] else None)
    for route, r in spec["routes"].items():
        headers = [(k, v) for k, v in r["headers"].items()]
        site.routes[route] = (r["status"], headers, r["body"])
    result = scan(site.url, {g: CHECKS[g] for g in spec["groups"]}, ScanOptions())
    assert not result.errors
    assert {f.rule.id for f in result.findings} == set(spec["expect"]), [
        (f.rule.id, f.message) for f in result.findings]


def test_corpus_is_not_empty():
    assert len(CORPUS) >= 6
