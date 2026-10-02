from __future__ import annotations

import json

from websec.cli import main
from websec.report import render_console


def test_json_html_markdown_outputs(site, tmp_path):
    site.routes["*"] = (200, [], "<html></html>")
    j, h, m = tmp_path / "r.json", tmp_path / "r.html", tmp_path / "r.md"
    main(["scan", site.url, "--checks", "headers", "--fail-on", "none",
          "--json", str(j), "--html", str(h), "--markdown", str(m)])
    doc = json.loads(j.read_text())
    assert doc["counts"]["medium"] >= 1 and doc["findings"][0]["fingerprint"]
    assert "<table>" in h.read_text() and "WSS001" in h.read_text()
    assert "| Severity |" in m.read_text()


def test_html_report_escapes_content(site, tmp_path):
    site.routes["*"] = (200, [("Server", "<script>alert(1)</script>/1.0")], "")
    h = tmp_path / "r.html"
    main(["scan", site.url, "--checks", "headers", "--fail-on", "none", "--html", str(h)])
    assert "<script>alert(1)" not in h.read_text()


def test_compare_with_marks_new_and_counts_fixed(site, tmp_path, capsys):
    prior = tmp_path / "prior.sarif"
    site.routes["*"] = (200, [("Referrer-Policy", "no-referrer")], "<html></html>")
    main(["scan", site.url, "--checks", "headers", "--fail-on", "none", "--sarif", str(prior)])
    # The site then gets worse in one way (drops nosniff handling is implicit) and better in another.
    site.routes["*"] = (200, [("X-Content-Type-Options", "nosniff")], "<html></html>")
    md = tmp_path / "now.md"
    main(["scan", site.url, "--checks", "headers", "--fail-on", "none",
          "--compare-with", str(prior), "--markdown", str(md)])
    out = capsys.readouterr().out
    assert "[NEW]" in out and "WSS007" in out  # Referrer-Policy was removed => new
    text = md.read_text()
    assert "(new)" in text and "Fixed since comparison scan: **1**" in text  # nosniff now fixed


def test_compare_with_missing_file_is_error(site, tmp_path):
    assert main(["scan", site.url, "--compare-with", str(tmp_path / "nope.sarif")]) == 2


def test_failed_scan_never_reads_as_clean(capsys):
    assert main(["scan", "http://127.0.0.1:1", "--timeout", "2"]) == 2
    out = capsys.readouterr().out
    assert "SCAN FAILED" in out and "No findings" not in out


def test_partial_scan_is_labelled(capsys):
    text = render_console([], errors=["boom"])
    assert "SCAN FAILED" in text
