import json
import os
import shutil

import pytest

from conftest import live, needs_asan
from reportsieve.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "reportsieve 0.1.0" in capsys.readouterr().out


def test_triage_json_uses_policy_and_known(example, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(example)
    assert main(["triage", "reports/", "--repo", ".", "--state", str(tmp_path / "st"), "-f", "json"]) == 0
    d = json.loads(capsys.readouterr().out)
    v = {r["id"]: r["verdict"] for r in d["reports"]}
    assert v["r04-count-wrap-known"] == "known"          # known/ from reportsieve.json
    assert v["r06-bench-dos"] == "out-of-scope"          # out_of_scope.paths from reportsieve.json
    assert v["r05-rce-callback"] == "likely-noise"
    assert d["read_first"][0] in ("r01-heap-overflow-parse-header", "r08-uaf-hdr-remove")
    r07 = next(r for r in d["reports"] if r["id"] == "r07-hdr-get-null")
    assert r07["ask_reporter_for"]


def test_triage_text_and_markdown_output(example, tmp_path, capsys):
    os.chdir(example)
    assert main(["triage", "reports/", "--repo", ".", "--state", str(tmp_path / "st"), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "8 reports:" in out and "duplicate of r01-heap-overflow-parse-header" in out
    md = tmp_path / "triage.md"
    assert main(["triage", "reports/", "--repo", ".", "--state", str(tmp_path / "st"), "-f", "markdown", "-o", str(md), "-q"]) == 0
    text = md.read_text()
    assert text.startswith("# Security inbox triage") and "| verdict |" in text and "**Ask the reporter for:**" in text


def test_fail_on(example, tmp_path):
    os.chdir(example)
    assert main(["triage", "reports/", "--state", str(tmp_path / "s"), "--fail-on", "likely-valid", "-q"]) == 1
    assert main(["triage", "reports/r05-rce-callback.md", "--state", str(tmp_path / "s"), "--fail-on", "likely-valid", "-q"]) == 0


def test_record_history_then_new_arrival_is_duplicate(tmp_path, capsys):
    os.chdir(tmp_path)
    (tmp_path / "a.md").write_text("Subject: overflow in foo_parse()\nfoo_parse() overflows the buffer, version 1.0.0\n")
    (tmp_path / "b.md").write_text("Subject: foo_parse() heap overflow\nheap overflow in foo_parse() with long input\n")
    assert main(["triage", "a.md", "--record", "-q"]) == 0
    capsys.readouterr()
    assert main(["triage", "b.md", "-f", "json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["reports"][0]["duplicate_of"]["id"] == "a"


def test_eml_and_json_inputs(tmp_path, capsys):
    (tmp_path / "m.eml").write_text("From: x@y.z\nSubject: SSRF in fetch_url()\nDate: Mon, 2 Nov 2026 10:00:00 +0000\n"
                                    "Content-Type: text/plain\n\nfetch_url() follows redirects to 169.254.169.254 (SSRF).\n")
    (tmp_path / "h1.json").write_text(json.dumps([{"id": "h1-77", "title": "XSS in search", "vulnerability_information": "reflected xss in search_page()"}]))
    assert main(["triage", str(tmp_path), "-f", "json", "--state", str(tmp_path / "s")]) == 0
    d = json.loads(capsys.readouterr().out)
    ids = {r["id"]: r for r in d["reports"]}
    assert "CWE-918" in ids["m"]["cwes"] and ids["m"]["title"] == "SSRF in fetch_url()"
    assert "CWE-79" in ids["h1-77"]["cwes"]


def test_brief_and_init(example, tmp_path, capsys):
    os.chdir(example)
    assert main(["brief", "reports/", "--id", "r05-rce-callback", "--repo", ".", "--state", str(tmp_path / "s")]) == 0
    out = capsys.readouterr().out
    assert out.startswith("## r05-rce-callback") and "Not found in repo" in out
    assert main(["brief", "reports/", "--id", "nope", "--state", str(tmp_path / "s")]) == 2
    os.chdir(tmp_path)
    assert main(["init"]) == 0 and json.load(open("reportsieve.json"))["out_of_scope"]["paths"]
    assert main(["init"]) == 1


def test_repro_show(example, capsys):
    os.chdir(example)
    assert main(["repro", "reports/r08-uaf-hdr-remove.md", "--show"]) == 0
    out = capsys.readouterr().out
    assert "poc.c" in out and "src/tinyhdr.c" in out   # template from reportsieve.json


def test_missing_source_is_error(capsys):
    assert main(["triage", "/no/such/dir"]) == 2


@needs_asan
def test_triage_with_repro_end_to_end(example, tmp_path, capsys):
    os.chdir(example)
    st = str(tmp_path / "st")
    assert main(["triage", "reports/", "--repo", ".", "--state", st, "--repro", "-f", "json", "-q"]) == 0
    d = json.loads(capsys.readouterr().out)
    v = {r["id"]: r for r in d["reports"]}
    assert v["r01-heap-overflow-parse-header"]["verdict"] == "confirmed"
    assert v["r08-uaf-hdr-remove"]["verdict"] == "confirmed"
    assert v["r02-ai-writeup-same-overflow"]["duplicate_of"]["similarity"] == 1.0
    assert sorted(os.listdir(os.path.join(st, "repro"))) == ["r01-heap-overflow-parse-header.json", "r02-ai-writeup-same-overflow.json", "r08-uaf-hdr-remove.json"]
    # cached results are reused without --repro
    assert main(["triage", "reports/", "--state", st, "-f", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["reports"][0]["verdict"] == "confirmed"


@live
def test_live_osv_known(tmp_path, capsys):
    (tmp_path / "r.md").write_text("Subject: Proxy-Authorization header leaked on redirect to different host\n"
                                   "requests leaks the Proxy-Authorization header to the destination after a redirect. Version 2.31.0.\n")
    assert main(["triage", str(tmp_path / "r.md"), "--known", "osv:PyPI/requests", "-f", "json", "--state", str(tmp_path / "s")]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["reports"][0]["verdict"] == "known"


@live
def test_live_github_published_advisories(tmp_path, capsys):
    (tmp_path / "r.md").write_text("Subject: Proxy-Authorization header leaked on redirect\nThe Proxy-Authorization header leaks to the new host.\n")
    assert main(["triage", str(tmp_path / "r.md"), "--known", "gh:psf/requests", "-f", "json", "--state", str(tmp_path / "s")]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["reports"][0]["known_as"]["id"].startswith("GHSA-")
