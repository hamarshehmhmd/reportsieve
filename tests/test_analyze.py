import os

from reportsieve.analyze import Policy, RepoIndex, ReproResult, assess, check_refs, similarity
from reportsieve.extract import Signature, parse_report
from reportsieve.sources import load_known, load_paths


def by_id(items):
    return {a.report.id: a for a in items}


def test_example_inbox_without_repro(example):
    reports = load_paths([os.path.join(example, "reports")])
    known = load_known([os.path.join(example, "known")])
    pol = Policy(oos_paths=["examples/*"])
    items = by_id(assess(reports, known=known, policy=pol, repo=RepoIndex(example)))
    assert items["r01-heap-overflow-parse-header"].verdict == "likely-valid"
    assert items["r08-uaf-hdr-remove"].verdict == "likely-valid"
    assert items["r02-ai-writeup-same-overflow"].verdict == "duplicate"
    assert items["r02-ai-writeup-same-overflow"].duplicate_of.other == "r01-heap-overflow-parse-header"
    assert items["r03-short-dup-no-poc"].duplicate_of.other == "r01-heap-overflow-parse-header"
    assert items["r04-count-wrap-known"].verdict == "known"
    assert items["r04-count-wrap-known"].known_as.other == "GHSA-demo-q7h2-x3kw"
    assert items["r06-bench-dos"].verdict == "out-of-scope"
    assert items["r07-hdr-get-null"].verdict == "needs-info"
    noise = items["r05-rce-callback"]
    assert noise.verdict == "likely-noise" and noise.score == 0
    assert "function tinyhdr_exec_callback()" in noise.missing_refs and "file src/callback.c" in noise.missing_refs
    # the AI write-up of a real bug is a duplicate, not noise
    assert items["r02-ai-writeup-same-overflow"].score >= 40


def test_repro_results_confirm_and_dedupe_by_signature(example):
    reports = load_paths([os.path.join(example, "reports")])
    sig = Signature("asan:heap-buffer-overflow", ["parse_header"])
    repro = {
        "r01-heap-overflow-parse-header": ReproResult("reproduced", sig, 1, "bwrap"),
        "r02-ai-writeup-same-overflow": ReproResult("reproduced", sig, 1, "bwrap"),
        "r08-uaf-hdr-remove": ReproResult("no-crash", None, 0, "bwrap"),
    }
    items = by_id(assess(reports, policy=Policy(oos_paths=["examples/*"]), repro=repro))
    assert items["r01-heap-overflow-parse-header"].verdict == "confirmed"
    d = items["r02-ai-writeup-same-overflow"].duplicate_of
    assert d.score == 1.0 and "same crash signature" in d.why[0]
    r08 = items["r08-uaf-hdr-remove"]
    assert any("without a crash" in t for _, t in r08.reasons) and r08.verdict != "confirmed"


def test_duplicate_repro_confirms_canonical():
    a = parse_report("Subject: overflow in foo_parse()\nfoo_parse() overflows the buffer on long input. 1.2.3", "a")
    b = parse_report("Subject: heap overflow foo_parse\nfoo_parse() heap overflow.\n```c\nint main(){}\n```\n", "b")
    items = by_id(assess([a, b], repro={"b": ReproResult("reproduced", Signature("asan:heap-buffer-overflow", ["foo_parse"]))}))
    assert items["b"].verdict == "duplicate" and items["a"].verdict == "confirmed"


def test_different_bugs_in_same_function_are_not_duplicates():
    a = parse_report("Subject: use-after-free in hdr_remove()\nhdr_remove() frees the node then reads h->next.\n"
                     "```\n==1==ERROR: AddressSanitizer: heap-use-after-free on address\n    #0 0x1 in hdr_remove src/t.c:67\n```", "a")
    b = parse_report("Subject: hdr_remove() leaks memory when name matches twice\nhdr_remove() memory leak, "
                     "LeakSanitizer: detected memory leaks\n    #0 0x1 in malloc x\n    #1 0x2 in hdr_remove src/t.c:60\n", "b")
    s, why = similarity(a, b)
    assert s < 0.55, (s, why)


def test_reworded_duplicate_without_shared_code_tokens():
    a = parse_report("Subject: Proxy-Authorization header leaked on redirect\nrequests sends Proxy-Authorization to the new host after a redirect", "a")
    b = parse_report("# Unintended leak of Proxy-Authorization header in requests\nThe Proxy-Authorization header is leaked to destination servers when redirected", "b")
    s, _ = similarity(a, b)
    assert s >= 0.55


def test_out_of_scope_by_cwe_and_keyword():
    r = parse_report("Subject: ReDoS in the date regex\ncatastrophic backtracking in parse_date()", "x")
    pol = Policy(oos_cwes=["CWE-1333"])
    assert assess([r], policy=pol)[0].verdict == "out-of-scope"
    r2 = parse_report("Subject: Self-XSS in the console\nself-xss when you paste code", "y")
    assert assess([r2], policy=Policy(oos_keywords=["self-xss"]))[0].verdict == "out-of-scope"


def test_check_refs_line_beyond_end_and_poc_local_functions(example):
    r = parse_report("parse_header() at src/tinyhdr.c:400 and helper_in_poc() is defined in the PoC\n"
                     "```c\nstatic int helper_in_poc(void) { return 0; }\n```\n", "x")
    miss = check_refs(r, RepoIndex(example))
    assert any("src/tinyhdr.c:400" in m and "87 lines" in m for m in miss)
    assert not any("helper_in_poc" in m for m in miss)
    assert not any("parse_header" in m for m in miss)


def test_history_dedupes_new_arrivals():
    old = parse_report("Subject: overflow in foo_parse()\nfoo_parse() overflows the buffer, version 1.0.0", "old")
    new = parse_report("Subject: foo_parse() heap overflow\nheap overflow in foo_parse() with long input", "new")
    a = assess([new], history=[old])[0]
    assert a.verdict == "duplicate" and a.duplicate_of.other == "old"


def test_policy_from_dict():
    p = Policy.from_dict({"out_of_scope": {"paths": ["tests/*"], "cwes": ["cwe-400"]}, "duplicate_threshold": 0.7})
    assert p.oos_cwes == ["CWE-400"] and p.threshold == 0.7 and p.oos_paths == ["tests/*"]


def test_critical_claim_without_evidence_scores_low():
    r = parse_report("Subject: RCE (critical)\nThis could potentially allow remote code execution. CVSS 9.8. "
                     "I hope this message finds you well. It is important to note the robust risk. In conclusion, fix it.", "x")
    a = assess([r])[0]
    assert a.verdict == "likely-noise" and a.score == 0
    assert a.suggested_severity in ("high", "medium (unproven)", "unclear")
