from reportsieve.extract import parse_report, parse_signature

ASAN = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60 at pc 0x1
WRITE of size 151 at 0x506000000060 thread T0
    #0 0x7fb2700f27ee in memcpy ../../../../src/libsanitizer/sanitizer_common/x.inc:115
    #1 0x55e5ae1416b3 in parse_header src/tinyhdr.c:29
    #2 0x55e5ae14249a in main /tmp/poc1.c:9

0x506000000060 is located 0 bytes after 64-byte region
allocated by thread T0 here:
    #0 0x7fb2700f4c57 in malloc ../../asan_malloc_linux.cpp:69
    #1 0x55e5ae141517 in other_fn src/tinyhdr.c:25
"""


def test_asan_signature_uses_first_stack_and_skips_interceptors():
    s = parse_signature(ASAN)
    assert s.kind == "asan:heap-buffer-overflow"
    assert s.frames == ["parse_header"]
    assert str(s) == "asan:heap-buffer-overflow in parse_header"


def test_ubsan_signature():
    t = "src/x.c:10:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented\n    #0 0x1 in add_len src/x.c:10\n    #1 0x2 in main a.c:3\n"
    s = parse_signature(t)
    assert s.kind == "ubsan:signed-integer-overflow"
    assert s.frames == ["add_len"]


def test_gdb_python_js_and_segv_signatures():
    g = parse_signature("Program received signal SIGSEGV, Segmentation fault.\n#0  0x000 in hdr_get (l=0x0) at tinyhdr.c:80\n#1  0x1 in main () at poc.c:5\n")
    assert (g.kind, g.frames) == ("segv", ["hdr_get"])
    p = parse_signature('Traceback (most recent call last):\n  File "a.py", line 3, in <module>\n  File "/x/lib.py", line 9, in load\nValueError: bad\n')
    assert (p.kind, p.frames) == ("python:ValueError", ["load"])
    j = parse_signature("RangeError: Maximum call stack size exceeded\n    at walk (/app/lib/walk.js:10:3)\n    at Object.parse (/app/lib/index.js:4:1)\n")
    assert j.kind == "js:RangeError" and j.frames[0] == "walk"
    assert parse_signature("everything is fine") is None


REPORT = """Subject: Re: Heap overflow in parse_header() via long `X-Forwarded-For`
From: Lena <lena@example.net>
Date: 2026-10-28

parse_header() in src/tinyhdr.c:29 copies the value without a bound. Tested on tinyhdr 1.4.2 (commit 3f9c2ab).
Also see `hdr_list_add`. CVSS score: 8.1. Uses --max-headers.

Impact: attacker can corrupt the heap.

Steps to reproduce: save as poc.c

```c
#include <string.h>
#include "tinyhdr.h"
int main(void){ return 0; }
```

```console
$ cc poc.c -o poc
$ ./poc
Segmentation fault
```
"""


def test_report_fields():
    r = parse_report(REPORT, "r1", "x.md")
    assert r.title == "Heap overflow in parse_header() via long `X-Forwarded-For`"
    assert r.reporter.startswith("Lena") and r.date == "2026-10-28"
    assert "CWE-787" in r.cwes
    assert "src/tinyhdr.c" in r.files and ("src/tinyhdr.c", 29) in r.file_lines
    assert "string.h" not in r.files and "tinyhdr.h" not in r.files  # includes inside PoC code are not citations
    assert {"parse_header", "hdr_list_add"} <= r.functions
    assert {"1.4.2", "3f9c2ab"} <= r.versions
    assert r.cvss_score == 8.1 and r.severity_claim == "high"
    assert "x-forwarded-for" in r.entities and "--max-headers" in r.entities
    assert r.has_steps and r.has_impact
    langs = [(b.lang, b.filename) for b in r.blocks]
    assert langs == [("c", "poc.c"), ("sh", None)]


def test_classifier_covers_common_classes():
    cases = {
        "use after free in foo": "CWE-416", "double free of buf": "CWE-415", "integer overflow in len": "CWE-190",
        "NULL pointer\ndereference": "CWE-476", "path traversal via ../../etc/passwd": "CWE-22",
        "SSRF via redirect": "CWE-918", "prototype pollution in merge": "CWE-1321", "ReDoS in the email regex": "CWE-1333",
        "request smuggling with chunked TE": "CWE-444", "leaks the Proxy-Authorization header": "CWE-200",
        "explicit CWE-1234 mention": "CWE-1234", "reads out-of-bounds read past end": "CWE-125",
    }
    for text, cwe in cases.items():
        assert cwe in parse_report(text, "x").cwes, text


def test_memory_leak_is_not_info_leak():
    r = parse_report("memory leak in hdr_list_free, LeakSanitizer: detected memory leaks", "x")
    assert "CWE-401" in r.cwes and "CWE-200" not in r.cwes


def test_heading_title_and_no_versions_from_cvss_or_ips():
    r = parse_report("# Bad thing\n\nCVSS score: 9.8, host 10.0.0.1 crashes\n", "x")
    assert r.title == "Bad thing"
    assert r.versions == set()
    assert r.cvss_score == 9.8 and r.severity_claim == "critical"


def test_crash_log_in_console_block_is_output_not_poc():
    r = parse_report("```console\n" + ASAN + "```\n", "x")
    assert r.poc_blocks == [] and r.signature.frames == ["parse_header"]
