import os
import sys

import pytest

from conftest import needs_asan, needs_bwrap, needs_docker
from reportsieve.extract import parse_report
from reportsieve.repro import ReproError, plan, run

SEGV_PY = "Subject: crash\n\n```python\nimport ctypes\nctypes.string_at(0)\n```\n"


def test_plan_console_prompts_and_filename_hint():
    r = parse_report("save as exploit.c:\n```c\nint main(){return 0;}\n```\n```console\n$ cc exploit.c -o x\n$ ./x\nSegmentation fault\n```\n", "x")
    files, script = plan(r)
    assert list(files) == ["exploit.c"]
    assert script == "cc exploit.c -o x\n./x"


def test_plan_template_and_override():
    r = parse_report("```python\nprint(1)\n```\n", "x")
    assert plan(r) == ({"poc.py": "print(1)\n"}, "python3 poc.py")
    assert plan(r, {"py": "python3 -X dev {poc}"})[1] == "python3 -X dev poc.py"
    assert plan(r, cmd="pytest {poc}")[1] == "pytest poc.py"


def test_plan_without_poc_raises():
    with pytest.raises(ReproError):
        plan(parse_report("no code here", "x"))


def test_no_poc_is_skipped():
    assert run(parse_report("just words", "x"), sandbox="local", unsafe_local=True).status == "skipped"


def test_local_runner_refused_without_flag():
    res = run(parse_report(SEGV_PY, "x"), sandbox="local")
    assert res.status == "skipped" and "--unsafe-local" in res.note


def test_docker_needs_image():
    res = run(parse_report(SEGV_PY, "x"), sandbox="docker")
    assert res.status == "skipped"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
def test_local_runner_detects_signal_crash():
    res = run(parse_report(SEGV_PY, "x"), sandbox="local", unsafe_local=True, timeout=30)
    assert res.status == "reproduced", res.output_tail


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
def test_local_runner_no_crash_and_expect():
    r = parse_report("```sh\necho token=SECRET123\n```\n", "x")
    assert run(r, sandbox="local", unsafe_local=True).status == "no-crash"
    res = run(r, sandbox="local", unsafe_local=True, expect=r"token=\w+")
    assert res.status == "reproduced"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
def test_timeout_kills_hung_poc():
    r = parse_report("```sh\nsleep 30\n```\n", "x")
    res = run(r, sandbox="local", unsafe_local=True, timeout=2)
    assert res.status == "timeout" and res.seconds < 15


@needs_bwrap
def test_bwrap_has_no_network_and_no_home(tmp_path, monkeypatch):
    secret = os.path.join(os.path.expanduser("~"), ".reportsieve-test-secret")
    with open(secret, "w") as fh:
        fh.write("s3cr3t")
    try:
        code = (
            "import os, socket\n"
            f"print('HOME_SECRET', os.path.exists({secret!r}))\n"
            "try:\n    socket.create_connection(('1.1.1.1', 53), timeout=3); print('NET', True)\n"
            "except OSError:\n    print('NET', False)\n"
            "print('ENV_TOKEN', 'GITHUB_TOKEN' in os.environ)\n"
        )
        monkeypatch.setenv("GITHUB_TOKEN", "should-not-leak")
        r = parse_report("```python\n" + code + "```\n", "x")
        res = run(r, sandbox="bwrap", timeout=30)
        assert "HOME_SECRET False" in res.output_tail
        assert "NET False" in res.output_tail
        assert "ENV_TOKEN False" in res.output_tail
    finally:
        os.remove(secret)


@needs_bwrap
def test_bwrap_repo_copy_is_writable_but_original_untouched(tmp_path):
    (tmp_path / "keep.txt").write_text("original")
    r = parse_report("```sh\necho changed > keep.txt\ncat keep.txt\n```\n", "x")
    res = run(r, repo=str(tmp_path), sandbox="bwrap")
    assert "changed" in res.output_tail
    assert (tmp_path / "keep.txt").read_text() == "original"


@needs_bwrap
def test_bwrap_setup_failure_is_error(tmp_path):
    r = parse_report("```sh\ntrue\n```\n", "x")
    res = run(r, repo=str(tmp_path), sandbox="bwrap", setup="false")
    assert res.status == "error" and "setup" in res.note


@needs_asan
def test_bwrap_reproduces_asan_heap_overflow(example):
    r = parse_report(open(os.path.join(example, "reports", "r01-heap-overflow-parse-header.md")).read(), "r01")
    res = run(r, repo=example, sandbox="bwrap", timeout=120)
    assert res.status == "reproduced", res.output_tail
    assert res.signature.kind == "asan:heap-buffer-overflow" and res.signature.frames[0] == "parse_header"


@needs_asan
def test_bwrap_template_builds_c_poc_without_shell_block(example):
    r = parse_report(open(os.path.join(example, "reports", "r08-uaf-hdr-remove.md")).read(), "r08")
    tpl = {"c": "cc -g -fsanitize=address -Iinclude src/tinyhdr.c {poc} -o /tmp/poc && /tmp/poc"}
    res = run(r, repo=example, sandbox="bwrap", templates=tpl, timeout=120)
    assert res.status == "reproduced" and res.signature.kind == "asan:heap-use-after-free"
    assert res.signature.frames[0] == "hdr_remove"


@needs_asan
def test_bwrap_build_error_is_error(tmp_path):
    r = parse_report("```c\nint main( { syntax error\n```\n", "x")
    res = run(r, repo=str(tmp_path), sandbox="bwrap")
    assert res.status == "error"


@needs_docker
def test_docker_runner_segv_and_no_network():
    res = run(parse_report(SEGV_PY, "x"), sandbox="docker", image="python:3.12-alpine", timeout=180)
    assert res.status == "reproduced", res.output_tail
    r = parse_report("```python\nimport socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), timeout=3); print('NET', True)\n"
                     "except OSError:\n    print('NET', False)\n```\n", "n")
    assert "NET False" in run(r, sandbox="docker", image="python:3.12-alpine", timeout=180).output_tail
