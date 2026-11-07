"""Run a report's PoC in a throwaway sandbox and capture the crash signature.

Runners (pick with --sandbox):
  bwrap   Linux bubblewrap: no network, read-only system dirs, empty home, writable copy of the repo
  docker  / podman: --network none, --cap-drop ALL, no-new-privileges, pids/memory limits, your image
  local   no isolation at all; refused unless you pass --unsafe-local

PoCs are attacker-supplied code. Never run them with `local` on a machine that holds secrets.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from .analyze import ReproResult
from .extract import EXT, Report, parse_signature

DEFAULT_TEMPLATES = {
    "c": "cc -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -I. -Iinclude -Isrc {poc} -o /tmp/poc && /tmp/poc",
    "cpp": "c++ -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -I. -Iinclude -Isrc {poc} -o /tmp/poc && /tmp/poc",
    "py": "python3 {poc}",
    "js": "node {poc}",
    "go": "go run {poc}",
    "rb": "ruby {poc}",
    "php": "php {poc}",
    "rs": "rustc -g {poc} -o /tmp/poc && /tmp/poc",
}
SAN_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:symbolize=1:allocator_may_return_null=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
    "MSAN_OPTIONS": "abort_on_error=0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONFAULTHANDLER": "1",
    "LANG": "C.UTF-8",
}
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class ReproError(Exception):
    pass


def plan(report: Report, templates: Optional[Dict[str, str]] = None, cmd: Optional[str] = None) -> Tuple[Dict[str, str], str]:
    """Return ({filename: content}, shell script) for a report's PoC."""
    templates = {**DEFAULT_TEMPLATES, **(templates or {})}
    files: Dict[str, str] = {}
    shell: List[str] = []
    first_src: Optional[Tuple[str, str]] = None
    for b in report.poc_blocks:
        if b.lang == "sh":
            lines = b.code.splitlines()
            prompted = [ln for ln in lines if re.match(r"^\s*[$#%>] ", ln) and not re.match(r"^\s*#\s*\d", ln)]
            if any(re.match(r"^\s*\$ ", ln) for ln in lines):
                lines = [re.sub(r"^\s*\$ ", "", ln) for ln in lines if re.match(r"^\s*\$ ", ln)]
            elif prompted and len(prompted) == len([ln for ln in lines if ln.strip()]):
                lines = [re.sub(r"^\s*[%>] ", "", ln) for ln in lines]
            shell.extend(lines)
            continue
        name = b.filename or f"poc.{EXT.get(b.lang, b.lang)}"
        base, ext = os.path.splitext(name)
        n = 2
        while name in files:
            name = f"{base}{n}{ext}"
            n += 1
        name = os.path.basename(name)
        files[name] = b.code
        if first_src is None:
            first_src = (b.lang, name)
    if cmd:
        script = cmd.replace("{poc}", shlex.quote(first_src[1]) if first_src else "")
    elif shell:
        script = "\n".join(shell)
    elif first_src:
        tpl = templates.get(first_src[0])
        if not tpl:
            raise ReproError(f"no run template for {first_src[0]} PoCs; pass --cmd")
        script = tpl.replace("{poc}", shlex.quote(first_src[1]))
    else:
        raise ReproError("report has no runnable PoC block (```c, ```python, ```sh, ...)")
    return files, script


def available(runner: str) -> bool:
    return runner == "local" or shutil.which(runner) is not None


def pick_runner(requested: str, image: Optional[str]) -> str:
    if requested != "auto":
        return requested
    if shutil.which("bwrap") and os.name == "posix" and os.uname().sysname == "Linux":
        return "bwrap"
    for r in ("docker", "podman"):
        if shutil.which(r) and image:
            return r
    raise ReproError("no sandbox available: install bubblewrap (Linux) or docker/podman and pass --image")


def _bwrap_cmd(work: str, setup: str, script: str, env: Dict[str, str]) -> List[str]:
    a = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--hostname", "reportsieve",
         "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/root", "--tmpfs", "/run"]
    for d in ("/usr", "/etc", "/opt", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/nix"):
        if os.path.islink(d):
            a += ["--symlink", os.readlink(d), d]
        elif os.path.isdir(d):
            a += ["--ro-bind", d, d]
    a += ["--bind", work, "/work", "--chdir", "/work/src", "--clearenv"]
    for k, v in {"PATH": PATH, "HOME": "/tmp", "SRC": "/work/src", **env}.items():
        a += ["--setenv", k, v]
    return a + ["sh", "-c", _wrap(setup, script)]


def _docker_cmd(engine: str, image: str, work: str, setup: str, script: str, env: Dict[str, str],
                memory: str, cpus: str) -> List[str]:
    a = [engine, "run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--pids-limit", "512", "--memory", memory, "--cpus", cpus, "-v", f"{work}:/work", "-w", "/work/src",
         "-e", "HOME=/tmp", "-e", "SRC=/work/src", "--tmpfs", "/tmp:exec"]
    if hasattr(os, "getuid") and engine == "docker":
        a += ["--user", f"{os.getuid()}:{os.getgid()}"]
    for k, v in env.items():
        a += ["-e", f"{k}={v}"]
    return a + [image, "sh", "-c", _wrap(setup, script)]


def _wrap(setup: str, script: str) -> str:
    parts = []
    if setup:
        parts.append(f"echo '[reportsieve] setup: {setup.replace(chr(39), '')[:60]}' >&2\n( {setup} ) || {{ echo '[reportsieve] setup failed' >&2; exit 97; }}")
    parts.append("echo '[reportsieve] running PoC' >&2\nsh ./.reportsieve-poc.sh")
    return "\n".join(parts)


def _copy_repo(src: str, dst: str) -> None:
    def ignore(d, names):
        return [n for n in names if n in {".git", "node_modules", ".venv", "venv", ".reportsieve", "__pycache__", ".tox"}]
    shutil.copytree(src, dst, symlinks=True, ignore=ignore)


def run(report: Report, repo: Optional[str] = None, sandbox: str = "auto", image: Optional[str] = None,
        timeout: int = 60, setup: str = "", cmd: Optional[str] = None, expect: Optional[str] = None,
        templates: Optional[Dict[str, str]] = None, unsafe_local: bool = False,
        memory: str = "2g", cpus: str = "2") -> ReproResult:
    try:
        files, script = plan(report, templates, cmd)
        runner = pick_runner(sandbox, image)
    except ReproError as e:
        return ReproResult("skipped", note=str(e))
    if runner == "local" and not unsafe_local:
        return ReproResult("skipped", runner=runner, note="local runner has no isolation; pass --unsafe-local to allow it")
    if runner in ("docker", "podman") and not image:
        return ReproResult("skipped", runner=runner, note=f"{runner} runner needs --image (e.g. gcc:14, python:3.12-slim)")
    if not available(runner):
        return ReproResult("skipped", runner=runner, note=f"{runner} not found on PATH")
    work = tempfile.mkdtemp(prefix="reportsieve-")
    try:
        src = os.path.join(work, "src")
        if repo:
            _copy_repo(repo, src)
        else:
            os.makedirs(src)
        for name, content in files.items():
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(content)
        with open(os.path.join(src, ".reportsieve-poc.sh"), "w", encoding="utf-8") as fh:
            fh.write("set -e\n" + script + "\n")
        if runner == "bwrap":
            argv = _bwrap_cmd(work, setup, script, SAN_ENV)
            env = {"PATH": os.environ.get("PATH", PATH)}
        elif runner in ("docker", "podman"):
            argv = _docker_cmd(runner, image, work, setup, script, SAN_ENV, memory, cpus)
            env = dict(os.environ)
        else:
            argv = ["sh", "-c", _wrap(setup, script)]
            env = {"PATH": os.environ.get("PATH", PATH), "HOME": work, "SRC": src, **SAN_ENV}
        t0 = time.time()
        p = subprocess.Popen(argv, cwd=src, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=os.name == "posix")
        timed_out = False
        try:
            out, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(p.pid, signal.SIGKILL)  # type: ignore[attr-defined]
            except (OSError, AttributeError):
                p.kill()
            out, _ = p.communicate()
        secs = time.time() - t0
        text = out.decode("utf-8", errors="replace")
        tail = "\n".join(text.splitlines()[-120:])
        rc = p.returncode
        if timed_out:
            return ReproResult("timeout", parse_signature(text), rc, runner, secs, tail, f"killed after {timeout}s")
        sig = parse_signature(text)
        if expect and re.search(expect, text, re.M):
            return ReproResult("reproduced", sig, rc, runner, secs, tail, f"output matched {expect!r}")
        if sig and not sig.kind.startswith(("python:", "js:")):
            return ReproResult("reproduced", sig, rc, runner, secs, tail)
        if rc is not None and (rc < 0 or rc in (134, 136, 139)):
            from .extract import Signature
            return ReproResult("reproduced", sig or Signature({-11: "segv", 139: "segv", -6: "abort", 134: "abort"}.get(rc, f"signal:{rc}")),
                               rc, runner, secs, tail, "killed by signal")
        if rc == 97:
            return ReproResult("error", None, rc, runner, secs, tail, "setup command failed")
        if rc and "[reportsieve] running PoC" in text and re.search(r"\berror:|undefined reference|No such file|command not found|SyntaxError", text):
            return ReproResult("error", sig, rc, runner, secs, tail, "PoC did not build or start")
        if sig:
            return ReproResult("no-crash", sig, rc, runner, secs, tail, f"uncaught {sig.kind} (not a memory-safety crash)")
        if expect:
            return ReproResult("no-crash", None, rc, runner, secs, tail, f"output did not match {expect!r}")
        return ReproResult("no-crash", None, rc, runner, secs, tail, f"exit code {rc}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
