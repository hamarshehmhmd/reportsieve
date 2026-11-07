"""reportsieve command line."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional

from . import __version__, render
from .analyze import Policy, RepoIndex, ReproResult, assess
from .extract import Report, parse_report
from .repro import run as run_repro
from .sources import SourceError, load_known, load_paths

POLICY_FILE = "reportsieve.json"
STATE_DIR = ".reportsieve"

TEMPLATE = {
    "project": "my-project",
    "known": ["known/", "gh:OWNER/REPO"],
    "out_of_scope": {
        "paths": ["examples/*", "tests/*", "fuzz/*", "docs/*"],
        "cwes": [],
        "keywords": ["self-xss", "missing security header", "clickjacking"],
    },
    "duplicate_threshold": 0.6,
    "likely_valid_score": 60,
    "noise_score": 35,
    "repro": {
        "sandbox": "auto",
        "image": None,
        "timeout": 60,
        "setup": "",
        "templates": {
            "c": "cc -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -I. -Iinclude -Isrc src/*.c {poc} -o /tmp/poc && /tmp/poc"
        },
    },
}


def _find_policy(explicit: Optional[str], repo: Optional[str]) -> Dict:
    paths = [explicit] if explicit else [os.path.join(repo, POLICY_FILE)] if repo else []
    paths.append(POLICY_FILE)
    for p in paths:
        if p and os.path.isfile(p):
            with open(p, encoding="utf-8") as fh:
                d = json.load(fh)
            d["_path"] = p
            return d
    if explicit:
        raise SourceError(f"policy file not found: {explicit}")
    return {}


def _state(args) -> str:
    return args.state or STATE_DIR


def _load_cached_repro(state: str) -> Dict[str, ReproResult]:
    d = os.path.join(state, "repro")
    out: Dict[str, ReproResult] = {}
    if os.path.isdir(d):
        for fn in os.listdir(d):
            if fn.endswith(".json"):
                try:
                    with open(os.path.join(d, fn), encoding="utf-8") as fh:
                        out[fn[:-5]] = ReproResult.from_dict(json.load(fh))
                except (OSError, ValueError, KeyError):
                    pass
    return out


def _save_repro(state: str, rid: str, res: ReproResult) -> None:
    d = os.path.join(state, "repro")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, rid + ".json"), "w", encoding="utf-8") as fh:
        json.dump(res.to_dict(), fh, indent=2)


def _history(state: str) -> List[Report]:
    p = os.path.join(state, "history.json")
    if not os.path.isfile(p):
        return []
    with open(p, encoding="utf-8") as fh:
        items = json.load(fh)
    out = []
    for d in items:
        r = parse_report(d["body"], d["id"], d.get("source", "history"))
        r.date = d.get("date", "")
        out.append(r)
    return out


def _record(state: str, reports: List[Report]) -> int:
    p = os.path.join(state, "history.json")
    os.makedirs(state, exist_ok=True)
    items = []
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as fh:
            items = json.load(fh)
    have = {d["id"] for d in items}
    new = [{"id": r.id, "title": r.title, "body": r.body, "source": r.source, "date": r.date} for r in reports if r.id not in have]
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(items + new, fh, indent=1)
    return len(new)


def _repro_kwargs(args, pol: Dict) -> Dict:
    rp = pol.get("repro", {}) or {}
    return dict(
        repo=args.repo, sandbox=args.sandbox or rp.get("sandbox") or "auto", image=args.image or rp.get("image"),
        timeout=args.timeout or int(rp.get("timeout") or 60), setup=args.setup if args.setup is not None else rp.get("setup", ""),
        templates=rp.get("templates") or {}, unsafe_local=args.unsafe_local,
    )


def _add_repro_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("sandbox (PoCs are untrusted code)")
    g.add_argument("--sandbox", choices=["auto", "bwrap", "docker", "podman", "local"], help="runner (default: auto = bwrap on Linux, else docker/podman with --image)")
    g.add_argument("--image", help="container image for docker/podman, e.g. gcc:14 or python:3.12-slim")
    g.add_argument("--timeout", type=int, help="seconds per PoC (default 60)")
    g.add_argument("--setup", help="command run in the sandbox before the PoC, e.g. 'make asan'")
    g.add_argument("--unsafe-local", action="store_true", help="allow --sandbox local (no isolation!)")


def cmd_triage(args) -> int:
    pol = _find_policy(args.policy, args.repo)
    policy = Policy.from_dict(pol)
    if args.threshold is not None:
        policy.threshold = args.threshold
    reports = load_paths(args.paths)
    if not reports:
        print("reportsieve: no reports found", file=sys.stderr)
        return 2
    known_specs = list(args.known or [])
    if not args.known and pol.get("known"):
        base = os.path.dirname(pol.get("_path", "")) or "."
        for s in pol["known"]:
            if s.startswith(("gh:", "osv:")):
                if "OWNER/REPO" not in s:
                    known_specs.append(s)
            else:
                full = s if os.path.isabs(s) else os.path.join(base, s)
                if os.path.exists(full):
                    known_specs.append(full)
    known = load_known(known_specs) if known_specs else []
    state = _state(args)
    repro = {} if args.no_cache else _load_cached_repro(state)
    if args.repro:
        kw = _repro_kwargs(args, pol)
        for r in reports:
            if r.poc_blocks and (r.id not in repro or args.no_cache):
                if not args.quiet:
                    print(f"reportsieve: running PoC for {r.id} …", file=sys.stderr)
                res = run_repro(r, **kw)
                repro[r.id] = res
                _save_repro(state, r.id, res)
    history = [h for h in _history(state) if h.id not in {r.id for r in reports}] if not args.no_history else []
    repo = RepoIndex(args.repo) if args.repo else None
    items = assess(reports, known=known, policy=policy, repo=repo, repro=repro, history=history)
    if args.format == "json":
        out = render.to_json(items)
    elif args.format == "markdown":
        out = render.markdown(items)
    else:
        color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
        out = render.text(items, color=color, verbose=args.verbose)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out if out.endswith("\n") else out + "\n")
        if not args.quiet:
            print(f"reportsieve: wrote {args.output} ({render.summary_line(items)})", file=sys.stderr)
    else:
        print(out.rstrip("\n"))
    if args.record:
        n = _record(state, reports)
        if not args.quiet:
            print(f"reportsieve: recorded {n} new report(s) in {os.path.join(state, 'history.json')}", file=sys.stderr)
    if args.fail_on:
        bad = {"confirmed": ["confirmed"], "likely-valid": ["confirmed", "likely-valid"],
               "needs-info": ["confirmed", "likely-valid", "needs-info"]}[args.fail_on]
        if any(a.verdict in bad for a in items):
            return 1
    return 0


def cmd_repro(args) -> int:
    pol = _find_policy(args.policy, args.repo)
    reports = load_paths([args.report])
    if args.id:
        reports = [r for r in reports if r.id == args.id]
    if not reports:
        print("reportsieve: report not found", file=sys.stderr)
        return 2
    kw = _repro_kwargs(args, pol)
    rc = 0
    for r in reports:
        if args.show:
            from .repro import plan, ReproError
            try:
                files, script = plan(r, kw["templates"], args.cmd)
            except ReproError as e:
                print(f"{r.id}: {e}")
                rc = 1
                continue
            print(f"# {r.id}: files {', '.join(files) or '(none)'}\n# script:\n{script}")
            continue
        res = run_repro(r, cmd=args.cmd, expect=args.expect, **kw)
        _save_repro(_state(args), r.id, res)
        sig = f" {res.signature}" if res.signature else ""
        print(f"{r.id}: {res.status}{sig}" + (f" [{res.runner}, {res.seconds:.1f}s]" if res.runner else "") + (f" — {res.note}" if res.note else ""))
        if args.verbose and res.output_tail:
            lines = res.output_tail.splitlines()
            start = next((i for i, ln in enumerate(lines) if re.search(r"ERROR: \w+Sanitizer|runtime error|Traceback|Segmentation fault", ln)), None)
            shown = lines[start:start + 14] if start is not None else lines[-25:]
            print("\n".join("    " + ln for ln in shown))
        if res.status in ("error", "skipped"):
            rc = max(rc, 1)
    return rc


def cmd_brief(args) -> int:
    ns = argparse.Namespace(**vars(args))
    ns.format = "json"
    pol = _find_policy(args.policy, args.repo)
    policy = Policy.from_dict(pol)
    reports = load_paths(args.paths)
    known = load_known(args.known) if args.known else []
    items = assess(reports, known=known, policy=policy, repo=RepoIndex(args.repo) if args.repo else None,
                   repro=_load_cached_repro(_state(args)))
    sel = [a for a in items if a.report.id == args.id] if args.id else items[-1:]
    if not sel:
        print(f"reportsieve: no report with id {args.id!r} (have: {', '.join(a.report.id for a in items)})", file=sys.stderr)
        return 2
    print(render.brief(sel[0]))
    return 0


def cmd_init(args) -> int:
    if os.path.exists(POLICY_FILE) and not args.force:
        print(f"reportsieve: {POLICY_FILE} exists (use --force)", file=sys.stderr)
        return 1
    with open(POLICY_FILE, "w", encoding="utf-8") as fh:
        json.dump(TEMPLATE, fh, indent=2)
        fh.write("\n")
    print(f"wrote {POLICY_FILE}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="reportsieve", description="Reproduce, dedupe and score inbound security reports before a human reads them.")
    ap.add_argument("--version", action="version", version=f"reportsieve {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--repo", help="your source tree: cross-check cited files/functions, and the PoC sandbox gets a copy")
        p.add_argument("--policy", help=f"policy file (default: {POLICY_FILE} in --repo or cwd)")
        p.add_argument("--state", help=f"state dir for repro results and history (default: {STATE_DIR})")

    t = sub.add_parser("triage", help="score, dedupe and order a batch of reports")
    t.add_argument("paths", nargs="+", help="report files/dirs (.md .txt .eml .json), '-' for stdin, or gh:owner/repo (triage advisories)")
    t.add_argument("--known", action="append", help="known advisories: dir/file, gh:owner/repo (published GHSAs), osv:Ecosystem/name (repeatable)")
    common(t)
    t.add_argument("--repro", action="store_true", help="run each PoC in the sandbox (cached in the state dir)")
    t.add_argument("--no-cache", action="store_true", help="ignore cached repro results")
    t.add_argument("--no-history", action="store_true", help="don't dedupe against previously recorded reports")
    t.add_argument("--record", action="store_true", help="add these reports to history so future arrivals dedupe against them")
    t.add_argument("--threshold", type=float, help="duplicate similarity threshold (default 0.55)")
    t.add_argument("-f", "--format", choices=["text", "markdown", "json"], default="text")
    t.add_argument("-o", "--output", help="write to file")
    t.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    t.add_argument("-v", "--verbose", action="store_true", help="show every scoring reason")
    t.add_argument("-q", "--quiet", action="store_true")
    t.add_argument("--fail-on", choices=["confirmed", "likely-valid", "needs-info"], help="exit 1 if any report reaches this verdict")
    _add_repro_opts(t)
    t.set_defaults(func=cmd_triage)

    r = sub.add_parser("repro", help="run one report's PoC in a sandbox and record the crash signature")
    r.add_argument("report", help="report file (or a .json export; pick one with --id)")
    r.add_argument("--id")
    common(r)
    r.add_argument("--cmd", help="override the command to run ({poc} = the extracted PoC file)")
    r.add_argument("--expect", help="regex in the output that counts as reproduced (logic bugs, info leaks)")
    r.add_argument("--show", action="store_true", help="print the extracted PoC plan without running it")
    r.add_argument("-v", "--verbose", action="store_true")
    _add_repro_opts(r)
    r.set_defaults(func=cmd_repro)

    b = sub.add_parser("brief", help="one-page Markdown brief for one report")
    b.add_argument("paths", nargs="+")
    b.add_argument("--id", help="report id (default: the last one given)")
    b.add_argument("--known", action="append")
    common(b)
    b.set_defaults(func=cmd_brief)

    i = sub.add_parser("init", help=f"write a {POLICY_FILE} policy template")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SourceError as e:
        print(f"reportsieve: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
