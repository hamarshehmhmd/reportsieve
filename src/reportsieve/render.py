"""Text, Markdown and JSON output."""
from __future__ import annotations

import json
from collections import Counter
from typing import List

from .analyze import VERDICT_ORDER, Assessment, needs_info_questions
from .extract import CWE_LABEL

COLORS = {"confirmed": "31;1", "likely-valid": "33;1", "needs-info": "36", "duplicate": "2", "known": "2",
          "out-of-scope": "2", "likely-noise": "2"}


def ordered(items: List[Assessment]) -> List[Assessment]:
    return sorted(items, key=lambda a: (VERDICT_ORDER.index(a.verdict), -a.score))


def human_queue(items: List[Assessment]) -> List[Assessment]:
    return [a for a in ordered(items) if a.verdict in ("confirmed", "likely-valid", "needs-info")]


def note(a: Assessment) -> str:
    if a.known_as:
        return f"matches known {a.known_as.other} ({a.known_as.score:.2f}: {'; '.join(a.known_as.why[:2])})"
    if a.duplicate_of:
        return f"duplicate of {a.duplicate_of.other} ({a.duplicate_of.score:.2f}: {'; '.join(a.duplicate_of.why[:2])})"
    if a.out_of_scope:
        return a.out_of_scope
    if a.repro and a.repro.status == "reproduced":
        return f"reproduced in {a.repro.runner} sandbox: {a.repro.signature}" if a.repro.signature else "reproduced"
    neg = [t for p, t in a.reasons if p < 0]
    if a.verdict == "likely-noise" and neg:
        return "; ".join(neg[:2])
    if a.verdict == "needs-info":
        q = needs_info_questions(a)
        rel = f"; related to {a.related[0].other}" if a.related else ""
        return ("ask for: " + "; ".join(q[:2]) if q else "") + rel
    pos = [t for p, t in a.reasons if p > 0]
    rel = f"related to {a.related[0].other} ({a.related[0].score:.2f})" if a.related else ""
    return "; ".join(([rel] if rel else []) + pos[:2])


def summary_line(items: List[Assessment]) -> str:
    c = Counter(a.verdict for a in items)
    parts = [f"{c[v]} {v}" for v in VERDICT_ORDER if c[v]]
    return f"{len(items)} report{'s' if len(items) != 1 else ''}: " + " · ".join(parts)


def text(items: List[Assessment], color: bool = False, verbose: bool = False) -> str:
    def paint(s: str, code: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if color and code else s

    out = [paint("reportsieve", "1") + "  " + summary_line(items)]
    q = human_queue(items)
    clusters = len({a.cluster for a in items if a.verdict != "known"})
    out.append(f"distinct issues: {clusters} · needs a human: {len(q)} of {len(items)}"
               + (f" → read first: {', '.join(a.report.id for a in q[:5])}" if q else ""))
    out.append("")
    idw = min(32, max([len(a.report.id) for a in items] + [2]))
    out.append(paint(f"  {'VERDICT':<13} {'SCORE':>5}  {'SEV':<8} {'ID':<{idw}}  TITLE", "2"))
    for a in ordered(items):
        sev = a.suggested_severity.split(" ")[0]
        title = a.report.title if len(a.report.title) <= 58 else a.report.title[:57] + "…"
        out.append(f"  {paint(f'{a.verdict:<13}', COLORS.get(a.verdict, ''))} {a.score:>5}  {sev:<8} {a.report.id:<{idw}}  {title}")
        n = note(a)
        if n:
            out.append(paint(f"  {'':<13} {'':>5}  {'':<8} ↳ {n}", "2" if a.verdict in ("duplicate", "known", "out-of-scope", "likely-noise") else ""))
        if verbose:
            for p, t in a.reasons:
                out.append(f"  {'':<29}{p:+4d}  {t}")
    return "\n".join(out)


def brief(a: Assessment) -> str:
    r = a.report
    L = [f"## {r.id}: {r.title}", ""]
    L.append(f"**Verdict:** {a.verdict} · **evidence score:** {a.score}/100 · **suggested severity (heuristic):** {a.suggested_severity}"
             + (f" · reporter claimed: {r.severity_claim}" + (f" (CVSS {r.cvss_score})" if r.cvss_score is not None else "") if r.severity_claim else ""))
    meta = []
    if r.reporter:
        meta.append(f"reporter: {r.reporter}")
    if r.date:
        meta.append(f"date: {r.date}")
    if r.source:
        meta.append(f"source: `{r.source}`")
    if meta:
        L.append("")
        L.append(" · ".join(meta))
    L.append("")
    if r.cwes:
        L.append("- **Class:** " + ", ".join(f"{c} {CWE_LABEL.get(c, '')}".strip() for c in sorted(r.cwes)))
    if r.functions or r.files:
        refs = sorted(f + "()" for f in r.functions)[:6] + sorted(r.files)[:6]
        L.append("- **Code cited:** " + ", ".join(f"`{x}`" for x in refs))
    if r.versions:
        L.append("- **Version:** " + ", ".join(sorted(r.versions)[:4]))
    if r.signature:
        L.append(f"- **Crash in report:** `{r.signature}`")
    if a.repro:
        rp = a.repro
        L.append(f"- **Sandbox repro ({rp.runner or 'n/a'}):** {rp.status}" + (f", `{rp.signature}`" if rp.signature else "")
                 + (f" — {rp.note}" if rp.note else "") + (f" ({rp.seconds:.1f}s)" if rp.seconds else ""))
    if a.duplicate_of:
        L.append(f"- **Duplicate of:** {a.duplicate_of.other} (similarity {a.duplicate_of.score:.2f}: {'; '.join(a.duplicate_of.why)})")
    if a.related:
        L.append("- **Related (read together):** " + "; ".join(f"{m.other} ({m.score:.2f})" for m in a.related))
    if a.known_as:
        L.append(f"- **Already known:** {a.known_as.other} (similarity {a.known_as.score:.2f}: {'; '.join(a.known_as.why)})")
    if a.out_of_scope:
        L.append(f"- **Out of scope:** {a.out_of_scope}")
    if a.missing_refs:
        L.append("- **Not found in repo:** " + "; ".join(a.missing_refs))
    L += ["", "| points | why |", "|---:|---|"]
    for p, t in a.reasons:
        L.append(f"| {p:+d} | {t.replace('|', '/')} |")
    q = needs_info_questions(a) if a.verdict in ("needs-info", "likely-noise") else []
    if q:
        L += ["", "**Ask the reporter for:**"] + [f"- {x}" for x in q]
    if a.repro and a.repro.output_tail and a.repro.status in ("reproduced", "error", "timeout"):
        tail = "\n".join(a.repro.output_tail.splitlines()[-15:])
        L += ["", "<details><summary>sandbox output (tail)</summary>", "", "```", tail, "```", "", "</details>"]
    return "\n".join(L)


def markdown(items: List[Assessment]) -> str:
    L = ["# Security inbox triage (reportsieve)", "", summary_line(items), ""]
    q = human_queue(items)
    if q:
        L.append("**Read first:** " + ", ".join(f"`{a.report.id}`" for a in q))
        L.append("")
    L += ["| verdict | score | severity | id | title | note |", "|---|---:|---|---|---|---|"]
    for a in ordered(items):
        L.append(f"| {a.verdict} | {a.score} | {a.suggested_severity} | `{a.report.id}` | {a.report.title.replace('|', '/')} | {note(a).replace('|', '/')} |")
    L.append("")
    for a in ordered(items):
        L += [brief(a), ""]
    L.append("_Scores and severities are heuristics to order the queue, not a verdict. A human still decides._")
    return "\n".join(L) + "\n"


def to_json(items: List[Assessment]) -> str:
    def one(a: Assessment) -> dict:
        r = a.report
        return {
            "id": r.id, "title": r.title, "source": r.source, "reporter": r.reporter, "date": r.date,
            "verdict": a.verdict, "score": a.score, "suggested_severity": a.suggested_severity,
            "claimed_severity": r.severity_claim or None, "claimed_cvss": r.cvss_score,
            "cwes": sorted(r.cwes), "functions": sorted(r.functions), "files": sorted(r.files),
            "versions": sorted(r.versions), "crash_signature": str(r.signature) if r.signature else None,
            "cluster": a.cluster,
            "duplicate_of": {"id": a.duplicate_of.other, "similarity": round(a.duplicate_of.score, 3), "why": a.duplicate_of.why} if a.duplicate_of else None,
            "known_as": {"id": a.known_as.other, "similarity": round(a.known_as.score, 3), "why": a.known_as.why} if a.known_as else None,
            "related": [{"id": m.other, "similarity": round(m.score, 3), "why": m.why} for m in a.related],
            "out_of_scope": a.out_of_scope or None, "missing_refs": a.missing_refs,
            "repro": a.repro.to_dict() if a.repro else None,
            "reasons": [{"points": p, "why": t} for p, t in a.reasons],
            "ask_reporter_for": needs_info_questions(a) if a.verdict in ("needs-info", "likely-noise") else [],
        }
    return json.dumps({"summary": summary_line(items), "read_first": [a.report.id for a in human_queue(items)],
                       "reports": [one(a) for a in ordered(items)]}, indent=2) + "\n"
