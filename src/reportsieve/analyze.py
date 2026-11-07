"""Dedupe, known-issue matching, repo cross-checks and evidence scoring."""
from __future__ import annotations

import fnmatch
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .extract import CWE_LABEL, Report, Signature

STOPWORDS = set("""a an and are as at be been but by can could did do does for from has have how i if in into is it its
of on or our please report reported reporting security so such that the their them then there these this those to
was we were what when where which while who will with would you your hello hi thanks thank regards team dear
issue vulnerability vulnerable bug found also may might should just very more most any all one two using use used""".split())

FILLER = [
    r"i hope this (message|email) finds you well", r"\bas an ai\b", r"comprehensive (security )?(analysis|review|audit)",
    r"it is (important|worth|crucial) to note", r"\bdelve\b", r"i have identified a (critical|serious|severe)",
    r"\bcertainly[,!]", r"\bin conclusion\b", r"\brobust\b", r"\bseamless(ly)?\b", r"thorough (analysis|investigation)",
    r"this (could|may) (potentially )?(lead to|result in|allow)", r"best practices", r"\bmitigation strategies\b",
    r"\bproactive(ly)?\b", r"\bleverag(e|ing)\b", r"i('d| would) (be happy|love) to (help|assist)",
]
SPECULATIVE = re.compile(r"\b(could potentially|may potentially|might allow|theoretical(ly)?|hypothetical(ly)?|"
                         r"if an attacker were (able )?to|in theory|it is possible that|could be exploited)\b", re.I)
SOURCE_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".rs", ".go", ".py", ".js", ".mjs", ".cjs", ".ts",
              ".tsx", ".java", ".kt", ".rb", ".php", ".cs", ".swift", ".m", ".mm", ".zig", ".lua", ".pl", ".sh")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist", ".tox", ".reportsieve"}

VERDICT_ORDER = ["confirmed", "likely-valid", "needs-info", "duplicate", "known", "out-of-scope", "likely-noise"]
SEVERE = {"CWE-787", "CWE-416", "CWE-415", "CWE-78", "CWE-89", "CWE-94", "CWE-502", "CWE-444", "CWE-918", "CWE-22", "CWE-611"}
MEDIUM = {"CWE-125", "CWE-190", "CWE-134", "CWE-79", "CWE-295", "CWE-200", "CWE-1321", "CWE-362", "CWE-457", "CWE-601"}
LOW = {"CWE-476", "CWE-400", "CWE-1333", "CWE-401", "CWE-208"}


@dataclass
class Policy:
    oos_paths: List[str] = field(default_factory=list)
    oos_cwes: List[str] = field(default_factory=list)
    oos_keywords: List[str] = field(default_factory=list)
    threshold: float = 0.6
    related: float = 0.4
    valid_score: int = 60
    noise_score: int = 35
    project: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        o = d.get("out_of_scope", {}) or {}
        return cls(
            oos_paths=list(o.get("paths", [])), oos_cwes=[c.upper() for c in o.get("cwes", [])],
            oos_keywords=[k.lower() for k in o.get("keywords", [])],
            threshold=float(d.get("duplicate_threshold", 0.6)), related=float(d.get("related_threshold", 0.4)),
            valid_score=int(d.get("likely_valid_score", 60)), noise_score=int(d.get("noise_score", 35)),
            project=d.get("project", ""),
        )


@dataclass
class ReproResult:
    status: str                      # reproduced | no-crash | error | timeout | skipped
    signature: Optional[Signature] = None
    exit_code: Optional[int] = None
    runner: str = ""
    seconds: float = 0.0
    output_tail: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {"status": self.status, "signature": str(self.signature) if self.signature else None,
                "signature_kind": self.signature.kind if self.signature else None,
                "signature_frames": self.signature.frames if self.signature else [],
                "exit_code": self.exit_code, "runner": self.runner, "seconds": round(self.seconds, 2),
                "output_tail": self.output_tail, "note": self.note}

    @classmethod
    def from_dict(cls, d: dict) -> "ReproResult":
        sig = Signature(d["signature_kind"], d.get("signature_frames") or []) if d.get("signature_kind") else None
        return cls(d["status"], sig, d.get("exit_code"), d.get("runner", ""), d.get("seconds", 0.0),
                   d.get("output_tail", ""), d.get("note", ""))


@dataclass
class Match:
    other: str
    score: float
    why: List[str]


@dataclass
class Assessment:
    report: Report
    verdict: str = ""
    score: int = 0
    reasons: List[Tuple[int, str]] = field(default_factory=list)   # (points, text)
    duplicate_of: Optional[Match] = None
    related: List[Match] = field(default_factory=list)
    known_as: Optional[Match] = None
    out_of_scope: str = ""
    missing_refs: List[str] = field(default_factory=list)
    repro: Optional[ReproResult] = None
    suggested_severity: str = ""
    cluster: str = ""

    def add(self, pts: int, text: str) -> None:
        self.reasons.append((pts, text))
        self.score += pts


# ---------------------------------------------------------------- similarity

def words(text: str) -> List[str]:
    toks = re.findall(r"[a-z_][a-z0-9_]{2,}", text.lower())
    return [t.rstrip("s") if len(t) > 4 and not t.endswith("ss") else t for t in toks if t not in STOPWORDS]


def cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(v * b.get(k, 0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def _poc_names(r: Report) -> Set[str]:
    return {b.filename for b in r.blocks if b.filename} | {f for f in r.files if os.path.basename(f).startswith(("poc", "repro", "exploit", "test_poc"))}


def tech_tokens(r: Report) -> Set[str]:
    poc = _poc_names(r)
    t = {"fn:" + f.lower().split(".")[-1].split("::")[-1] for f in r.functions}
    t |= {"file:" + os.path.basename(f).lower() for f in r.files if f not in poc}
    fn_names = {x.split(":", 1)[1] for x in t if x.startswith("fn:")}
    t |= {"ent:" + e for e in r.entities if e.split(".")[-1].split("::")[-1] not in fn_names and not e.endswith(tuple("." + x for x in ("c", "h", "py", "js", "go", "rs")))}
    return t


class Corpus:
    """Document frequencies over everything being compared, so common words ('cache', 'client') count less."""

    def __init__(self, reports: Iterable[Report] = ()):
        self.n = 0
        self.df_tok: Counter = Counter()
        self.df_word: Counter = Counter()
        self._vec: Dict[int, Counter] = {}
        self._tok: Dict[int, Set[str]] = {}
        for r in reports:
            self.add(r)

    def add(self, r: Report) -> None:
        self.n += 1
        self.df_tok.update(self.tokens(r))
        self.df_word.update(set(self.words(r)))

    def tokens(self, r: Report) -> Set[str]:
        if id(r) not in self._tok:
            self._tok[id(r)] = tech_tokens(r)
        return self._tok[id(r)]

    def words(self, r: Report) -> Counter:
        if id(r) not in self._vec:
            self._vec[id(r)] = Counter(words(r.title + " " + r.title + " " + r.prose))
        return self._vec[id(r)]

    def idf(self, df: int) -> float:
        if self.n <= 2:
            return 1.0
        return max(0.05, math.log((self.n + 1) / (df + 0.5)))

    def w_tok(self, t: str) -> float:
        return self.idf(self.df_tok.get(t, 0))

    def tfidf(self, r: Report) -> Counter:
        return Counter({k: v * self.idf(self.df_word.get(k, 0)) for k, v in self.words(r).items()})


def similarity(a: Report, b: Report, corpus: Optional[Corpus] = None) -> Tuple[float, List[str]]:
    corpus = corpus or Corpus([a, b])
    why: List[str] = []
    if a.signature and b.signature and a.signature.frames and a.signature.key(2) == b.signature.key(2):
        return 1.0, [f"same crash signature ({a.signature})"]
    ta, tb = corpus.tokens(a), corpus.tokens(b)
    shared = ta & tb
    if ta and tb:
        wa = sum(corpus.w_tok(t) for t in ta)
        wb = sum(corpus.w_tok(t) for t in tb)
        tech = sum(corpus.w_tok(t) for t in shared) / min(wa, wb) if shared else 0.0
    else:
        tech = -1.0  # nothing technical to compare on one side: fall back to wording + class
    if shared:
        top = sorted(shared, key=lambda t: -corpus.w_tok(t))[:4]
        why.append("both cite " + ", ".join(t.split(":", 1)[1] + ("()" if t.startswith("fn:") else "") for t in top))
    ca, cb = a.cwes - {"CWE-94"}, b.cwes - {"CWE-94"}
    cwe = len(ca & cb) / len(ca | cb) if ca and cb else 0.0
    if ca & cb:
        why.append("same class: " + ", ".join(CWE_LABEL.get(c, c) for c in sorted(ca & cb)))
    cos = cosine(corpus.tfidf(a), corpus.tfidf(b))
    if cos >= 0.3:
        why.append(f"similar wording ({cos:.2f})")
    if tech < 0:
        score = 0.7 * cos + 0.25 * cwe
    else:
        score = 0.45 * min(1.0, tech) + 0.40 * cos + 0.15 * cwe
        if not shared:
            score *= 0.6
    if a.signature and b.signature:
        if a.signature.kind == b.signature.kind:
            score += 0.1
        else:
            score *= 0.6
            why.append(f"different crashes ({a.signature.kind} vs {b.signature.kind})")
    if ca and cb and not (ca & cb):
        score *= 0.7
    return min(score, 0.99), why


# ---------------------------------------------------------------- repo cross-check

class RepoIndex:
    def __init__(self, root: str, max_files: int = 20000):
        self.root = root
        self.files: List[str] = []
        self.lines: Dict[str, int] = {}
        self._idents: Optional[Set[str]] = None
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for fn in fns:
                rel = os.path.relpath(os.path.join(dp, fn), root).replace(os.sep, "/")
                self.files.append(rel)
                if len(self.files) >= max_files:
                    return

    def idents(self) -> Set[str]:
        if self._idents is None:
            ids: Set[str] = set()
            for rel in self.files:
                if not rel.endswith(SOURCE_EXT):
                    continue
                p = os.path.join(self.root, rel)
                try:
                    if os.path.getsize(p) > 2_000_000:
                        continue
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        txt = fh.read()
                except OSError:
                    continue
                self.lines[rel] = len(txt.splitlines())
                ids.update(re.findall(r"[A-Za-z_]\w*", txt))
            self._idents = ids
        return self._idents

    def find(self, path: str) -> Optional[str]:
        path = path.lstrip("./")
        if path in self.files:
            return path
        cands = [f for f in self.files if f.endswith("/" + path) or f == path]
        if not cands:
            base = os.path.basename(path)
            cands = [f for f in self.files if os.path.basename(f) == base]
        return cands[0] if len(cands) == 1 else (min(cands, key=len) if cands else None)

    def line_count(self, rel: str) -> int:
        self.idents()
        if rel not in self.lines:
            try:
                with open(os.path.join(self.root, rel), encoding="utf-8", errors="replace") as fh:
                    self.lines[rel] = len(fh.read().splitlines())
            except OSError:
                self.lines[rel] = 0
        return self.lines[rel]


def check_refs(r: Report, repo: RepoIndex) -> List[str]:
    missing: List[str] = []
    poc = _poc_names(r)
    poc_code = "\n".join(b.code for b in r.blocks if b.lang)
    defined_in_poc = set(re.findall(r"\b(?:def|function|void|int|static|char)\s+\**([A-Za-z_]\w*)\s*\(", poc_code))
    ids = repo.idents()
    for f in sorted(r.files):
        if f in poc or os.path.basename(f) in {os.path.basename(p) for p in poc}:
            continue
        if not repo.find(f):
            missing.append(f"file {f}")
    for f, ln in sorted(r.file_lines):
        rel = repo.find(f)
        if rel and f not in poc:
            n = repo.line_count(rel)
            if n and ln > n:
                missing.append(f"{f}:{ln} (file has {n} lines)")
    for fn in sorted(r.functions):
        name = re.split(r"::|\.", fn)[-1]
        if name in defined_in_poc or name in ids:
            continue
        missing.append(f"function {fn}()")
    return missing


# ---------------------------------------------------------------- scoring

def _matches_oos_path(path: str, patterns: Sequence[str]) -> bool:
    p = path.lstrip("./")
    return any(fnmatch.fnmatch(p, pat) or fnmatch.fnmatch("/" + p, "*/" + pat.lstrip("/")) for pat in patterns)


def out_of_scope(r: Report, policy: Policy) -> str:
    if policy.oos_paths:
        poc = _poc_names(r)
        cited = [f for f in r.files if f not in poc]
        if cited and all(_matches_oos_path(f, policy.oos_paths) for f in cited):
            return "only touches out-of-scope paths: " + ", ".join(sorted(cited)[:3])
    hit = sorted(set(policy.oos_cwes) & r.cwes)
    if hit and not (r.cwes - set(policy.oos_cwes) - {"CWE-94"}):
        return "out-of-scope class: " + ", ".join(f"{c} ({CWE_LABEL.get(c, '')})" for c in hit)
    low = (r.title + " " + r.prose).lower()
    for k in policy.oos_keywords:
        if k in low:
            return f"policy keyword: {k!r}"
    return ""


def suggest_severity(r: Report, repro: Optional[ReproResult]) -> str:
    cw = set(r.cwes)
    if repro and repro.signature:
        k = repro.signature.kind
        if any(x in k for x in ("heap-buffer-overflow", "stack-buffer-overflow", "use-after-free", "double-free", "global-buffer-overflow")):
            cw.add("CWE-787" if "overflow" in k else "CWE-416")
    if cw & SEVERE - {"CWE-94"}:
        base = "high"
    elif cw & MEDIUM:
        base = "medium"
    elif cw & LOW:
        base = "low"
    else:
        base = "unclear"
    if not (repro and repro.status == "reproduced") and base == "high" and not r.poc_blocks and not r.reported_signature:
        base = "medium (unproven)"
    return base


def score_report(a: Assessment, policy: Policy) -> None:
    r = a.report
    if r.poc_blocks:
        a.add(25, f"PoC included ({', '.join(sorted({b.lang for b in r.poc_blocks}))})")
    else:
        a.add(0, "no PoC")
    if r.reported_signature:
        a.add(15, f"crash trace included ({r.reported_signature})")
    if r.versions:
        a.add(10, "affected version/commit: " + ", ".join(sorted(r.versions)[:3]))
    else:
        a.add(0, "no affected version")
    if r.has_steps:
        a.add(10, "reproduction steps")
    poc = _poc_names(r)
    if any(f not in poc for f in r.files) or r.functions:
        a.add(10, "points at specific code")
    if r.has_impact:
        a.add(10, "states impact / expected vs actual")
    evidence = bool(r.poc_blocks or r.reported_signature)
    if r.cvss_score is not None and r.cvss_score >= 9 and not evidence:
        a.add(-15, f"claims CVSS {r.cvss_score} with no PoC or trace")
    elif r.severity_claim == "critical" and not evidence:
        a.add(-10, "claims critical with no PoC or trace")
    if "CWE-94" in r.cwes and not evidence:
        a.add(-5, "claims code execution without evidence")
    text = (r.title + " " + r.prose).lower()
    fill = [p for p in FILLER if re.search(p, text)]
    if len(fill) >= 3:
        a.add(-10, f"boilerplate-heavy text ({len(fill)} filler phrases)")
    spec = SPECULATIVE.findall(r.prose)
    if spec and not evidence:
        a.add(-10, f"speculative wording without proof ({len(spec)}×)")
    if a.missing_refs:
        a.add(-min(30, 10 * len(a.missing_refs)), "cites things not in the repo: " + "; ".join(a.missing_refs[:4]))
    if a.repro:
        st = a.repro.status
        if st == "reproduced":
            msg = f"reproduced in sandbox ({a.repro.signature or 'crash'})"
            rs = r.reported_signature
            if rs and a.repro.signature and rs.kind != a.repro.signature.kind:
                msg += f"; report claimed {rs.kind}"
            a.add(30, msg)
        elif st == "no-crash":
            a.add(-10, "PoC ran in sandbox without a crash")
        elif st == "timeout":
            a.add(0, "PoC timed out in sandbox (possible hang/DoS)")
        elif st == "error":
            a.add(-5, f"PoC failed to build/run: {a.repro.note}"[:120])
    a.score = max(0, min(100, a.score))


def assess(reports: List[Report], known: Iterable[Report] = (), policy: Policy = None,
           repo: Optional[RepoIndex] = None, repro: Optional[Dict[str, ReproResult]] = None,
           history: Iterable[Report] = ()) -> List[Assessment]:
    policy = policy or Policy()
    repro = repro or {}
    known = list(known)
    history = list(history)
    corpus = Corpus(list(reports) + known + history)

    out: List[Assessment] = []
    for r in reports:
        a = Assessment(report=r, repro=repro.get(r.id))
        if a.repro and a.repro.status == "reproduced" and a.repro.signature:
            # the crash we observed beats the one the reporter pasted, for dedupe
            r.signature = a.repro.signature
        if repo is not None:
            a.missing_refs = check_refs(r, repo)
        a.out_of_scope = out_of_scope(r, policy)
        best: Optional[Match] = None
        for k in known:
            s, why = similarity(r, k, corpus)
            if s >= policy.threshold and (best is None or s > best.score):
                best = Match(k.id, s, why)
            elif s >= policy.related:
                a.related.append(Match(k.id, s, why))
        a.known_as = best
        best = None
        for prev in [x.report for x in out] + history:
            s, why = similarity(r, prev, corpus)
            if s >= policy.threshold and (best is None or s > best.score):
                best = Match(prev.id, s, why)
            elif s >= policy.related:
                a.related.append(Match(prev.id, s, why))
        a.related = sorted((m for m in a.related if not best or m.other != best.other), key=lambda m: -m.score)[:3]
        if best:
            root = next((x for x in out if x.report.id == best.other), None)
            canonical = root.cluster if root else best.other
            a.duplicate_of = Match(canonical, best.score, best.why if canonical == best.other else best.why + [f"via {best.other}"])
            a.cluster = canonical
        else:
            a.cluster = r.id
        score_report(a, policy)
        a.suggested_severity = suggest_severity(r, a.repro)
        if a.known_as:
            a.verdict = "known"
        elif a.duplicate_of:
            a.verdict = "duplicate"
        elif a.out_of_scope:
            a.verdict = "out-of-scope"
        elif a.repro and a.repro.status == "reproduced":
            a.verdict = "confirmed"
        elif a.score >= policy.valid_score:
            a.verdict = "likely-valid"
        elif a.score >= policy.noise_score or not any(p < 0 for p, _ in a.reasons):
            a.verdict = "needs-info"
        else:
            a.verdict = "likely-noise"
        out.append(a)
    # a duplicate whose sandbox repro worked confirms its canonical report too
    by_id = {a.report.id: a for a in out}
    for a in out:
        if a.duplicate_of and a.repro and a.repro.status == "reproduced":
            root = by_id.get(a.duplicate_of.other)
            if root and root.verdict in ("likely-valid", "needs-info", "likely-noise"):
                root.verdict = "confirmed"
                root.add(0, f"confirmed via duplicate {a.report.id} (reproduced in sandbox)")
    return out


def needs_info_questions(a: Assessment) -> List[str]:
    r = a.report
    q = []
    if not r.poc_blocks:
        q.append("a minimal PoC (input file or program) that triggers the issue")
    if not r.versions:
        q.append("the exact version or commit you tested")
    if not r.signature and r.cwes & (SEVERE | MEDIUM | LOW):
        q.append("the crash output (ideally an ASan/UBSan build) or observed behaviour")
    if not r.has_impact:
        q.append("what an attacker gains, and from what position")
    if a.missing_refs:
        q.append("where these are in the code: " + "; ".join(a.missing_refs[:3]))
    return q
