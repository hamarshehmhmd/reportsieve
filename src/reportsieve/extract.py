"""Turn a free-form security report into structured facts.

Everything here is plain regex/heuristics over the report text: no model, no network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# keyword pattern -> (CWE, short label). Order matters only for the label list.
CWE_RULES: List[Tuple[str, str, str]] = [
    (r"heap[- ]buffer[- ]overflow|heap overflow|overflows? (the |a )?(heap |stack )?buffer|out[- ]of[- ]bounds write|oob write|buffer overflow|stack[- ]buffer[- ]overflow|buffer overrun",
     "CWE-787", "out-of-bounds write"),
    (r"out[- ]of[- ]bounds read|oob read|heap[- ]buffer[- ]over-?read|buffer over-?read|global[- ]buffer[- ]overflow",
     "CWE-125", "out-of-bounds read"),
    (r"use[- ]after[- ]free|\buaf\b|heap-use-after-free|dangling pointer", "CWE-416", "use after free"),
    (r"double[- ]free|attempting double-free", "CWE-415", "double free"),
    (r"integer overflow|integer wrap|wraparound|signed integer overflow|size_t overflow|unsigned integer overflow",
     "CWE-190", "integer overflow"),
    (r"null[\s-]pointer[\s-]deref|null deref|nullptr deref|segv on unknown address 0x0+\b|null dereference",
     "CWE-476", "NULL dereference"),
    (r"format string", "CWE-134", "format string"),
    (r"path traversal|directory traversal|\.\./\.\./|zip ?slip", "CWE-22", "path traversal"),
    (r"command injection|os command|shell injection|arbitrary command", "CWE-78", "command injection"),
    (r"sql injection|\bsqli\b", "CWE-89", "SQL injection"),
    (r"cross[- ]site scripting|\bxss\b", "CWE-79", "XSS"),
    (r"server[- ]side request forgery|\bssrf\b", "CWE-918", "SSRF"),
    (r"open redirect", "CWE-601", "open redirect"),
    (r"\bxxe\b|xml external entit", "CWE-611", "XXE"),
    (r"deserializ", "CWE-502", "unsafe deserialization"),
    (r"prototype pollution", "CWE-1321", "prototype pollution"),
    (r"request smuggling|desync", "CWE-444", "request smuggling"),
    (r"\bredos\b|catastrophic backtracking|regular expression denial", "CWE-1333", "ReDoS"),
    (r"denial of service|\bdos\b|resource exhaustion|infinite loop|unbounded (memory|allocation)|memory exhaustion|cpu exhaustion",
     "CWE-400", "resource exhaustion / DoS"),
    (r"timing attack|timing side[- ]channel|constant[- ]time", "CWE-208", "timing side channel"),
    (r"race condition|toctou|data race", "CWE-362", "race condition"),
    (r"uninitiali[sz]ed (memory|value|read)|use-of-uninitialized-value", "CWE-457", "uninitialized memory"),
    (r"memory leak|leaksanitizer|detected memory leaks", "CWE-401", "memory leak"),
    (r"remote code execution|\brce\b|arbitrary code execution", "CWE-94", "code execution (claimed)"),
    (r"information (disclosure|leak)|(?<!memory )(?<!memory-)\bleak(s|ed|ing|age)?\b(?! ?sanitizer)|sensitive data exposure|leaks? (the )?(token|credential|password)s?",
     "CWE-200", "information disclosure"),
    (r"certificate (validation|verification)|hostname verification|tls verification", "CWE-295", "TLS/cert validation"),
]
CWE_LABEL = {c: l for _, c, l in CWE_RULES}

SANITIZER_KINDS = [
    (r"AddressSanitizer: ([a-z-]+)", "asan"),
    (r"MemorySanitizer: ([a-z-]+)", "msan"),
    (r"ThreadSanitizer: ([a-z ]+?)(?: \(|$)", "tsan"),
    (r"LeakSanitizer: (detected memory leaks)", "lsan"),
    (r"runtime error: ([a-z ]+)", "ubsan"),
]
SAN_FRAME = re.compile(r"^[ \t]*#(\d+)[ \t]+0x[0-9a-fA-F]+[ \t]+in[ \t]+([^\s(]+)(?:[ \t]*\([^)\n]*\))?[ \t]*(\S*)", re.M)
GDB_FRAME = re.compile(r"^[ \t]*#(\d+)[ \t]+(?:0x[0-9a-fA-F]+[ \t]+in[ \t]+)?([A-Za-z_][\w:~<>]*)[ \t]*\([^\n]*?\)[ \t]*(?:at[ \t]+(\S+))?", re.M)
PY_FRAME = re.compile(r'^\s*File "([^"]+)", line (\d+), in (\S+)', re.M)
JS_FRAME = re.compile(r"^\s*at\s+(?:async\s+)?([\w$.<>\[\]]+)\s+\(([^)]+)\)", re.M)
SKIP_FRAMES = re.compile(
    r"^(__asan|__msan|__tsan|__ubsan|__sanitizer|__interceptor_|___interceptor_|__interception|"
    r"__libc_start|_start$|__GI_|__memcpy|__memmove|__strcpy|__strlen|asan_|malloc$|calloc$|realloc$|free$|"
    r"(memcpy|memmove|memset|strcpy|strncpy|strcat|strlen|strcmp|strcasecmp|printf|sprintf|snprintf)$|"
    r"operator new|operator delete|<module>$|main$)"
)
CODE_BLOCK = re.compile(r"^(```|~~~)[ \t]*([\w+.#-]*)[^\n]*\n(.*?)^\1[ \t]*$", re.M | re.S)
FILE_RE = re.compile(
    r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.(?:c|h|cc|cpp|cxx|hpp|hh|rs|go|py|js|mjs|cjs|ts|tsx|java|kt|rb|php|cs|swift|m|mm|zig|lua|pl|sh))"
    r"(?::(\d+))?(?![\w])"
)
FUNC_RE = re.compile(r"(?<![\w.$])([A-Za-z_][\w]*(?:(?:::|\.)[A-Za-z_]\w*)*)\s*\(\)")
FUNC_IN_CODE_RE = re.compile(r"`([A-Za-z_]\w*(?:(?:::|\.)[A-Za-z_]\w*)*)(?:\(\))?`")
VERSION_RE = re.compile(
    r"\b(?:version|ver\.?|release|tag|v)\s*(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)(?![\d.]*\.\d)"
    r"|(?<![\d.])(\d+\.\d+\.\d+(?:-[\w.]+)?)(?![\d.]*\.\d)"
    r"|\bcommit\s+([0-9a-f]{7,40})\b",
    re.I,
)
CVSS_VEC = re.compile(r"CVSS:3\.[01]/[A-Z:/]+|CVSS:4\.0/[A-Z:/]+")
CVSS_SCORE = re.compile(r"(?:cvss(?:\s*v?[34](?:\.\d)?)?\s*(?:base\s*)?(?:score)?\s*[:=]?\s*|score\s*[:=]\s*)(\d{1,2}\.\d)", re.I)
SEVERITY_WORD = re.compile(r"\b(critical|high|medium|moderate|low)\s+(?:severity|risk|impact)\b|severity\s*[:=]\s*(critical|high|medium|moderate|low)", re.I)
STEPS_RE = re.compile(r"steps? to reproduce|reproduction steps|to reproduce|repro(?:duction)?:|^\s*\d+\.\s+\S", re.I | re.M)
IMPACT_RE = re.compile(r"\bimpact\b|^\s*(expected|actual)\s*:|attacker\s+(can|could)|allows?\s+(an?\s+)?(remote\s+|local\s+|unauthenticated\s+)?(attackers?|users?)|(expected|actual)\s+(behaviou?r|result)", re.I)
ENTITY_RES = [
    re.compile(r"(?<![\w-])((?:X-)?[A-Z][a-z]+(?:-[A-Z][a-zA-Z0-9]+)+)(?![\w-])"),  # HTTP header names
    re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b", re.I),
    re.compile(r"(?<![\w-])(--[a-z][\w-]{2,})"),                                     # CLI flags
    re.compile(r"`([A-Za-z_][\w.-]{2,40})`"),                                       # backticked names
]
HEADING = re.compile(r"^\s{0,3}#{1,3}\s+(.+?)\s*#*\s*$", re.M)
HEADER_LINE = re.compile(r"^(Subject|Title|From|Reporter|Date|Reported|Package|Affected|Version|Commit)\s*:\s*(.+)$", re.I | re.M)

POC_LANGS = {
    "sh": "sh", "bash": "sh", "shell": "sh", "console": "sh", "zsh": "sh", "shell-session": "sh",
    "c": "c", "h": "c", "cpp": "cpp", "c++": "cpp", "cc": "cpp", "cxx": "cpp",
    "python": "py", "py": "py", "python3": "py",
    "js": "js", "javascript": "js", "node": "js", "mjs": "js",
    "go": "go", "rust": "rs", "rs": "rs", "ruby": "rb", "rb": "rb", "php": "php",
}
OUTPUT_LANGS = {"", "text", "txt", "log", "output", "plain", "plaintext", "asan", "stacktrace", "diff", "patch"}
EXT = {"sh": "sh", "c": "c", "cpp": "cpp", "py": "py", "js": "js", "go": "go", "rs": "rs", "rb": "rb", "php": "php"}


@dataclass
class CodeBlock:
    lang: str          # normalised: sh, c, cpp, py, js, ... or "" for output/unknown
    raw_lang: str
    code: str
    filename: Optional[str] = None   # "save as poc.c" hint right before the block


@dataclass
class Signature:
    kind: str                       # e.g. "asan:heap-buffer-overflow", "segv", "python:ValueError"
    frames: List[str] = field(default_factory=list)

    def key(self, depth: int = 3) -> str:
        return self.kind + "|" + ">".join(self.frames[:depth])

    def __str__(self) -> str:
        f = " > ".join(self.frames[:3])
        return f"{self.kind} in {f}" if f else self.kind


@dataclass
class Report:
    id: str
    title: str
    body: str
    source: str = ""
    reporter: str = ""
    date: str = ""
    cwes: Set[str] = field(default_factory=set)
    files: Set[str] = field(default_factory=set)
    file_lines: Set[Tuple[str, int]] = field(default_factory=set)
    functions: Set[str] = field(default_factory=set)
    entities: Set[str] = field(default_factory=set)   # header names, config keys, CLI flags, CVE ids
    versions: Set[str] = field(default_factory=set)
    blocks: List[CodeBlock] = field(default_factory=list)
    signature: Optional[Signature] = None
    reported_signature: Optional[Signature] = None
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    severity_claim: str = ""
    has_steps: bool = False
    has_impact: bool = False
    meta: Dict[str, str] = field(default_factory=dict)

    @property
    def poc_blocks(self) -> List[CodeBlock]:
        return [b for b in self.blocks if b.lang]

    @property
    def prose(self) -> str:
        return CODE_BLOCK.sub(" ", self.body)


def _norm_frame(name: str) -> str:
    name = name.strip()
    name = re.sub(r"\(.*$", "", name)
    return name.split("::")[-1] if name.count("::") > 2 else name


def _first_stack(text: str) -> List[str]:
    """Function names of the first contiguous '#N 0x... in fn' stack in text."""
    frames: List[str] = []
    last = -1
    for m in SAN_FRAME.finditer(text):
        n = int(m.group(1))
        if frames and (n <= last or "\n\n" in text[prev_end:m.start()] or re.search(r"\n\S", text[prev_end:m.start()])):
            break
        frames.append(m.group(2))
        last, prev_end = n, m.end()
    return frames


def parse_signature(text: str) -> Optional[Signature]:
    """Find the first crash signature in text: sanitizer report, gdb backtrace, Python/JS traceback, SIGSEGV."""
    for pat, tool in SANITIZER_KINDS:
        m = re.search(pat, text)
        if m:
            kind = f"{tool}:{m.group(1).strip().replace(' ', '-')}"
            if tool == "ubsan":
                loc = re.search(r"([\w./-]+\.\w+):(\d+):\d+: runtime error", text)
                frames = [f for f in _first_stack(text[m.start():]) if not SKIP_FRAMES.match(f)]
                if not frames and loc:
                    frames = [loc.group(1).split("/")[-1]]
                return Signature(kind, [_norm_frame(f) for f in frames][:5])
            frames = [f for f in _first_stack(text[m.start():]) if not SKIP_FRAMES.match(f)]
            if not frames:
                frames = [f for f in _first_stack(text) if not SKIP_FRAMES.match(f)]
            return Signature(kind, [_norm_frame(f) for f in frames][:5])
    if re.search(r"Traceback \(most recent call last\)", text):
        frames = [fn for _, _, fn in PY_FRAME.findall(text)]
        exc = re.findall(r"^(\w+(?:\.\w+)*(?:Error|Exception|Exit|Interrupt|Warning)):?", text, re.M)
        frames = [f for f in reversed(frames) if not SKIP_FRAMES.match(f)]
        return Signature("python:" + (exc[-1].split(".")[-1] if exc else "exception"), frames[:5])
    segv = re.search(r"SIGSEGV|Segmentation fault|SIGABRT|Aborted \(core dumped\)|SIGBUS|stack overflow", text, re.I)
    if segv or re.search(r"^\s*#0\s+", text, re.M):
        frames = [f for _, f, _ in GDB_FRAME.findall(text) if not SKIP_FRAMES.match(f)]
        kind = "segv"
        if segv:
            w = segv.group(0).lower()
            kind = "abort" if "abort" in w else "stack-overflow" if "stack" in w else "segv"
        if segv or frames:
            return Signature(kind, [_norm_frame(f) for f in frames][:5])
    m = re.search(r"^(?:Uncaught\s+)?(\w*Error|RangeError|TypeError): .*$", text, re.M)
    if m and JS_FRAME.search(text[m.end():]):
        frames = [f.split(".")[-1] for f, _ in JS_FRAME.findall(text[m.end():])]
        return Signature("js:" + m.group(1), [f for f in frames if f not in ("Module", "Object")][:5])
    return None


def _blocks(body: str) -> List[CodeBlock]:
    out = []
    for m in CODE_BLOCK.finditer(body):
        raw = m.group(2).lower()
        code = m.group(3)
        lang = POC_LANGS.get(raw, "")
        before = body[max(0, m.start() - 200):m.start()]
        fn = None
        prev = [ln for ln in before.splitlines() if ln.strip()]
        hint = re.findall(r"[`\"']?([\w.-]+\.(?:c|cc|cpp|py|js|mjs|sh|go|rs|rb|php))[`\"']?", prev[-1] if prev else "")
        if hint:
            fn = hint[-1]
        if not lang and raw in OUTPUT_LANGS:
            # an untagged block of "$ cmd" lines is a shell PoC; sanitizer logs are output
            lines = [ln for ln in code.splitlines() if ln.strip()]
            if lines and sum(ln.lstrip().startswith("$ ") for ln in lines) >= 1 and not parse_signature(code):
                lang = "sh"
            elif fn and raw == "":
                lang = POC_LANGS.get(fn.rsplit(".", 1)[-1], "")
        if lang == "sh" and parse_signature(code) and not re.search(r"^\s*\$ ", code, re.M):
            lang = ""  # a pasted crash log tagged as console
        out.append(CodeBlock(lang=lang, raw_lang=raw, code=code, filename=fn))
    return out


def classify(text: str) -> Set[str]:
    found = set(re.findall(r"\bCWE-\d+\b", text, re.I))
    found = {c.upper() for c in found}
    low = text.lower()
    for pat, cwe, _ in CWE_RULES:
        if re.search(pat, low):
            found.add(cwe)
    return found


STOP_FUNCS = {"main", "printf", "if", "for", "while", "return", "sizeof", "malloc", "free", "memcpy", "strcpy",
              "strlen", "print", "len", "require", "import", "exec", "eval", "assert", "calloc", "realloc",
              "fprintf", "sprintf", "snprintf", "puts", "exit", "abort", "open", "read", "write", "close",
              "e.g", "i.e", "fork", "system", "memset", "memmove", "strcmp", "strncpy", "strncmp", "console.log"}


def parse_report(text: str, rid: str, source: str = "") -> Report:
    meta: Dict[str, str] = {}
    for k, v in HEADER_LINE.findall(text[:2000]):
        meta.setdefault(k.lower(), v.strip())
    title = meta.get("subject") or meta.get("title") or ""
    if not title:
        h = HEADING.search(text)
        title = h.group(1).strip() if h else next((ln.strip() for ln in text.splitlines() if ln.strip()), rid)
    title = re.sub(r"^(re|fwd?):\s*", "", title, flags=re.I)[:160]
    r = Report(id=rid, title=title, body=text, source=source, meta=meta,
               reporter=meta.get("from") or meta.get("reporter") or "",
               date=meta.get("date") or meta.get("reported") or "")
    r.blocks = _blocks(text)
    prose = r.prose
    r.cwes = classify(title + "\n" + prose)
    ref_text = prose + "\n" + "\n".join(b.code for b in r.blocks if not b.lang)
    for m in FILE_RE.finditer(ref_text):
        f = m.group(1)
        if f.startswith(("http", "www.")) or re.match(r"^\d+\.\d+", f) or f.lower() in {"e.g", "i.e"}:
            continue
        pre = ref_text[max(0, m.start() - 12):m.start()]
        if pre.endswith(("<", "../", "/tmp/", "/usr/", "/lib/")) or re.search(r"(\.\./|/usr/|/tmp/|/lib\w*/|libsanitizer/)[\w./-]*$", pre):
            continue
        r.files.add(f)
        if m.group(2):
            r.file_lines.add((f, int(m.group(2))))
    funcs = set(FUNC_RE.findall(prose)) | {f for f in FUNC_IN_CODE_RE.findall(prose) if "_" in f or "::" in f or re.search(r"[a-z][A-Z]", f)}
    r.functions = {f for f in funcs if f.lower() not in STOP_FUNCS and not re.match(r"^[A-Z0-9_]+$", f) and len(f) > 2}
    r.signature = r.reported_signature = parse_signature(text)
    for rx in ENTITY_RES:
        for e in rx.findall(title + "\n" + prose):
            e = e.lower().rstrip(".")
            if e not in STOP_FUNCS and not re.match(r"^\d", e) and e not in {"e.g", "i.e"}:
                r.entities.add(e)
    if r.signature:
        r.functions |= {f for f in r.signature.frames if f.lower() not in STOP_FUNCS}
    for m in VERSION_RE.finditer(prose[:6000]):
        v = m.group(1) or m.group(2) or m.group(3)
        if m.group(1) and CVSS_SCORE.search(prose[max(0, m.start() - 30):m.end()]):
            continue
        r.versions.add(v)
    for k in ("version", "commit"):
        if k in meta:
            r.versions.add(meta[k])
    vec = CVSS_VEC.search(text)
    r.cvss_vector = vec.group(0) if vec else ""
    sc = CVSS_SCORE.search(text)
    if sc:
        try:
            val = float(sc.group(1))
            if 0 <= val <= 10:
                r.cvss_score = val
        except ValueError:
            pass
    sw = SEVERITY_WORD.search(text)
    if sw:
        r.severity_claim = (sw.group(1) or sw.group(2)).lower()
    elif r.cvss_score is not None:
        s = r.cvss_score
        r.severity_claim = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
    r.has_steps = bool(STEPS_RE.search(prose)) or bool(r.poc_blocks)
    r.has_impact = bool(IMPACT_RE.search(prose))
    return r
