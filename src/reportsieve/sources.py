"""Load reports and known advisories from files, mailboxes exports, GitHub and OSV."""
from __future__ import annotations

import email
import email.policy
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import List, Optional

from . import __version__
from .extract import Report, parse_report

REPORT_EXT = (".md", ".markdown", ".txt", ".eml", ".json", ".text")


class SourceError(Exception):
    pass


def _http_json(url: str, data: Optional[dict] = None, token: Optional[str] = None):
    headers = {"User-Agent": f"reportsieve/{__version__}", "Accept": "application/json"}
    if "api.github.com" in url:
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if token:
            headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise SourceError(f"{url}: HTTP {e.code} {e.reason}") from None
    except urllib.error.URLError as e:
        raise SourceError(f"{url}: {e.reason}") from None


def _gh_token() -> Optional[str]:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _from_record(d: dict, fallback_id: str, source: str) -> Report:
    rid = str(d.get("ghsa_id") or d.get("id") or d.get("report_id") or fallback_id)
    title = d.get("summary") or d.get("title") or ""
    body = d.get("description") or d.get("details") or d.get("body") or d.get("vulnerability_information") or ""
    extra = []
    for k in ("aliases", "cve_id", "cwe_ids", "cwes"):
        val = d.get(k)
        if isinstance(val, list):
            extra.extend(x if isinstance(x, str) else x.get("cwe_id", "") for x in val)
        elif isinstance(val, str):
            extra.append(val)
    vulns = d.get("vulnerabilities") or d.get("affected") or []
    for vv in vulns if isinstance(vulns, list) else []:
        pk = vv.get("package") or {}
        extra.append(" ".join(str(pk.get(x, "")) for x in ("ecosystem", "name")))
        for k in ("vulnerable_version_range", "patched_versions"):
            if vv.get(k):
                extra.append(f"{k.replace('_', ' ')}: {vv[k]}")
    text = f"# {title}\n\n{body}\n\n" + "\n".join(x for x in extra if x)
    author = d.get("author")
    who = d.get("reporter") or (author.get("login", "") if isinstance(author, dict) else "")
    r = parse_report(text, rid, source)
    r.title = title or r.title
    r.reporter = who or r.reporter
    r.date = str(d.get("created_at") or d.get("published") or d.get("published_at") or d.get("date") or "")
    return r


def load_file(path: str) -> List[Report]:
    rid = os.path.splitext(os.path.basename(path))[0]
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        items = data if isinstance(data, list) else data.get("reports") or data.get("vulns") or [data]
        return [_from_record(d, f"{rid}-{i + 1}", path) for i, d in enumerate(items)]
    with open(path, "rb") as fh:
        raw = fh.read()
    if path.endswith(".eml") or raw[:200].lower().startswith((b"from:", b"return-path:", b"received:", b"subject:", b"message-id:", b"delivered-to:")) and b"\n\n" in raw:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        part = msg.get_body(preferencelist=("plain", "html"))
        body = part.get_content() if part else ""
        if part is not None and part.get_content_type() == "text/html":
            body = re.sub(r"<[^>]+>", " ", body)
        text = f"Subject: {msg.get('subject', '')}\nFrom: {msg.get('from', '')}\nDate: {msg.get('date', '')}\n\n{body}"
        return [parse_report(text, rid, path)]
    return [parse_report(raw.decode("utf-8", errors="replace"), rid, path)]


def load_paths(paths: List[str]) -> List[Report]:
    out: List[Report] = []
    for p in paths:
        if p == "-":
            out.append(parse_report(sys.stdin.read(), "stdin", "stdin"))
        elif p.startswith("gh:"):
            out.extend(github_advisories(p[3:], state="triage"))
        elif os.path.isdir(p):
            for fn in sorted(os.listdir(p)):
                full = os.path.join(p, fn)
                if os.path.isfile(full) and fn.lower().endswith(REPORT_EXT) and not fn.startswith((".", "README")):
                    out.extend(load_file(full))
        elif os.path.isfile(p):
            out.extend(load_file(p))
        else:
            raise SourceError(f"no such file, directory or source: {p}")
    seen = {}
    for r in out:
        if r.id in seen:
            seen[r.id] += 1
            r.id = f"{r.id}-{seen[r.id]}"
        else:
            seen[r.id] = 1
    return out


def github_advisories(repo: str, state: str = "published") -> List[Report]:
    if not re.match(r"^[\w.-]+/[\w.-]+$", repo):
        raise SourceError(f"expected owner/repo, got {repo!r}")
    token = _gh_token()
    if state != "published" and not token:
        raise SourceError("reading draft/triage advisories needs GITHUB_TOKEN with admin or security-manager access")
    out: List[Report] = []
    page = 1
    while page < 20:
        url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100&page={page}&state={state}"
        items = _http_json(url, token=token)
        if not items:
            break
        out.extend(_from_record(d, f"adv-{i}", f"gh:{repo}") for i, d in enumerate(items))
        if len(items) < 100:
            break
        page += 1
    return out


def osv_known(spec: str) -> List[Report]:
    """spec: Ecosystem/name, e.g. PyPI/requests, npm/undici, OSS-Fuzz/curl."""
    if "/" not in spec:
        raise SourceError("osv source must look like osv:<Ecosystem>/<package>, e.g. osv:PyPI/requests")
    eco, name = spec.split("/", 1)
    data = _http_json("https://api.osv.dev/v1/query", {"package": {"ecosystem": eco, "name": name}})
    vulns = data.get("vulns", [])
    return [_from_record(v, v.get("id", f"osv-{i}"), f"osv:{spec}") for i, v in enumerate(vulns)]


def load_known(specs: List[str]) -> List[Report]:
    out: List[Report] = []
    for s in specs:
        if s.startswith("gh:"):
            out.extend(github_advisories(s[3:], state="published"))
        elif s.startswith("osv:"):
            out.extend(osv_known(s[4:]))
        else:
            out.extend(load_paths([s]))
    return out
