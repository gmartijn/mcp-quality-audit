#!/usr/bin/env python3
# mcp_quality_audit.py — MCP registry + GitHub audit (integrated metrics, 4-level risk, explainable)
import argparse
import csv
import json
import os
import re
import sys
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dateutil import parser as dtparser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
console_err = Console(stderr=True)

# Optional PDF/report deps
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
except Exception:
    plt = None
    PdfPages = None

# ------------------ Registry API ------------------
DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io"
API_PREFIX = "/v0"
PATH_SERVERS = f"{API_PREFIX}/servers"

# ------------------ GitHub API ------------------
API_BASE = os.getenv("GITHUB_API_BASE", "https://api.github.com")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

GH_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "mcp-quality-audit/1.3"
}
if GITHUB_TOKEN:
    GH_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"
else:
    console_err.print("[yellow]Warning: No GITHUB_TOKEN set; you may hit rate limits quickly.[/yellow]")

# Single shared session so we can toggle SSL verification globally + retries
SESSION = requests.Session()

# Add retrying + default timeouts to the session
DEFAULT_TIMEOUT = 20  # seconds
class _TimeoutAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_retries", Retry(
            total=3,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
            raise_on_status=False,
        ))
        super().__init__(*args, **kwargs)
    def send(self, request, **kwargs):
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return super().send(request, **kwargs)

# Remove global GitHub headers from the shared session; we will pass them only in gh_api()
# SESSION.headers.update(GH_HEADERS)  # ← removed
SESSION.mount("https://", _TimeoutAdapter())
SESSION.mount("http://", _TimeoutAdapter())

# ------------------ Defaults ------------------
DEFAULT_WEIGHTS = {
    "publisher_trust": 0.30,
    "security_posture": 0.30,
    "maintenance": 0.25,
    "license": 0.10,
    "privacy_signal": 0.05,
}

# Allowed risk labels (4-level scale)
ALLOWED_RATINGS = ["low", "medium", "high", "critical"]

# thresholds are MINIMUM score → rating; pick the highest min <= score
DEFAULT_RISK_THRESHOLDS = {
    "low": 75,
    "medium": 60,
    "high": 40,
    "critical": 0
}

RATING_STYLES = {
    "low": "green",
    "medium": "yellow3",
    "high": "dark_orange",
    "critical": "red",
}

# ------------------ HTTP helpers ------------------
def get_json(url: str, headers: Optional[Dict[str, str]] = None, timeout=DEFAULT_TIMEOUT, params: Optional[dict]=None) -> Optional[dict]:
    try:
        r = SESSION.get(url, headers=headers, timeout=timeout, params=params)
        # surface GH ratelimit
        if "api.github.com" in url and r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
            reset = r.headers.get("X-RateLimit-Reset")
            when = ""
            try:
                if reset:
                    ts = datetime.utcfromtimestamp(int(reset)).strftime("%Y-%m-%d %H:%M:%S UTC")
                    when = f" until {ts}"
            except Exception:
                pass
            console_err.print(f"[yellow]GitHub rate limit exceeded{when}. Set GITHUB_TOKEN or retry later.[/yellow]")
            return None
        if r.status_code == 200:
            return r.json()
        # Log non-GitHub non-200 responses so --list failures aren’t silent
        if "api.github.com" not in url:
            console_err.print(f"[red]HTTP {r.status_code}[/red] fetching {url}")
        return None
    except Exception as e:
        # Log non-GitHub exceptions
        if "api.github.com" not in url:
            console_err.print(f"[red]Request failed[/red] {url}: {e}")
        return None

# ------------------ Config helpers ------------------
def _load_json_str_or_file(s: Optional[str], path: Optional[str]) -> Optional[dict]:
    data = None
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            console_err.print(f"[red]Failed to load JSON file[/red] {path}: {e}")
    elif s:
        try:
            data = json.loads(s)
        except Exception as e:
            console_err.print(f"[red]Failed to parse JSON string[/red]: {e}")
    return data

def resolve_weights(weights_arg: Optional[str], weights_file: Optional[str]) -> Dict[str, float]:
    w = dict(DEFAULT_WEIGHTS)
    override = _load_json_str_or_file(weights_arg, weights_file)
    if isinstance(override, dict):
        for k in override.keys():
            if k not in DEFAULT_WEIGHTS:
                console_err.print(f"[yellow]Ignoring unknown weight key: {k}[/yellow]")
        w.update({k: float(v) for k, v in override.items() if k in DEFAULT_WEIGHTS})
    s = sum(w.values())
    if s <= 0:
        w = dict(DEFAULT_WEIGHTS)
        s = sum(w.values())
    if abs(s - 1.0) > 1e-6:
        w = {k: v / s for k, v in w.items()}
        console_err.print("[dim]Weights normalized to sum to 1.0[/dim]")
    return w

def resolve_thresholds(th_arg: Optional[str], th_file: Optional[str]) -> Dict[str, float]:
    t = dict(DEFAULT_RISK_THRESHOLDS)
    override = _load_json_str_or_file(th_arg, th_file)
    if isinstance(override, dict):
        filtered = {}
        for k, v in override.items():
            k_l = str(k).lower()
            if k_l in ALLOWED_RATINGS:
                try:
                    filtered[k_l] = float(v)
                except Exception:
                    pass
        if filtered:
            t.update(filtered)
    if "critical" not in t:
        t["critical"] = 0.0
    ordered = ["low", "medium", "high", "critical"]
    mins = [t.get(k, 0) for k in ordered]
    if not all(x >= y for x, y in zip(mins, mins[1:])):
        console_err.print("[yellow]Warning: risk thresholds are non-monotonic; results may be surprising.[/yellow]")
    return t

def rating_from_score(score: float, thresholds: Dict[str, float]) -> str:
    items = [(k, thresholds.get(k, -1e9)) for k in ALLOWED_RATINGS]
    items = sorted(items, key=lambda kv: kv[1], reverse=True)
    for label, minimum in items:
        if score >= minimum:
            return label
    return "critical"

# ------------------ Registry lookups ------------------
def _extract_items_and_next(payload: Any) -> Tuple[List[dict], Optional[str]]:
    if not isinstance(payload, dict):
        return [], None
    items = payload.get("servers") or payload.get("items") or payload.get("results") or payload.get("data") or []
    # If "servers" (or other) is an envelope with an "items" list, unwrap it
    if isinstance(items, dict):
        inner = items.get("items") or items.get("results") or items.get("servers")
        if isinstance(inner, list):
            items = inner
    meta = payload.get("metadata") or payload.get("meta") or {}
    nxt = (
        meta.get("next_cursor")
        or meta.get("nextCursor")
        or payload.get("next_cursor")
        or payload.get("nextCursor")
        or payload.get("next")
        or (items.get("next") if isinstance(items, dict) else None)
    )
    if isinstance(nxt, str) and nxt.strip() == "":
        nxt = None
    return items if isinstance(items, list) else [], nxt

def try_registry_lookup(registry: str, mcp_name: str, fuzzy: bool) -> Tuple[Optional[dict], List[dict]]:
    base = registry.rstrip("/")
    data = get_json(f"{base}{PATH_SERVERS}/{mcp_name}")
    if isinstance(data, dict) and data:
        return data, [data]
    payload = get_json(f"{base}{PATH_SERVERS}", params={"search": mcp_name, "limit": 50})
    items, _ = _extract_items_and_next(payload)
    best = None
    def name_of(x):
        return x.get("name") or x.get("id") or x.get("slug") or x.get("namespace") or x.get("full_name")
    for x in items:
        if name_of(x) == mcp_name:
            best = x
            break
    if fuzzy and not best and items:
        best = items[0]
    return best, items or []

def list_all_servers(registry: str, limit: int = 200, page_size: int = 100) -> List[dict]:
    base = registry.rstrip("/")
    results: List[dict] = []
    cursor = None
    while len(results) < limit:
        params = {"limit": min(page_size, 100)}
        if cursor:
            params["cursor"] = cursor
        payload = get_json(f"{base}{PATH_SERVERS}", params=params)
        items, cursor = _extract_items_and_next(payload)
        if not items:
            break
        results.extend(items)
        if not cursor:
            break
    return results[:limit]

def filter_servers(servers: List[dict], query: Optional[str]) -> List[dict]:
    if not query:
        return servers
    q = query.lower()
    def blob(s: dict) -> str:
        parts = [
            s.get("name"), s.get("id"), s.get("namespace"),
            s.get("description"), s.get("publisher"), s.get("owner")
        ]
        return " ".join([str(p) for p in parts if p])
    return [s for s in servers if q in blob(s).lower()]

# ------------------ Listing helpers ------------------
def unwrap_entry(entry: Any) -> Any:
    """
    Unwrap common envelope shapes like {'server': {...}} or {'package': {...}}
    so field lookups work across registries.
    """
    if not isinstance(entry, dict):
        return entry
    for key in ("server", "item", "entry", "package", "data", "node", "attributes"):
        inner = entry.get(key)
        if isinstance(inner, dict):
            if any(k in inner for k in ("name", "id", "namespace", "slug", "full_name", "display_name", "displayName", "title")):
                return inner
    return entry

def _first_str(d: dict, keys: List[str]) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return None

# ------------------ Repo utilities ------------------
def extract_repo_url(entry: dict) -> Optional[str]:
    # Unwrap common container shapes first
    entry = unwrap_entry(entry)
    for k in ("repo", "repository", "github", "source", "homepage", "url", "website"):
        v = entry.get(k)
        if isinstance(v, str) and "github.com" in v:
            return v
        if isinstance(v, dict):
            for vv in v.values():
                if isinstance(vv, str) and "github.com" in vv:
                    return vv
    meta = entry.get("_meta") or entry.get("metadata") or {}
    if isinstance(meta, dict):
        for _, v in meta.items():
            if isinstance(v, str) and "github.com" in v:
                return v
    pkgs = entry.get("packages") or []
    for p in pkgs:
        src = p.get("source") or p.get("url")
        if isinstance(src, str) and "github.com" in src:
            return src
    return None

def gh_api(path: str) -> Optional[dict]:
    # Pass GitHub headers explicitly only for GitHub API calls
    return get_json(API_BASE + path, headers=GH_HEADERS)

def parse_github_owner_repo(url: str) -> Optional[Tuple[str, str]]:
    m = re.search(r"github\.com/([^/]+)/([^/#]+)", url or "")
    if not m:
        return None
    return m.group(1), m.group(2).replace(".git", "")

def github_repo_stats(repo_url: str, *, max_commits: int = 500, no_deps: bool = False) -> Dict[str, Any]:
    out = {"repo_url": repo_url}
    parsed = parse_github_owner_repo(repo_url)
    if not parsed:
        return out
    owner, repo = parsed

    repo_data = gh_api(f"/repos/{owner}/{repo}") or {}
    out.update({
        "stars": repo_data.get("stargazers_count"),
        "forks": repo_data.get("forks_count"),
        "open_issues": repo_data.get("open_issues_count"),
        "license": (repo_data.get("license") or {}).get("spdx_id"),
        "pushed_at": repo_data.get("pushed_at"),
        "updated_at": repo_data.get("updated_at"),
        "archived": repo_data.get("archived"),
        "disabled": repo_data.get("disabled"),
        "homepage": repo_data.get("homepage"),
        "language": repo_data.get("language"),
        "has_issues": repo_data.get("has_issues"),
        "default_branch": repo_data.get("default_branch") or "HEAD",
    })

    owner_data = gh_api(f"/users/{owner}") or {}
    out.update({
        "owner_type": owner_data.get("type"),
        "org_is_verified_guess": owner_data.get("is_verified"),
    })

    commits = gh_api(f"/repos/{owner}/{repo}/commits?sha={out['default_branch']}&per_page=1")
    if isinstance(commits, list) and commits:
        out["latest_commit"] = (commits[0].get("commit", {}).get("committer", {}) or {}).get("date")

    def _looks_bot(login: Optional[str]) -> bool:
        if not login: return False
        l = login.lower()
        return l.endswith("[bot]") or l.endswith("-bot") or l.startswith("bot-")

    since_iso = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat().replace("+00:00", "Z")
    devs = set()
    page = 1
    while True:
        page_commits = gh_api(f"/repos/{owner}/{repo}/commits?since={since_iso}&per_page=100&page={page}")
        if not isinstance(page_commits, list) or not page_commits:
            break
        for c in page_commits:
            for who in ("author","committer"):
                user = c.get(who) or {}
                login = user.get("login")
                if login and not _looks_bot(login):
                    devs.add(login)
        page += 1
        if page > 10:
            break
    out["active_devs_90d"] = len(devs)

    def _has_path(path: str) -> bool:
        resp = gh_api(f"/repos/{owner}/{repo}/contents/{path}")
        return bool(resp and resp.get("download_url"))
    out["has_security_md"] = any(_has_path(p) for p in (".github/SECURITY.md","SECURITY.md","docs/SECURITY.md"))

    signed, total = 0, 0
    page = 1
    while total < max_commits:
        batch = gh_api(f"/repos/{owner}/{repo}/commits?per_page=100&page={page}")
        if not isinstance(batch, list) or not batch:
            break
        for c in batch:
            if total >= max_commits:
                break
            ver = (c.get("commit") or {}).get("verification") or {}
            if ver.get("verified"):
                signed += 1
            total += 1
        page += 1
    out["signed_commits"] = signed
    out["signed_commits_sampled"] = total
    out["signed_commits_ratio"] = (signed / total) if total else None

    if not no_deps:
        sbom = gh_api(f"/repos/{owner}/{repo}/dependency-graph/sbom") or {}
        status = sbom.get("message")
        if sbom and "sbom" in sbom:
            out["dep_graph_enabled"] = True
            packages = (sbom.get("sbom") or {}).get("packages") or []
            out["sbom_package_count"] = len(packages)
        elif status == "Accepted":
            out["dep_graph_enabled"] = True
            out["sbom_package_count"] = None
        else:
            out["dep_graph_enabled"] = False
            out["sbom_package_count"] = None

        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
        page = 1
        total_alerts = 0
        while True:
            alerts = gh_api(f"/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100&page={page}")
            if alerts is None:
                total_alerts = None
                severities = None
                break
            if not isinstance(alerts, list) or not alerts:
                break
            for a in alerts:
                sev = ((a.get("security_vulnerability") or {}).get("severity") or "none").lower()
                if sev not in severities:
                    sev = "none"
                severities[sev] += 1
                total_alerts += 1
            if len(alerts) < 100:
                break
            page += 1
        out["dependabot_alerts_total"] = total_alerts
        out["dependabot_alerts_by_severity"] = severities
    else:
        out["dep_graph_enabled"] = None
        out["sbom_package_count"] = None
        out["dependabot_alerts_total"] = None
        out["dependabot_alerts_by_severity"] = None

    issues = gh_api(f"/search/issues?q=repo:{owner}/{repo}+security+in:title,body") or {}
    out["security_issue_hits"] = issues.get("total_count")

    readme = gh_api(f"/repos/{owner}/{repo}/readme")
    if readme and "download_url" in readme:
        try:
            txt = SESSION.get(readme["download_url"], timeout=20).text.lower()
            out["gdpr_mentions"] = any(k in txt for k in ("gdpr","general data protection regulation","privacy","data residency","eu data"))
            out["privacy_policy_linked"] = ("privacy policy" in txt) or ("privacy-policy" in txt)
        except Exception:
            pass

    return out

SECRET_SMELLS = [
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----",
    r"api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    r"secret\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    r"x-api-key\s*:\s*[A-Za-z0-9_\-]{16,}",
    r"ghp_[A-Za-z0-9]{36,}",
]

def shallow_secret_scan(repo_url: str, limit_files=50) -> Dict[str, Any]:
    out = {"scanned_files": 0, "hits": [], "truncated": False}
    parsed = parse_github_owner_repo(repo_url)
    if not parsed:
        return out
    owner, repo = parsed
    meta = gh_api(f"/repos/{owner}/{repo}") or {}
    branch = meta.get("default_branch") or "HEAD"
    tree = gh_api(f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
    if not tree or "tree" not in tree:
        return out
    files = [t for t in tree["tree"] if t.get("type") == "blob"]
    out["truncated"] = bool(tree.get("truncated"))
    sample = [f for f in files if not f["path"].lower().endswith((
        ".png",".jpg",".jpeg",".gif",".pdf",".zip",".gz",".jar",".exe",".dll",".webp",".svg"
    ))]
    random.seed(f"{owner}/{repo}")
    random.shuffle(sample)
    sample = sample[:limit_files]
    for f in sample:
        blob = gh_api(f"/repos/{owner}/{repo}/contents/{f['path']}")
        if not blob or "download_url" not in blob:
            continue
        try:
            txt = SESSION.get(blob["download_url"], timeout=15).text
        except Exception:
            continue
        out["scanned_files"] += 1
        for pat in SECRET_SMELLS:
            if re.search(pat, txt):
                out["hits"].append({"path": f["path"], "pattern": pat})
    return out

# ------------------ Scoring / reporting ------------------
def calc_scores(entry: dict, repo_stats: Dict[str, Any], secret_scan: Dict[str, Any], *, explain: bool=False) -> Tuple[Dict[str, Any], Optional[dict]]:
    """
    Return (scores_dict, explanation_dict|None).
    Scores integrate richer GitHub metrics into the 5-dimension model.
    """
    def clamp(x: float) -> float:
        return max(0.0, min(100.0, x))

    POPULAR_LANGS = {
        "python", "javascript", "typescript", "go", "rust",
        "java", "c#", "kotlin", "swift"
    }

    explanation = {
        "publisher_trust": {"steps": []},
        "maintenance": {"steps": []},
        "license": {"steps": []},
        "privacy_signal": {"steps": []},
        "security_posture": {"steps": []},
        "overall": {},
        "rating": {}
    } if explain else None

    scores: Dict[str, float] = {}

    # Publisher trust
    base_pt = 70.0
    pt = base_pt
    if explain: explanation["publisher_trust"]["steps"].append({"reason": "Base", "value": base_pt})
    ns = entry.get("namespace") or entry.get("name") or entry.get("id") or ""
    explicit_verified = entry.get("verified") or entry.get("publisher_verified") or entry.get("is_verified")
    namespace_verified = bool(explicit_verified) or ns.startswith("io.github.") or re.match(r"([a-z0-9-]+\.)+[a-z]{2,}/", ns)
    if namespace_verified:
        pt += 15
        if explain: explanation["publisher_trust"]["steps"].append({"reason": "Namespace/registry verified", "delta": +15})
    if repo_stats.get("org_is_verified_guess"):
        pt += 15
        if explain: explanation["publisher_trust"]["steps"].append({"reason": "GitHub org verified", "delta": +15})
    pt = clamp(pt)
    scores["publisher_trust"] = pt
    if explain: explanation["publisher_trust"]["final"] = pt

    # Maintenance
    if explain: explanation["maintenance"]["steps"].append({"reason": "Base from recency buckets"})
    latest = repo_stats.get("latest_commit") or repo_stats.get("pushed_at") or repo_stats.get("updated_at")
    days = None
    if latest:
        try:
            dt = dtparser.parse(latest)
            days = (datetime.now(timezone.utc) - dt).days
        except Exception:
            pass
    if days is None:
        maint = 35
        if explain: explanation["maintenance"]["steps"].append({"reason": "No recent commit info", "value": 35})
    elif days <= 30:
        maint = 95
        if explain: explanation["maintenance"]["steps"].append({"reason": "Latest commit ≤30 days", "value": 95})
    elif days <= 90:
        maint = 80
        if explain: explanation["maintenance"]["steps"].append({"reason": "Latest commit ≤90 days", "value": 80})
    elif days <= 180:
        maint = 65
        if explain: explanation["maintenance"]["steps"].append({"reason": "Latest commit ≤180 days", "value": 65})
    elif days <= 365:
        maint = 55
        if explain: explanation["maintenance"]["steps"].append({"reason": "Latest commit ≤365 days", "value": 55})
    else:
        maint = 35
        if explain: explanation["maintenance"]["steps"].append({"reason": "Latest commit >365 days", "value": 35})

    devs = int(repo_stats.get("active_devs_90d") or 0)
    if devs >= 10:
        maint += 10
        if explain: explanation["maintenance"]["steps"].append({"reason": "Active devs ≥10 (90d)", "delta": +10})
    elif devs >= 5:
        maint += 5
        if explain: explanation["maintenance"]["steps"].append({"reason": "Active devs ≥5 (90d)", "delta": +5})
    elif devs == 0 and (days is not None and days > 180):
        maint -= 10
        if explain: explanation["maintenance"]["steps"].append({"reason": "0 active devs & stale >180d", "delta": -10})

    if repo_stats.get("has_issues") is True:
        maint += 3
        if explain: explanation["maintenance"]["steps"].append({"reason": "Issue tracking enabled", "delta": +3})
    elif repo_stats.get("has_issues") is False:
        maint -= 5
        if explain: explanation["maintenance"]["steps"].append({"reason": "Issue tracking disabled", "delta": -5})

    lang = (repo_stats.get("language") or "").strip().lower()
    if lang in POPULAR_LANGS:
        maint += 3
        if explain: explanation["maintenance"]["steps"].append({"reason": f"Popular language: {lang}", "delta": +3})

    if repo_stats.get("archived") or repo_stats.get("disabled"):
        old_maint = maint
        maint = min(maint, 20)
        if explain: explanation["maintenance"]["steps"].append({"reason": "Archived/disabled: cap to ≤20", "from": old_maint, "to": maint})

    maint = clamp(maint)
    scores["maintenance"] = maint
    if explain: explanation["maintenance"]["final"] = maint

    # License
    lic = (repo_stats.get("license") or "").upper()
    if lic in {"MIT","APACHE-2.0","BSD-2-CLAUSE","BSD-3-CLAUSE","MPL-2.0"}:
        lic_score = 100
        rule = f"{lic or 'permissive family'} → 100"
    elif lic in {"GPL-3.0","AGPL-3.0","LGPL-3.0"}:
        lic_score = 75
        rule = f"{lic} → 75"
    elif lic:
        lic_score = 70
        rule = f"{lic} (other) → 70"
    else:
        lic_score = 40
        rule = "No license → 40"
    lic_score = clamp(lic_score)
    scores["license"] = lic_score
    if explain:
        explanation["license"]["steps"].append({"reason": "License rule", "value": rule})
        explanation["license"]["final"] = lic_score

    # Privacy
    gdpr = bool(repo_stats.get("gdpr_mentions"))
    privacy_url_hint = bool(str(repo_stats.get("homepage") or "").lower().find("privacy") != -1)
    if gdpr:
        pr = 85
        why = "README mentions GDPR/privacy/data residency"
    elif privacy_url_hint or repo_stats.get("privacy_policy_linked"):
        pr = 70
        why = "Privacy policy hinted/linked"
    else:
        pr = 60
        why = "No explicit privacy signals"
    pr = clamp(pr)
    scores["privacy_signal"] = pr
    if explain:
        explanation["privacy_signal"]["steps"].append({"reason": why, "value": pr})
        explanation["privacy_signal"]["final"] = pr

    # Security posture
    sec = 100.0
    if explain: explanation["security_posture"]["steps"].append({"reason": "Base", "value": 100})

    sec_hits = int(repo_stats.get("security_issue_hits") or 0)
    if sec_hits >= 3:
        sec -= 10; eff=-10
    elif sec_hits == 2:
        sec -= 6; eff=-6
    elif sec_hits == 1:
        sec -= 3; eff=-3
    else:
        eff = 0
    if explain and eff:
        explanation["security_posture"]["steps"].append({"reason": "Security keyword issue hits", "delta": eff, "hits": sec_hits})

    secret_hits = len(secret_scan.get("hits") or [])
    if secret_hits > 0:
        sec -= 40
        if explain: explanation["security_posture"]["steps"].append({"reason": "Secret scan hits", "delta": -40, "matches": secret_hits})

    if repo_stats.get("has_security_md"):
        sec += 5
        if explain: explanation["security_posture"]["steps"].append({"reason": "SECURITY.md present", "delta": +5})

    scr = repo_stats.get("signed_commits_ratio")
    if isinstance(scr, (int, float)):
        if scr >= 0.75:
            sec += 6; add = +6
        elif scr >= 0.5:
            sec += 3; add = +3
        else:
            add = 0
        if explain and add:
            explanation["security_posture"]["steps"].append({"reason": "Signed commits ratio", "delta": add, "ratio": round(scr, 3)})

    sev = repo_stats.get("dependabot_alerts_by_severity")
    if isinstance(sev, dict):
        penalty = ((sev.get("critical",0)*4.0) + (sev.get("high",0)*2.0) +
                   (sev.get("medium",0)*1.0) + (sev.get("low",0)*0.5))
        penalty = min(penalty, 30.0)
        if penalty:
            sec -= penalty
            if explain:
                explanation["security_posture"]["steps"].append({
                    "reason": "Dependabot open alerts penalty (clamped ≤30)",
                    "delta": -penalty,
                    "by_severity": {k:int(v) for k,v in sev.items()}
                })

    if repo_stats.get("dep_graph_enabled") is True:
        sec += 4
        if explain: explanation["security_posture"]["steps"].append({"reason": "Dependency graph enabled", "delta": +4})
        if isinstance(repo_stats.get("sbom_package_count"), int) and repo_stats.get("sbom_package_count") > 0:
            sec += 2
            if explain: explanation["security_posture"]["steps"].append({"reason": "SBOM packages present", "delta": +2})

    if repo_stats.get("archived") or repo_stats.get("disabled"):
        sec -= 10
        if explain: explanation["security_posture"]["steps"].append({"reason": "Archived/disabled", "delta": -10})

    sec = clamp(sec)
    scores["security_posture"] = sec
    if explain: explanation["security_posture"]["final"] = sec

    return scores, explanation

def overall_from(scores: Dict[str, float], weights: Dict[str, float]) -> float:
    total = 0.0
    for k, v in scores.items():
        w = float(weights.get(k, 0.0))
        total += w * float(v)
    return round(total, 1)

def bool_emoji(v: Optional[bool]) -> str:
    return "✅" if v else "❓" if v is None else "❌"

def summarize_tools_resources(entry: dict) -> Tuple[List[str], List[str], List[str]]:
    tools = []
    resources = []
    risk = []
    for k in ("tools", "capabilities", "operations"):
        t = entry.get(k) or []
        if isinstance(t, dict):
            for group, arr in t.items():
                if isinstance(arr, list):
                    for i in arr:
                        tools.append(i.get("name") or i.get("title") or group)
        elif isinstance(t, list):
            for i in t:
                if isinstance(i, dict):
                    tools.append(i.get("name") or i.get("title") or str(i))
                else:
                    tools.append(str(i))

    r = entry.get("resources") or []
    if isinstance(r, list):
        for i in r:
            resources.append(i.get("name") or i.get("title") or str(i))
    elif isinstance(r, dict):
        for i in r.values():
            if isinstance(i, list):
                for j in i:
                    resources.append(j.get("name") or j.get("title") or str(j))

    text_blob = json.dumps(entry).lower()
    if "http://" in text_blob or "https://" in text_blob:
        risk.append("External network calls likely")
    if any(k in text_blob for k in ["api_key", "token", "bearer", "oauth", "authorization"]):
        risk.append("Likely requires API tokens/secrets")
    return tools, resources, risk

def print_report(mcp_name: str, registry: str, entry: dict, repo_stats: Dict[str, Any], secret_scan: Dict[str, Any], scores: Dict[str, Any], weights: Dict[str, float], thresholds: Dict[str, float], *, json_mode: bool = False, suppress_scores: bool = False, suppress_thresholds: bool = False):
    overall = overall_from(scores, weights)
    rating = rating_from_score(overall, thresholds)
    style = RATING_STYLES.get(rating, "white")

    if json_mode:
        return

    title = f"[bold]MCP Quality Assessment[/bold]\n[dim]{mcp_name}[/dim]\nRegistry: {registry}"
    badge = f"[{style}]Risk Rating: {rating.title()}[/]  •  Score: {overall}/100"
    console.print(Panel.fit(f"{title}\n{badge}", border_style="cyan", box=box.ROUNDED))

    t = Table(title="Registry Entry", box=box.SIMPLE_HEAVY)
    t.add_column("Field"); t.add_column("Value")
    for k in ("name","id","namespace","version","description","publisher","homepage","website"):
        v = entry.get(k)
        if v:
            t.add_row(k, str(v))
    console.print(t)

    ns = entry.get("namespace") or entry.get("name") or entry.get("id") or ""
    explicit_verified = entry.get("verified") or entry.get("publisher_verified") or entry.get("is_verified")
    likely_verified = bool(explicit_verified) or ns.startswith("io.github.") or re.match(r"([a-z0-9-]+\.)+[a-z]{2,}/", ns) is not None

    t = Table(title="Publisher Trust", box=box.SIMPLE_HEAVY)
    t.add_column("Check"); t.add_column("Result")
    t.add_row("Namespace looks verified (DNS/GitHub)", bool_emoji(likely_verified))
    t.add_row("Registry 'verified' flag", str(explicit_verified))
    if repo_stats.get("owner_type"):
        t.add_row("GitHub owner type", str(repo_stats["owner_type"]))
    t.add_row("GitHub org verified (approx.)", str(repo_stats.get("org_is_verified_guess")))
    console.print(t)

    tools, resources, risk = summarize_tools_resources(entry)
    t = Table(title="Declared Capabilities", box=box.SIMPLE_HEAVY)
    t.add_column("Type"); t.add_column("Items")
    t.add_row("Tools", ", ".join(tools[:15]) + (" …" if len(tools) > 15 else ""))
    t.add_row("Resources", ", ".join(resources[:15]) + (" …" if len(resources) > 15 else ""))
    if risk:
        t.add_row("Risk Notes", " | ".join(risk))
    console.print(t)

    if repo_stats.get("repo_url"):
        t = Table(title="Repository & Security", box=box.SIMPLE_HEAVY)
        t.add_column("Metric"); t.add_column("Value")
        for k in ("repo_url","license","stars","forks","open_issues","latest_commit","pushed_at","archived","disabled","homepage","security_issue_hits"):
            if k in repo_stats and repo_stats[k] is not None:
                t.add_row(k, str(repo_stats[k]))
        hits = secret_scan.get("hits") or []
        t.add_row("Secret scan hits", str(len(hits)))
        console.print(t)
        if hits:
            subt = Table(title="Potential Secret Matches", box=box.MINIMAL)
            subt.add_column("File"); subt.add_column("Pattern")
            for h in hits[:20]:
                subt.add_row(h["path"], h["pattern"])
            console.print(subt)

        enrich = Table(title="Enhanced GitHub Signals", box=box.SIMPLE_HEAVY)
        enrich.add_column("Metric"); enrich.add_column("Value")

        def _add_if(k, label=None, fmt=str):
            v = repo_stats.get(k)
            if v is not None:
                try:
                    val = fmt(v)
                except Exception:
                    val = v
                enrich.add_row(label or k, str(val))

        _add_if("default_branch", "default_branch")
        _add_if("language", "language")
        _add_if("has_issues", "issue_tracking_enabled")
        _add_if("active_devs_90d", "active_devs_last_90_days", int)
        _add_if("has_security_md", "security_policy_present", lambda x: "Yes" if x else "No")
        if repo_stats.get("signed_commits_sampled"):
            ratio = repo_stats.get("signed_commits_ratio")
            enrich.add_row("signed_commits", f"{repo_stats.get('signed_commits')}/{repo_stats.get('signed_commits_sampled')} ({ratio:.2%})")
        if repo_stats.get("dep_graph_enabled") is not None:
            enrich.add_row("dependency_graph_enabled", "Yes" if repo_stats.get("dep_graph_enabled") else "No")
            if repo_stats.get("sbom_package_count") is not None:
                enrich.add_row("sbom_package_count", str(repo_stats.get("sbom_package_count")))
        if isinstance(repo_stats.get("dependabot_alerts_by_severity"), dict):
            sev = repo_stats["dependabot_alerts_by_severity"]
            enrich.add_row("dependabot_alerts_total", str(repo_stats.get("dependabot_alerts_total")))
            enrich.add_row("dependabot_by_severity", f"crit:{sev.get('critical',0)} high:{sev.get('high',0)} med:{sev.get('medium',0)} low:{sev.get('low',0)}")
        console.print(enrich)

    if not suppress_scores:
        st = Table(title="Scores (0–100)", box=box.SIMPLE_HEAVY)
        st.add_column("Dimension"); st.add_column("Score"); st.add_column("Weight")
        for k in ("publisher_trust","security_posture","maintenance","license","privacy_signal"):
            st.add_row(k, str(scores[k]), f"{weights.get(k,0):.2f}")
        st.add_row("overall", f"{overall}", "—")
        console.print(st)

    if not suppress_thresholds:
        thr = Table(title="Risk Thresholds (min score → label)", box=box.SIMPLE_HEAVY)
        thr.add_column("Label"); thr.add_column("Min Score")
        for label in sorted(ALLOWED_RATINGS, key=lambda L: thresholds.get(L, -1e9), reverse=True):
            thr.add_row(label.title(), str(thresholds.get(label)))
        console.print(thr)

    checklist = [
        ("Permissions & scopes alignment", "Review tools/resources and any required env vars (MCP has no runtime scopes)."),
        ("Test in non-prod", "Run server in sandbox; monitor latency/side-effects."),
        ("GDPR compliance", "Confirm personal data processing; DPA if needed."),
        ("Data residency", "Verify storage/processing locations."),
        ("Privacy policy", "Locate and review publisher’s policy."),
        ("Support options", "Docs, forums, issue responsiveness, security contact."),
        ("DR/rollback", "Have a rollback plan if workflows break."),
        ("Security policy", "If missing SECURITY.md, ask publisher for contact & vulnerability disclosure process."),
        ("Signed commits", "If ratio <50%, consider requiring verified signing for critical repos."),
        ("Dependencies", "If dep graph disabled, request enablement; review SBOM if available."),
        ("Vulnerabilities", "Triage Dependabot alerts; prioritize Critical/High."),
    ]
    ct = Table(title="Manual Review Needed", box=box.SIMPLE_HEAVY)
    ct.add_column("Item"); ct.add_column("Action")
    for a,b in checklist:
        ct.add_row(a,b)
    console.print(ct)

def print_step_by_step_explanation(explanation: dict, weights: Dict[str, float], thresholds: Dict[str, float], scores: Dict[str, float]):
    # Weighted contributions
    contrib = []
    total = 0.0
    for k in ("publisher_trust","security_posture","maintenance","license","privacy_signal"):
        w = float(weights.get(k,0.0))
        s = float(scores.get(k,0.0))
        prod = round(w*s, 3)
        contrib.append((k, s, w, prod))
        total += prod
    total = round(total, 1)

    console.print(Panel.fit("[bold]Risk Calculation — Step by Step[/bold]", border_style="magenta", box=box.ROUNDED))

    def section(title: str, steps: List[dict], final: float):
        t = Table(title=title, box=box.SIMPLE_HEAVY)
        t.add_column("Step/Reason", style="bold")
        t.add_column("Effect / Value", overflow="fold")
        for s in steps:
            if "delta" in s:
                t.add_row(str(s.get("reason")), f"{s['delta']:+} {json.dumps({k:v for k,v in s.items() if k not in ('reason','delta')}) if len(s)>2 else ''}".strip())
            elif "from" in s and "to" in s:
                t.add_row(str(s.get("reason")), f"{s['from']} → {s['to']}")
            elif "value" in s:
                t.add_row(str(s.get("reason")), str(s["value"]))
            else:
                t.add_row(str(s.get("reason")), json.dumps({k:v for k,v in s.items() if k!='reason'}))
        t.add_row("—", f"Final: {final}")
        console.print(t)

    # Per-dimension explanation
    for dim, title in [
        ("publisher_trust","Publisher Trust"),
        ("maintenance","Maintenance"),
        ("license","License"),
        ("privacy_signal","Privacy"),
        ("security_posture","Security Posture"),
    ]:
        sec = explanation.get(dim, {})
        section(title, sec.get("steps", []), sec.get("final"))

    # Weighted contributions
    wt = Table(title="Weighted Contributions → Overall", box=box.SIMPLE_HEAVY)
    wt.add_column("Dimension"); wt.add_column("Score"); wt.add_column("Weight"); wt.add_column("Contribution (w*score)")
    for (k,s,w,p) in contrib:
        wt.add_row(k, str(s), f"{w:.2f}", str(p))
    wt.add_row("—","—","—", f"{total}")
    console.print(wt)

    # Threshold mapping
    ordered = sorted(ALLOWED_RATINGS, key=lambda L: thresholds.get(L, -1e9), reverse=True)
    th = Table(title="Risk Label Mapping", box=box.SIMPLE_HEAVY)
    th.add_column("Label"); th.add_column("Min Score"); th.add_column("Meets?")
    for lab in ordered:
        minv = thresholds.get(lab, 0.0)
        meets = "Yes" if total >= minv else "No"
        th.add_row(lab.title(), str(minv), meets)
    console.print(th)

# ------------------ PDF report ------------------
def generate_pdf_report(pdf_path: str, mcp_name: str, registry: str, entry: dict, repo_stats: Dict[str, Any], secret_scan: Dict[str, Any], scores: Dict[str, Any], weights: Dict[str, float], thresholds: Dict[str, float]):
    if PdfPages is None or plt is None:
        console_err.print("[red]matplotlib is not installed. Unable to generate PDF.[/red] Try: pip3 install matplotlib")
        return

    overall = overall_from(scores, weights)
    rating = rating_from_score(overall, thresholds)
    rating_colors = {"low": "#2ca02c", "medium": "#ffbf00", "high": "#ff7f0e", "critical": "#d62728"}
    dims = [
        ("publisher_trust", "Publisher Trust"),
        ("security_posture", "Security"),
        ("maintenance", "Maintenance"),
        ("license", "License"),
        ("privacy_signal", "Privacy"),
    ]
    values = [float(scores.get(k, 0.0)) for k, _ in dims]

    try:
        with PdfPages(pdf_path) as pdf:
            # Page 1: Summary and details
            fig1 = plt.figure(figsize=(8.5, 11), dpi=150)
            fig1.subplots_adjust(left=0.08, right=0.92, top=0.92, bottom=0.08)
            ax1 = fig1.add_subplot(111)
            ax1.axis("off")

            # Title
            title = f"MCP Quality Assessment\n{mcp_name}"
            subtitle = f"Registry: {registry}"
            ax1.text(0.5, 0.96, title, ha="center", va="top", fontsize=18, fontweight="bold")
            ax1.text(0.5, 0.92, subtitle, ha="center", va="top", fontsize=10, color="#555")

            # Rating badge
            badge = f"Risk Rating: {rating.title()}  •  Score: {overall}/100"
            ax1.text(0.5, 0.87, badge, ha="center", va="top", fontsize=12, color="white",
                     bbox=dict(boxstyle="round,pad=0.5", fc=rating_colors.get(rating, "#444"), ec="none"))

            # Registry entry fields
            y = 0.82
            ax1.text(0.05, y, "Registry Entry", fontsize=12, fontweight="bold"); y -= 0.02
            for k in ("name","id","namespace","version","description","publisher","homepage","website"):
                v = entry.get(k)
                if v:
                    ax1.text(0.06, y, f"{k}: ", fontsize=10, fontweight="bold")
                    ax1.text(0.18, y, str(v), fontsize=10)
                    y -= 0.018

            # Repo and security signals
            y -= 0.01
            ax1.text(0.05, y, "Repository & Security", fontsize=12, fontweight="bold"); y -= 0.02
            if repo_stats.get("repo_url"):
                for k in ("repo_url","license","stars","forks","open_issues","latest_commit","pushed_at","archived","disabled","homepage","security_issue_hits"):
                    if repo_stats.get(k) is not None:
                        ax1.text(0.06, y, f"{k}: ", fontsize=10, fontweight="bold")
                        ax1.text(0.24, y, str(repo_stats.get(k)), fontsize=10)
                        y -= 0.018
                hits = secret_scan.get("hits") or []
                ax1.text(0.06, y, "secret_scan_hits: ", fontsize=10, fontweight="bold")
                ax1.text(0.24, y, str(len(hits)), fontsize=10); y -= 0.02

            # Scores and weights
            y -= 0.01
            ax1.text(0.05, y, "Scores", fontsize=12, fontweight="bold"); y -= 0.02
            for k, label in dims:
                ax1.text(0.06, y, f"{label}:", fontsize=10, fontweight="bold")
                ax1.text(0.24, y, f"{scores.get(k, 0):.1f}", fontsize=10)
                ax1.text(0.36, y, f"(w={weights.get(k,0):.2f})", fontsize=9, color="#555")
                y -= 0.018
            ax1.text(0.06, y, "overall:", fontsize=10, fontweight="bold")
            ax1.text(0.24, y, f"{overall:.1f}", fontsize=10); y -= 0.02

            # Thresholds
            y -= 0.01
            ax1.text(0.05, y, "Risk Thresholds (min score → label)", fontsize=12, fontweight="bold"); y -= 0.02
            for lab in sorted(ALLOWED_RATINGS, key=lambda L: thresholds.get(L, -1e9), reverse=True):
                ax1.text(0.06, y, f"{lab.title()}: ", fontsize=10, fontweight="bold")
                ax1.text(0.24, y, str(thresholds.get(lab)), fontsize=10)
                y -= 0.018

            pdf.savefig(fig1)
            plt.close(fig1)

            # Page 2: Heatmap
            fig2 = plt.figure(figsize=(8.5, 3.5), dpi=150)
            ax2 = fig2.add_subplot(111)
            # Ensure enough space for rotated x-axis labels without altering existing lines
            fig2.set_size_inches(8.5, 4.2, forward=True)  # add a bit more height
            data = [values]  # 1 x N heatmap
            im = ax2.imshow(data, aspect="auto", cmap="RdYlGn", vmin=0, vmax=100)
            ax2.set_yticks([])
            ax2.set_xticks(range(len(dims)))
            ax2.set_xticklabels([label for _, label in dims], rotation=30, ha="right")
            # Anchor rotation so long labels stay inside the figure
            import matplotlib.pyplot as _plt
            _plt.setp(ax2.get_xticklabels(), rotation=30, ha="right", rotation_mode="anchor")
            for i, v in enumerate(values):
                ax2.text(i, 0, f"{int(round(v))}", ha="center", va="center", color="black", fontsize=12, fontweight="bold")
            cbar = fig2.colorbar(im, ax=ax2, orientation="vertical", fraction=0.046, pad=0.04)
            cbar.set_label("Score (0–100)")

            fig2.suptitle(f"Risk Heatmap — Overall: {overall}/100 ({rating.title()})", fontsize=14, fontweight="bold", color=rating_colors.get(rating, "#222"))
            # Reserve extra bottom margin to avoid clipping tick labels
            fig2.subplots_adjust(bottom=0.30)
            pdf.savefig(fig2)
            plt.close(fig2)

        console.print(f"[green]PDF report written to[/green] {pdf_path}")
    except Exception as e:
        console_err.print(f"[red]Failed to write PDF[/red] {pdf_path}: {e}")

# ------------------ CSV & list printing ------------------
def print_server_list(servers: List[dict], json_out: bool = False):
    if json_out:
        print(json.dumps(servers, indent=2))
        return
    t = Table(title=f"Registry Servers ({len(servers)})", box=box.SIMPLE_HEAVY)
    t.add_column("Name/ID", overflow="fold")
    t.add_column("Namespace", overflow="fold")
    t.add_column("Version", justify="right")
    t.add_column("Publisher", overflow="fold")
    t.add_column("Repo", overflow="fold")

    for s in servers:
        # Be robust to non-dict entries
        if not isinstance(s, dict):
            t.add_row(str(s), "", "", "", "")
            continue
        e = unwrap_entry(s)
        # Name/id with broad fallbacks
        name = (
            _first_str(e, ["name","id","slug","full_name","fullName","display_name","displayName","title"])
            or str(e.get("namespace") or "")
        )
        # Namespace fallbacks
        ns = _first_str(e, ["namespace","ns","scope","group"]) or ""
        # Version fallbacks
        ver = _first_str(e, ["version","latest_version","latestVersion","release","releaseTag","tag"]) or ""
        # Publisher/owner fallbacks
        pub = _first_str(e, ["publisher","owner","author","maintainer","organization","org","vendor"]) or ""
        repo = extract_repo_url(e) or ""
        t.add_row(str(name), str(ns), str(ver), str(pub), str(repo))
    console.print(t)

def export_csv(servers: List[dict], path: str):
    cols = ["name_or_id", "namespace", "version", "publisher", "repo", "verified"]
    close_file = True
    if path == "-":
        f = sys.stdout
        close_file = False
    else:
        f = open(path, "w", newline="", encoding="utf-8")
    try:
        writer = csv.writer(f)
        writer.writerow(cols)
        for s in servers:
            if not isinstance(s, dict):
                writer.writerow([str(s), "", "", "", "", ""])
                continue
            e = unwrap_entry(s)
            name = (
                _first_str(e, ["name","id","slug","full_name","fullName","display_name","displayName","title"])
                or str(e.get("namespace") or "")
            )
            ns = _first_str(e, ["namespace","ns","scope","group"]) or ""
            ver = _first_str(e, ["version","latest_version","latestVersion","release","releaseTag","tag"]) or ""
            pub = _first_str(e, ["publisher","owner","author","maintainer","organization","org","vendor"]) or ""
            repo = extract_repo_url(e) or ""
            verified = e.get("verified") or e.get("publisher_verified") or e.get("is_verified") or ""
            writer.writerow([name, ns, ver, pub, repo, verified])
    finally:
        if close_file:
            f.close()

# ------------------ CLI ------------------
def main():
    ap = argparse.ArgumentParser(description="MCP quality audit from registry + GitHub signals (integrated metrics, explainable)")
    ap.add_argument("name", nargs="?", help="MCP name (e.g., com.example/my-mcp). Use --fuzzy to search by keyword.")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY, help="MCP registry base URL")
    ap.add_argument("--fuzzy", action="store_true", help="Search instead of exact lookup")
    ap.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    ap.add_argument("--explain-risk", action="store_true", help="Show step-by-step explanation of the risk level calculation and suppress the standard scores/thresholds tables")
    # listing
    ap.add_argument("--list", action="store_true", help="List MCP servers and exit")
    ap.add_argument("--limit", type=int, default=200, help="Max number of servers to list with --list (default: 200)")
    ap.add_argument("--page-size", type=int, default=100, help="Per-page limit for registry calls (max 100)")
    ap.add_argument("--search", type=str, default=None, help="Filter listed servers by keyword")
    ap.add_argument("--csv", type=str, default=None, help="CSV output path (use '-' for stdout) when used with --list")
    # PDF report
    ap.add_argument("--pdf", type=str, default=None, help="Write a PDF report to the specified file (single server mode)")
    # configurables
    ap.add_argument("--weights", type=str, default=None, help="JSON object of weights (publisher_trust, security_posture, maintenance, license, privacy_signal)")
    ap.add_argument("--weights-file", type=str, default=None, help="Path to JSON file with weights")
    ap.add_argument("--risk-thresholds", type=str, default=None, help="JSON object mapping label->min score (allowed: low, medium, high, critical)")
    ap.add_argument("--risk-thresholds-file", type=str, default=None, help="Path to JSON file with risk thresholds")

    # networking
    ap.add_argument("--skipssl", action="store_true", help="Skip TLS certificate verification (useful behind SSL-inspecting proxies)")

    # extra GitHub options
    ap.add_argument("--no-deps", action="store_true", help="Skip dependency graph + Dependabot vulnerability checks")
    ap.add_argument("--max-commits", type=int, default=500, help="Maximum commits to sample for signed-commit ratio (default: 500)")
    ap.add_argument("--no-secret-scan", action="store_true", help="Skip shallow secret scan of repo contents")

    args = ap.parse_args()

    if args.skipssl:
        SESSION.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        console_err.print("[yellow]TLS verification disabled (--skipssl). Use with caution.[/yellow]")

    weights = resolve_weights(args.weights, args.weights_file)
    thresholds = resolve_thresholds(args.risk_thresholds, args.risk_thresholds_file)

    if args.list:
        if args.pdf:
            console_err.print("[red]--pdf is not supported with --list. Generate a PDF for a single server query.[/red]")
            sys.exit(2)
        servers = list_all_servers(args.registry, limit=args.limit, page_size=args.page_size)
        servers = filter_servers(servers, args.search)
        if not servers:
            console.print(f"[red]No servers found at {args.registry}[/red]")
            sys.exit(2)
        if args.csv:
            export_csv(servers, args.csv)
        else:
            print_server_list(servers, json_out=args.json)
        sys.exit(0)

    if not args.name:
        console.print("[red]Please provide a server name (or use --list).[/red]")
        sys.exit(2)

    entry, matches = try_registry_lookup(args.registry, args.name, args.fuzzy)
    if not entry:
        console.print(f"[red]No registry entry found for[/red] {args.name} at {args.registry}")
        if matches:
            console.print(f"Found {len(matches)} candidates. Try --fuzzy and a broader query.")
        sys.exit(2)

    repo_url = extract_repo_url(entry)
    repo_stats = {}
    secret_scan = {"scanned_files": 0, "hits": []}
    if repo_url:
        repo_stats = github_repo_stats(repo_url, max_commits=args.max_commits, no_deps=args.no_deps)
        if not args.no_secret_scan:
            secret_scan = shallow_secret_scan(repo_url)

    scores, explanation = calc_scores(entry, repo_stats, secret_scan, explain=args.explain_risk)

    # Human-readable report
    print_report(
        args.name, args.registry, entry, repo_stats, secret_scan, scores, weights, thresholds,
        json_mode=args.json,
        suppress_scores=args.explain_risk,
        suppress_thresholds=args.explain_risk
    )

    # Step-by-step explanation (if requested and not JSON)
    if args.explain_risk and not args.json and explanation:
        print_step_by_step_explanation(explanation, weights, thresholds, scores)

    # PDF report output
    if args.pdf:
        generate_pdf_report(args.pdf, args.name, args.registry, entry, repo_stats, secret_scan, scores, weights, thresholds)

    if args.json:
        overall = overall_from(scores, weights)
        output = {
            "query": args.name,
            "registry": args.registry,
            "entry": entry,
            "repo_stats": repo_stats,
            "secret_scan": secret_scan,
            "scores": scores,
            "weights_used": weights,
            "risk": {
                "score": overall,
                "rating": rating_from_score(overall, thresholds),
                "thresholds": thresholds
            },
            "explanation": explanation if args.explain_risk else None
        }
        print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
