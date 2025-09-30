#!/usr/bin/env python3
# mcp_quality_audit.py
import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple

import requests
from dateutil import parser as dtparser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ------------------ Registry API ------------------
DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io"
API_PREFIX = "/v0"
PATH_SERVERS = f"{API_PREFIX}/servers"

# ------------------ GitHub API ------------------
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GH_HEADERS = {"Accept": "application/vnd.github+json"}
if GITHUB_TOKEN:
    GH_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# ------------------ HTTP helpers ------------------
def get_json(url: str, headers: Optional[Dict[str, str]] = None, timeout=20, params: Optional[dict]=None) -> Optional[dict]:
    try:
        r = requests.get(url, headers=headers, timeout=timeout, params=params)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

# ------------------ Registry lookups ------------------
def _extract_items_and_next(payload: Any) -> Tuple[List[dict], Optional[str]]:
    """
    Normalize registry list responses.

    Official example:
    {
      "servers": [...],
      "metadata": {"next_cursor": "abc", "count": 30}
    }
    """
    if not isinstance(payload, dict):
        return [], None
    items = payload.get("servers") or payload.get("items") or payload.get("results") or payload.get("data") or []
    meta = payload.get("metadata") or {}
    nxt = (
        meta.get("next_cursor")
        or meta.get("nextCursor")
        or payload.get("next_cursor")
        or payload.get("nextCursor")
        or payload.get("next")
    )
    if isinstance(nxt, str) and nxt.strip() == "":
        nxt = None
    return items, nxt

def try_registry_lookup(registry: str, mcp_name: str, fuzzy: bool) -> Tuple[Optional[dict], List[dict]]:
    """
    Use official /v0 endpoints.
      - Exact: GET /v0/servers/{id}
      - Fuzzy: GET /v0/servers?search=<query>&limit=50
    """
    base = registry.rstrip("/")
    # exact by ID
    data = get_json(f"{base}{PATH_SERVERS}/{mcp_name}")
    if isinstance(data, dict) and data:
        return data, [data]

    # fuzzy/search
    payload = get_json(f"{base}{PATH_SERVERS}", params={"search": mcp_name, "limit": 50})
    items, _ = _extract_items_and_next(payload)
    best = None

    def name_of(x):
        return x.get("name") or x.get("id") or x.get("slug") or x.get("full_name")

    for x in items:
        if name_of(x) == mcp_name:
            best = x
            break
    if fuzzy and not best and items:
        best = items[0]
    return best, items or []

def list_all_servers(registry: str, limit: int = 200, page_size: int = 100) -> List[dict]:
    """
    Cursor-based enumeration of /v0/servers.
      - limit: max total items to return
      - page_size: 'limit' query param per page (max 100)
    """
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

# ------------------ Repo utilities ------------------
def extract_repo_url(entry: dict) -> Optional[str]:
    for k in ("repo", "repository", "github", "source", "homepage", "url", "website"):
        v = entry.get(k)
        if isinstance(v, str) and "github.com" in v:
            return v
        if isinstance(v, dict):
            for vv in v.values():
                if isinstance(vv, str) and "github.com" in vv:
                    return vv
    meta = entry.get("_meta") or entry.get("metadata") or {}
    for _, v in (meta.items() if isinstance(meta, dict) else []):
        if isinstance(v, str) and "github.com" in v:
            return v
    pkgs = entry.get("packages") or []
    for p in pkgs:
        src = p.get("source") or p.get("url")
        if isinstance(src, str) and "github.com" in src:
            return src
    return None

def gh_api(path: str) -> Optional[dict]:
    return get_json("https://api.github.com" + path, headers=GH_HEADERS)

def parse_github_owner_repo(url: str) -> Optional[Tuple[str, str]]:
    m = re.search(r"github\.com/([^/]+)/([^/#]+)", url or "")
    if not m:
        return None
    return m.group(1), m.group(2).replace(".git", "")

def github_repo_stats(repo_url: str) -> Dict[str, Any]:
    out = {"repo_url": repo_url}
    parsed = parse_github_owner_repo(repo_url)
    if not parsed:
        return out
    owner, repo = parsed
    repo_data = gh_api(f"/repos/{owner}/{repo}") or {}
    out["stars"] = repo_data.get("stargazers_count")
    out["forks"] = repo_data.get("forks_count")
    out["open_issues"] = repo_data.get("open_issues_count")
    out["license"] = (repo_data.get("license") or {}).get("spdx_id")
    out["pushed_at"] = repo_data.get("pushed_at")
    out["updated_at"] = repo_data.get("updated_at")
    out["archived"] = repo_data.get("archived")
    out["disabled"] = repo_data.get("disabled")
    out["homepage"] = repo_data.get("homepage")

    owner_data = gh_api(f"/users/{owner}") or {}
    out["owner_type"] = owner_data.get("type")
    out["org_is_verified_guess"] = owner_data.get("is_verified")

    issues = gh_api(f"/search/issues?q=repo:{owner}/{repo}+security+in:title,body") or {}
    out["security_issue_hits"] = issues.get("total_count")

    commits = gh_api(f"/repos/{owner}/{repo}/commits")
    if isinstance(commits, list) and commits:
        latest = commits[0].get("commit", {}).get("committer", {}).get("date")
        out["latest_commit"] = latest

    readme = gh_api(f"/repos/{owner}/{repo}/readme")
    if readme and "download_url" in readme:
        try:
            txt = requests.get(readme["download_url"], timeout=20).text.lower()
            out["gdpr_mentions"] = any(k in txt for k in ("gdpr", "general data protection regulation", "privacy", "data residency", "eu data"))
            out["privacy_policy_linked"] = ("privacy policy" in txt) or ("privacy-policy" in txt)
        except Exception:
            pass

    return out

SECRET_SMELLS = [
    r"AKIA[0-9A-Z]{16}",                       # AWS key
    r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----",
    r"api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    r"secret\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    r"x-api-key\s*:\s*[A-Za-z0-9_\-]{16,}",
    r"ghp_[A-Za-z0-9]{36,}",                   # GitHub token
]

def shallow_secret_scan(repo_url: str, limit_files=50) -> Dict[str, Any]:
    out = {"scanned_files": 0, "hits": []}
    parsed = parse_github_owner_repo(repo_url)
    if not parsed:
        return out
    owner, repo = parsed
    tree = gh_api(f"/repos/{owner}/{repo}/git/trees/HEAD?recursive=1")
    if not tree or "tree" not in tree:
        return out
    files = [t for t in tree["tree"] if t.get("type") == "blob"]
    sample = [f for f in files if not f["path"].lower().endswith((
        ".png",".jpg",".jpeg",".gif",".pdf",".zip",".gz",".jar",".exe",".dll",".webp",".svg"
    ))][:limit_files]
    for f in sample:
        blob = gh_api(f"/repos/{owner}/{repo}/contents/{f['path']}")
        if not blob or "download_url" not in blob:
            continue
        try:
            txt = requests.get(blob["download_url"], timeout=15).text
        except Exception:
            continue
        out["scanned_files"] += 1
        for pat in SECRET_SMELLS:
            if re.search(pat, txt):
                out["hits"].append({"path": f["path"], "pattern": pat})
    return out

# ------------------ Scoring / reporting ------------------
def calc_scores(entry: dict, repo_stats: Dict[str, Any], secret_scan: Dict[str, Any]) -> Dict[str, Any]:
    scores = {}

    ns = entry.get("namespace") or entry.get("name") or entry.get("id") or ""
    explicit_verified = entry.get("verified") or entry.get("publisher_verified") or entry.get("is_verified")
    verified = bool(explicit_verified) or ns.startswith("io.github.") or re.match(r"([a-z0-9-]+\.)+[a-z]{2,}/", ns)
    org_verified = True if repo_stats.get("org_is_verified_guess") else False
    pub_score = 70 + (15 if verified else 0) + (15 if org_verified else 0)
    scores["publisher_trust"] = min(pub_score, 100)

    sec_hits = int(repo_stats.get("security_issue_hits") or 0)
    secret_hits = len(secret_scan.get("hits") or [])
    sec_score = 100
    if sec_hits >= 3:
        sec_score -= 30
    elif sec_hits == 2:
        sec_score -= 20
    elif sec_hits == 1:
        sec_score -= 10
    if secret_hits > 0:
        sec_score = max(sec_score - 50, 10)
    scores["security_posture"] = max(min(sec_score, 100), 0)

    latest = repo_stats.get("latest_commit") or repo_stats.get("pushed_at") or repo_stats.get("updated_at")
    maint_score = 50
    if latest:
        try:
            dt = dtparser.parse(latest)
            days = (datetime.now(timezone.utc) - dt).days
            if days <= 30:
                maint_score = 95
            elif days <= 90:
                maint_score = 80
            elif days <= 180:
                maint_score = 65
            elif days <= 365:
                maint_score = 55
            else:
                maint_score = 35
        except Exception:
            pass
    scores["maintenance"] = maint_score

    lic = (repo_stats.get("license") or "").upper()
    if lic in {"MIT","APACHE-2.0","BSD-2-CLAUSE","BSD-3-CLAUSE","MPL-2.0"}:
        lic_score = 100
    elif lic in {"GPL-3.0","AGPL-3.0","LGPL-3.0"}:
        lic_score = 75
    elif lic:
        lic_score = 70
    else:
        lic_score = 40
    scores["license"] = lic_score

    gdpr = bool(repo_stats.get("gdpr_mentions"))
    scores["privacy_signal"] = 85 if gdpr else 60

    overall = (
        0.30 * scores["publisher_trust"] +
        0.30 * scores["security_posture"] +
        0.25 * scores["maintenance"] +
        0.10 * scores["license"] +
        0.05 * scores["privacy_signal"]
    )
    scores["overall"] = round(overall, 1)
    return scores

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

def print_report(mcp_name: str, registry: str, entry: dict, repo_stats: Dict[str, Any], secret_scan: Dict[str, Any], scores: Dict[str, Any]):
    console.print(Panel.fit(f"[bold]MCP Quality Assessment[/bold]\n[dim]{mcp_name}[/dim]\nRegistry: {registry}", border_style="cyan", box=box.ROUNDED))

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

    st = Table(title="Scores (0–100)", box=box.SIMPLE_HEAVY)
    st.add_column("Dimension"); st.add_column("Score")
    for k in ("publisher_trust","security_posture","maintenance","license","privacy_signal","overall"):
        st.add_row(k, str(scores[k]))
    console.print(st)

    checklist = [
        ("Permissions & scopes alignment", "Review tools/resources and any required env vars (MCP has no runtime scopes)."),
        ("Test in non-prod", "Run server in sandbox; monitor latency/side-effects."),
        ("GDPR compliance", "Confirm personal data processing; DPA if needed."),
        ("Data residency", "Verify storage/processing locations."),
        ("Privacy policy", "Locate and review publisher’s policy."),
        ("Support options", "Docs, forums, issue responsiveness, security contact."),
        ("DR/rollback", "Have a rollback plan if workflows break."),
    ]
    ct = Table(title="Manual Review Needed", box=box.SIMPLE_HEAVY)
    ct.add_column("Item"); ct.add_column("Action")
    for a,b in checklist:
        ct.add_row(a,b)
    console.print(ct)

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
        name = s.get("name") or s.get("id") or s.get("slug") or ""
        ns = s.get("namespace") or ""
        ver = s.get("version") or ""
        pub = (s.get("publisher") or s.get("owner") or "")
        repo = extract_repo_url(s) or ""
        t.add_row(str(name), str(ns), str(ver), str(pub), str(repo))
    console.print(t)

def export_csv(servers: List[dict], path: str):
    """Write a CSV with lightweight registry fields (no GitHub calls)."""
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
            name = s.get("name") or s.get("id") or s.get("slug") or ""
            ns = s.get("namespace") or ""
            ver = s.get("version") or ""
            pub = (s.get("publisher") or s.get("owner") or "")
            repo = extract_repo_url(s) or ""
            verified = s.get("verified") or s.get("publisher_verified") or s.get("is_verified") or ""
            writer.writerow([name, ns, ver, pub, repo, verified])
    finally:
        if close_file:
            f.close()

# ------------------ CLI ------------------
def main():
    ap = argparse.ArgumentParser(description="MCP quality audit from registry + GitHub signals")
    ap.add_argument("name", nargs="?", help="MCP name (e.g., com.example/my-mcp). Use --fuzzy to search by keyword.")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY, help="MCP registry base URL")
    ap.add_argument("--fuzzy", action="store_true", help="Search instead of exact lookup")
    ap.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    ap.add_argument("--list", action="store_true", help="List MCP servers and exit")
    ap.add_argument("--limit", type=int, default=200, help="Max number of servers to list with --list (default: 200)")
    ap.add_argument("--page-size", type=int, default=100, help="Per-page limit for registry calls (max 100)")
    ap.add_argument("--search", type=str, default=None, help="Filter listed servers by keyword")
    ap.add_argument("--csv", type=str, default=None, help="CSV output path (use '-' for stdout) when used with --list")
    args = ap.parse_args()

    # Handle --list first
    if args.list:
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
    repo_stats = github_repo_stats(repo_url) if repo_url else {}
    secret_scan = shallow_secret_scan(repo_url) if repo_url else {"scanned_files": 0, "hits": []}
    scores = calc_scores(entry, repo_stats, secret_scan)

    print_report(args.name, args.registry, entry, repo_stats, secret_scan, scores)

    if args.json:
        output = {
            "query": args.name,
            "registry": args.registry,
            "entry": entry,
            "repo_stats": repo_stats,
            "secret_scan": secret_scan,
            "scores": scores,
        }
        print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
