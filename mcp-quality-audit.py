#!/usr/bin/env python3
import argparse
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

DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GH_HEADERS = {"Accept": "application/vnd.github+json"}
if GITHUB_TOKEN:
    GH_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# ---------- Helpers

def get_json(url: str, headers: Optional[Dict[str, str]] = None, timeout=20) -> Optional[dict]:
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

def try_registry_lookup(registry: str, mcp_name: str, fuzzy: bool) -> Tuple[Optional[dict], List[dict]]:
    """Return (best_match, all_matches)."""
    all_matches = []
    # Try exact by ID first (/servers/:id)
    for path in (f"/servers/{mcp_name}", f"/api/servers/{mcp_name}"):
        data = get_json(registry.rstrip("/") + path)
        if isinstance(data, dict) and data:
            return data, [data]

    # Fallback search endpoints we often see in registries:
    candidates = [
        ("/servers", {"q": mcp_name}),
        ("/servers", {"query": mcp_name}),
        ("/api/servers", {"q": mcp_name}),
        ("/api/servers", {"query": mcp_name}),
    ]
    for path, qs in candidates:
        try:
            r = requests.get(registry.rstrip("/") + path, params=qs, timeout=20)
            if r.status_code == 200:
                j = r.json()
                if isinstance(j, dict) and "items" in j:
                    all_matches = j["items"]
                elif isinstance(j, list):
                    all_matches = j
                break
        except Exception:
            pass

    # Pick best match by exact name equality if present
    best = None
    if all_matches:
        # normalize keys we often see
        def name_of(x):
            return x.get("name") or x.get("id") or x.get("slug") or x.get("full_name")
        # exact
        for x in all_matches:
            if name_of(x) == mcp_name:
                best = x
                break
        # fuzzy top
        if fuzzy and not best:
            best = all_matches[0]
    return best, all_matches

def extract_repo_url(entry: dict) -> Optional[str]:
    # common locations for repo links across registries
    for k in ("repo", "repository", "github", "source", "homepage", "url", "website"):
        v = entry.get(k)
        if isinstance(v, str) and "github.com" in v:
            return v
        if isinstance(v, dict):
            for vv in v.values():
                if isinstance(vv, str) and "github.com" in vv:
                    return vv
    # deep metadata
    meta = entry.get("_meta") or entry.get("metadata") or {}
    for k, v in meta.items():
        if isinstance(v, str) and "github.com" in v:
            return v
    # sometimes inside package refs
    pkgs = entry.get("packages") or []
    for p in pkgs:
        src = p.get("source") or p.get("url")
        if isinstance(src, str) and "github.com" in src:
            return src
    return None

def gh_api(path: str) -> Optional[dict]:
    return get_json("https://api.github.com" + path, headers=GH_HEADERS)

def parse_github_owner_repo(url: str) -> Optional[Tuple[str, str]]:
    m = re.search(r"github\.com/([^/]+)/([^/#]+)", url)
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

    # org verification (publisher trust)
    owner_data = gh_api(f"/users/{owner}") or {}
    out["owner_type"] = owner_data.get("type")
    # For orgs, try to see if they look "verified": there isn't a simple flag via REST,
    # but many verified orgs have a non-null "is_verified" in GraphQL; we approximate via "is_verified" key if present.
    out["org_is_verified_guess"] = owner_data.get("is_verified")

    # advisories and security issues (best effort)
    # Search issues with "security" keyword
    issues = gh_api(f"/search/issues?q=repo:{owner}/{repo}+security+in:title,body") or {}
    out["security_issue_hits"] = issues.get("total_count")

    # recent commits for update frequency
    commits = gh_api(f"/repos/{owner}/{repo}/commits")
    if isinstance(commits, list) and commits:
        latest = commits[0].get("commit", {}).get("committer", {}).get("date")
        out["latest_commit"] = latest

    # pull README for GDPR keywords
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
    # sample first N text-like files
    sample = [f for f in files if not f["path"].lower().endswith((".png",".jpg",".jpeg",".gif",".pdf",".zip",".gz",".jar",".exe",".dll"))][:limit_files]
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

def calc_scores(entry: dict, repo_stats: Dict[str, Any], secret_scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce per-dimension scores (0-100) and a weighted overall.
    Weights can be tweaked to your policy.
    """
    scores = {}

    # Publisher trust (verification + org signals)
    verified = False
    ns = entry.get("namespace") or entry.get("name") or entry.get("id") or ""
    # Registry FAQ: namespaces are verified via DNS or GitHub. We infer via presence of a domain-backed namespace or io.github.*. (Manual proof would be a field; many registries expose `verified`.)
    explicit_verified = entry.get("verified") or entry.get("publisher_verified") or entry.get("is_verified")
    if explicit_verified:
        verified = True
    elif ns.startswith("io.github.") or re.match(r"([a-z0-9-]+\.)+[a-z]{2,}/", ns):
        verified = True  # heuristic
    org_verified = True if repo_stats.get("org_is_verified_guess") else False
    pub_score = 70 + (15 if verified else 0) + (15 if org_verified else 0)
    scores["publisher_trust"] = min(pub_score, 100)

    # Security posture (advisories, secret-scan hits)
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

    # Maintenance / updates
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

    # License compliance
    lic = (repo_stats.get("license") or "").upper()
    if lic in {"MIT","APACHE-2.0","BSD-2-CLAUSE","BSD-3-CLAUSE","MPL-2.0"}:
        lic_score = 100
    elif lic in {"GPL-3.0","AGPL-3.0","LGPL-3.0"}:
        lic_score = 75   # compatible depending on org policy
    elif lic:
        lic_score = 70
    else:
        lic_score = 40
    scores["license"] = lic_score

    # Privacy/GDPR (signal only)
    gdpr = bool(repo_stats.get("gdpr_mentions"))
    scores["privacy_signal"] = 85 if gdpr else 60

    # Overall (weights)
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
    """Return (tools, resources, risk_notes)."""
    tools = []
    resources = []
    risk = []
    # server.json shapes typically include 'tools', 'resources', 'prompts', 'env'
    for k in ("tools", "capabilities", "operations"):
        t = entry.get(k) or []
        if isinstance(t, dict):  # sometimes grouped by type
            for group, arr in t.items():
                if isinstance(arr, list):
                    for i in arr: tools.append(i.get("name") or group)
        elif isinstance(t, list):
            for i in t:
                tools.append(i.get("name") or i.get("title") or str(i))

    r = entry.get("resources") or []
    if isinstance(r, list):
        for i in r:
            resources.append(i.get("name") or i.get("title") or str(i))
    elif isinstance(r, dict):
        for i in r.values():
            if isinstance(i, list):
                for j in i:
                    resources.append(j.get("name") or j.get("title") or str(j))

    # heuristic risks
    text_blob = json.dumps(entry).lower()
    if "http://" in text_blob or "https://" in text_blob:
        risk.append("External network calls likely")
    if any(k in text_blob for k in ["api_key", "token", "bearer", "oauth", "authorization"]):
        risk.append("Likely requires API tokens/secrets")
    return tools, resources, risk

def print_report(mcp_name: str, registry: str, entry: dict, repo_stats: Dict[str, Any], secret_scan: Dict[str, Any], scores: Dict[str, Any]):
    console.print(Panel.fit(f"[bold]MCP Quality Assessment[/bold]\n[dim]{mcp_name}[/dim]\nRegistry: {registry}", border_style="cyan", box=box.ROUNDED))

    # Basic facts
    t = Table(title="Registry Entry", box=box.SIMPLE_HEAVY)
    t.add_column("Field"); t.add_column("Value")
    for k in ("name","id","namespace","version","description","publisher","homepage","website"):
        v = entry.get(k)
        if v:
            t.add_row(k, str(v))
    console.print(t)

    # Publisher trust
    ns = entry.get("namespace") or entry.get("name") or entry.get("id") or ""
    explicit_verified = entry.get("verified") or entry.get("publisher_verified") or entry.get("is_verified")
    likely_verified = explicit_verified or ns.startswith("io.github.") or re.match(r"([a-z0-9-]+\.)+[a-z]{2,}/", ns) is not None

    t = Table(title="Publisher Trust", box=box.SIMPLE_HEAVY)
    t.add_column("Check"); t.add_column("Result")
    t.add_row("Namespace looks verified (DNS/GitHub)", bool_emoji(likely_verified))
    t.add_row("Registry 'verified' flag", str(explicit_verified))
    if repo_stats.get("owner_type"):
        t.add_row("GitHub owner type", str(repo_stats["owner_type"]))
    t.add_row("GitHub org verified (approx.)", str(repo_stats.get("org_is_verified_guess")))
    console.print(t)

    # Tools & resources
    tools, resources, risk = summarize_tools_resources(entry)
    t = Table(title="Declared Capabilities", box=box.SIMPLE_HEAVY)
    t.add_column("Type"); t.add_column("Items")
    t.add_row("Tools", ", ".join(tools[:15]) + (" …" if len(tools) > 15 else ""))
    t.add_row("Resources", ", ".join(resources[:15]) + (" …" if len(resources) > 15 else ""))
    if risk:
        t.add_row("Risk Notes", " | ".join(risk))
    console.print(t)

    # Repo stats & security
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

    # Scores
    st = Table(title="Scores (0–100)", box=box.SIMPLE_HEAVY)
    st.add_column("Dimension"); st.add_column("Score")
    for k in ("publisher_trust","security_posture","maintenance","license","privacy_signal","overall"):
        st.add_row(k, str(scores[k]))
    console.print(st)

    # Manual review checklist
    checklist = [
        ("Permissions & scopes alignment", "MCP servers don’t request runtime scopes like extensions; review tools/resources and any required env vars."),
        ("Test in non-prod", "Run server in a sandboxed host; monitor latency and side-effects."),
        ("GDPR compliance", "Confirm if personal data is processed; obtain a DPA where applicable."),
        ("Data residency", "Verify storage/processing locations; prefer EU or SCCs in place."),
        ("Privacy policy", "Locate and review publisher’s policy for collection/usage/sharing."),
        ("Support options", "Docs, discussion forum, issue response times, security contact."),
        ("DR/rollback", "Plan rollback if server breaks workflows."),
    ]
    ct = Table(title="Manual Review Needed", box=box.SIMPLE_HEAVY)
    ct.add_column("Item"); ct.add_column("Action")
    for a,b in checklist:
        ct.add_row(a,b)
    console.print(ct)

def main():
    ap = argparse.ArgumentParser(description="MCP quality audit from registry + GitHub signals")
    ap.add_argument("name", help="MCP name (e.g., com.example/my-mcp). Use --fuzzy to search by keyword.")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY, help="MCP registry base URL")
    ap.add_argument("--fuzzy", action="store_true", help="Search instead of exact lookup")
    ap.add_argument("--json", action="store_true", help="Output machine-readable JSON in addition to rich report")
    args = ap.parse_args()

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
