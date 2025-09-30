# MCP Quality Audit 🕵️‍♀️✨
*A slightly overconfident CLI that sizes up Model Context Protocol (MCP) servers like a bouncer at a very nerdy nightclub.*

> “Trust me, I’m a script.” — Also the last words of many scripts

---

## What is this?
`mcp_quality_audit.py` is a command‑line tool that:
- Talks to the **official MCP Registry** (`/v0/servers`) to discover servers
- Peeks at linked **GitHub repos** for vibes data (license, commits, issues)
- Does a **light secret sniff** (no shame, just regex)
- Rolls everything up into a **quality score** so you can decide if an MCP server is:
  - 🟢 “Ship it”  
  - 🟡 “Maybe. In a sandbox. With a helmet.”  
  - 🔴 “Absolutely not. Block it with a firewall and holy water.”

It’s designed to help you do **quick due diligence**, not to replace your security team (hi security team, please don’t @ me).

---

## Features (now with 17% extra sass)
- `--list` — Enumerate servers from the MCP Registry (cursor‑based pagination! wow such API)
- `--search "<query>"` — Filter server list by keyword
- `--csv <path|- >` — Export a tidy CSV for spreadsheets and/or questionable pivot tables
- `--page-size` & `--limit` — You get a page size! You get a page size! Everyone gets a page size!
- Single‑server audit with **evidence‑based** signals:
  - Publisher trust (namespace + GitHub org hints)
  - Security posture (security issue hits + secret smells)
  - Maintenance (freshness of commits)
  - License sanity check
  - Privacy/GDPR *vibes* (keyword hints in README)
- Pretty terminal output via `rich` **and** `--json` for machines that don’t appreciate dramatic tables

---

## Installation
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

> Minimal `requirements.txt`:
> ```txt
> requests
> python-dateutil
> rich
> ```

Optional but recommended (for kinder GitHub API rate limits):
```bash
export GITHUB_TOKEN=ghp_yourTokenGoesHere
```

---

## Quickstart

### 1) List some servers
```bash
python mcp_quality_audit.py --list --limit 20
```

### 2) Search and CSV it
```bash
python mcp_quality_audit.py --list --search git --csv servers.csv
# or dump CSV to stdout:
python mcp_quality_audit.py --list --csv - | head
```

### 3) Audit a specific MCP (fuzzy search FTW)
```bash
python mcp_quality_audit.py filesystem --fuzzy
```

### 4) Machine‑readable output
```bash
python mcp_quality_audit.py fetch --fuzzy --json > fetch_audit.json
```

---

## Scoring (a.k.a. “The Sorting Hat, but for MCPs”)
Each dimension gets 0–100, then we compute a tasteful weighted average:

- **Publisher Trust (30%)** — Registry verification hints + GitHub org vibes  
- **Security Posture (30%)** — Security issue hits + secret smell penalties  
- **Maintenance (25%)** — Latest commit recency (fresh code smells better)  
- **License (10%)** — MIT/Apache/BSD/MPL get full points; everything else gets “it depends”  
- **Privacy Signal (5%)** — README keywords like “privacy”, “GDPR”, “EU data”

> This is a **heuristic**. It’s here to *start* the conversation, not finish it. Bring humans. Preferably caffeinated ones.

---

## What this tool actually checks
- ✅ **Registry**: `/v0/servers`, supports `limit` & `cursor` (no trailing slash)
- ✅ **GitHub repo**: stars, forks, open issues, license, latest commit
- ✅ **Security signals**: searches for “security”/“CVE” in issues (best‑effort)
- ✅ **Secret sniff**: simple regex pass over a small sample of repo files
- ✅ **Privacy vibes**: README keyword scan

### What it does **not** do
- ❌ Replace SAST/DAST/SCA (please don’t fire your scanners)
- ❌ Prove GDPR compliance (you still need lawyers and/or a deep sigh)
- ❌ Guarantee safety (if you figure out how, call me immediately)

---

## CLI Reference (abridged but adorable)
```text
mcp_quality_audit.py [NAME] [flags]

Positional:
  NAME                MCP server id or name (use --fuzzy for loose matching)

Flags:
  --list              List servers (and exit)
  --search QUERY      Filter when using --list
  --limit N           Max items to list (default: 200)
  --page-size N       Per-page size for registry calls (max 100)
  --csv PATH          Export CSV (use '-' for stdout) with --list
  --registry URL      MCP registry base (default: https://registry.modelcontextprotocol.io)
  --fuzzy             Fuzzy search when auditing a single NAME
  --json              Also print JSON blob (great for pipelines)
```

---

## Exit Codes (so your CI can judge harshly)
- `0` — Success / results found
- `2` — No results / input error / registry said “nope”

---

## Tips & Tricks
- Set `GITHUB_TOKEN` to avoid rate‑limit grumpiness.
- For super‑large listings: `--limit 1000 --page-size 100`
- CSV + jq + xsv = ✨ data wrangling magic ✨
- Think an MCP looks suspicious? **Test in a sandbox.** If it breaks things,
  congrats: you’ve done science.

---

## Contributing
PRs welcome! Please keep the tone cheeky but professional. If you add a feature,
consider a flag. (Engineers love flags. We hoard them like dragons.)

---

## License
MIT. (Because life is short and lawyers are expensive.)

---

## Disclaimer (the serious bit)
This tool provides **heuristics** and **hints**. It does not constitute a
security assessment, legal advice, or a promise that the universe will behave.
Use your organization’s security policies, staging environments, and common sense.
