# MCP Quality Audit 🕵️‍♀️✨
*A slightly overconfident CLI that sizes up Model Context Protocol (MCP) servers like a bouncer at a very nerdy nightclub.*

> “Trust me, I’m a script.” — Also the last words of many scripts

---

## What is this?
`mcp_quality_audit.py` is a command-line tool that:
- Talks to the **official MCP Registry** (`/v0/servers`) to discover servers
- Peeks at linked **GitHub repos** for signals (license, activity, issues, security bits)
- Does a **light secret sniff** (regex only; no cloning)
- Rolls everything up into a **quality score** *and* a **risk rating** on a 4-level scale:
  - 🟢 **Low**
  - 🟡 **Medium**
  - 🟠 **High**
  - 🔴 **Critical**

It’s designed for **quick due diligence**, not to replace your security team (hi security team, please don’t @ me).

---

## Features (now with explainable receipts)
- `--list` — Enumerate servers from the MCP Registry (cursor-aware)
- `--search "<query>"` — Filter listed servers by keyword
- `--csv <path|- >` — Export a tidy CSV for spreadsheets and/or questionable pivot tables
- `--page-size` & `--limit` — Control registry pagination
- **Single-server audit** with evidence-based signals:
  - **Publisher trust** (namespace hints, registry flags, GitHub owner/org data)
  - **Security posture** (security keyword hits, optional SBOM/dependabot signals, optional secret scan)
  - **Maintenance** (freshness of commits + active devs in last 90 days)
  - **License** sanity check (SPDX)
  - **Privacy/GDPR** *vibes* (README hints)
- **Configurable scoring** via `--weights` / `--weights-file`
- **Configurable risk thresholds** via `--risk-thresholds` / `--risk-thresholds-file`
- **Explainable risk** via `--explain-risk` (step-by-step tables of how the number happened)
- **Optional PDF report** via `--pdf path.pdf` (pretty summary + heatmap)
- **Networking options**
  - `--skipssl` for environments with SSL-inspecting proxies (be careful)
- **GitHub options**
  - `--no-deps` to skip dependency graph + Dependabot lookups
  - `--max-commits` to cap signed-commit sampling
  - `--no-secret-scan` to skip shallow regex scanning

---

## Example Output

### Human-friendly terminal report
```
╭────────────────────────────────────────────────────╮
│ MCP Quality Assessment                             │
│ com.example/my-mcp                                 │
│ Registry: https://registry.modelcontextprotocol.io │
│ Risk Rating: Medium  •  Score: 72.4/100            │
╰────────────────────────────────────────────────────╯
...
```

### Explainable risk mode
```
python mcp_quality_audit.py com.example/my-mcp --explain-risk
```
Shows a **step-by-step breakdown** for each dimension.

### PDF report (optional)
```
python mcp_quality_audit.py com.example/my-mcp --pdf report.pdf
```

---

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Minimal `requirements.txt`:**
```txt
requests
urllib3
python-dateutil
rich
```

**Optional (for PDF reports):**
```txt
matplotlib
```

**GitHub rate limits will love you if you set a token:**
```bash
export GITHUB_TOKEN=ghp_yourTokenGoesHere
```

---

## Quickstart

### 1) List servers
```bash
python mcp_quality_audit.py --list --limit 20
```

### 2) Search + CSV export
```bash
python mcp_quality_audit.py --list --search git --csv servers.csv
```

### 3) Audit a specific MCP (fuzzy search FTW)
```bash
python mcp_quality_audit.py filesystem --fuzzy
```

### 4) Machine-readable JSON
```bash
python mcp_quality_audit.py fetch --fuzzy --json > fetch_audit.json
```

### 5) PDF report
```bash
python mcp_quality_audit.py com.example/my-mcp --pdf audit.pdf
```

---

## Scoring & Risk (the tiny version)

Scores five dimensions **0–100**:
- `publisher_trust`
- `security_posture`
- `maintenance`
- `license`
- `privacy_signal`

Default weights sum to 1.0, thresholds map overall score → risk.

---

## Exit Codes
- `0` — Success
- `2` — No results / input error

---

## License
MIT.

---

## Disclaimer
This tool provides **heuristics** and **hints**. Use your organization’s security policies, staging environments, and common sense.
