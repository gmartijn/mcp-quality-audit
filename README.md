# MCP Quality Audit 🕵️‍♀️✨
*A slightly overconfident CLI that sizes up Model Context Protocol (MCP) servers like a bouncer at a very nerdy nightclub.*

> “Trust me, I’m a script.” — Also the last words of many scripts

---

## What is this?
`mcp_quality_audit.py` is a command‑line tool that:
- Talks to the **official MCP Registry** (`/v0/servers`) to discover servers
- Peeks at linked **GitHub repos** for vibes data (license, commits, issues)
- Does a **light secret sniff** (no shame, just regex)
- Rolls everything up into a **quality score** *and* a **risk rating**
  - 🟢 “Very Low”
  - 🟡 “Low”
  - 🟠 “Medium”
  - 🟧 “High”
  - 🔴 “Critical”

It’s designed to help you do **quick due diligence**, not to replace your security team (hi security team, please don’t @ me).

> Curious how the score is calculated? See **[CALCULATION.md](./CALCULATION.md)** for the full, spicy breakdown.

---

## Features (now with 17% extra sass)
- `--list` — Enumerate servers from the MCP Registry (cursor‑based pagination)
- `--search "<query>"` — Filter server list by keyword
- `--csv <path|- >` — Export a tidy CSV for spreadsheets and/or questionable pivot tables
- `--page-size` & `--limit` — You get a page size! You get a page size! Everyone gets a page size!
- **Single‑server audit** with **evidence‑based** signals:
  - Publisher trust (namespace + GitHub org hints)
  - Security posture (security issue hits + secret smells)
  - Maintenance (freshness of commits)
  - License sanity check
  - Privacy/GDPR *vibes* (keyword hints in README)
- **Configurable scoring** via `--weights` / `--weights-file`
- **Configurable risk thresholds** via `--risk-thresholds` / `--risk-thresholds-file`
- **Proxy‑friendly networking** via `--skipssl` (skip TLS verification when your corporate proxy does SSL inspection)
- Pretty terminal output via `rich` **and** `--json` for machines that don’t appreciate dramatic tables

---

---

---

## Example Output

Here’s a real-world run using **`io.github.p1va/symbols`** (colors trimmed for Markdown).

```text
╭────────────────────────────────────────────────────╮
│ MCP Quality Assessment                             │
│ io.github.p1va/symbols                             │
│ Registry: https://registry.modelcontextprotocol.io │
│ Risk Rating: Low  •  Score: 86.2/100               │
╰────────────────────────────────────────────────────╯
                                Registry Entry                                 
                                                                               
  Field         Value                                                          
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 
  name          io.github.p1va/symbols                                         
  version       0.0.12                                                         
  description   MCP server to read, inspect and troubleshoot codebase symbols  
                                                                               
                 Publisher Trust                  
                                                  
  Check                                   Result  
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 
  Namespace looks verified (DNS/GitHub)   ✅      
  Registry 'verified' flag                None    
  GitHub owner type                       User    
  GitHub org verified (approx.)           None    
                                                  
            Declared Capabilities             
                                              
  Type         Items                          
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 
  Tools                                       
  Resources                                   
  Risk Notes   External network calls likely  
                                              
                  Repository & Security                  
                                                         
  Metric                Value                            
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 
  repo_url              https://github.com/p1va/symbols  
  stars                 0                                
  forks                 0                                
  open_issues           0                                
  latest_commit         2025-09-17T14:14:22Z             
  pushed_at             2025-09-17T14:14:27Z             
  archived              False                            
  disabled              False                            
  homepage                                               
  security_issue_hits   0                                
  Secret scan hits      0                                
                                                         
           Scores (0–100)            
                                     
  Dimension          Score   Weight  
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 
  publisher_trust    85      0.30    
  security_posture   100     0.30    
  maintenance        95      0.25    
  license            40      0.10    
  privacy_signal     60      0.05    
  overall            86.2    —       
                                     
  Risk Thresholds (min  
     score → label)     
                        
  Label      Min Score  
 ━━━━━━━━━━━━━━━━━━━━━━ 
  Very Low   90         
  Low        75         
  Medium     60         
  High       40         
  Critical   0          
                        
                                               Manual Review Needed                                               
                                                                                                                  
  Item                             Action                                                                         
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 
  Permissions & scopes alignment   Review tools/resources and any required env vars (MCP has no runtime scopes).  
  Test in non-prod                 Run server in sandbox; monitor latency/side-effects.                           
  GDPR compliance                  Confirm personal data processing; DPA if needed.                               
  Data residency                   Verify storage/processing locations.                                           
  Privacy policy                   Locate and review publisher’s policy.                                          
  Support options                  Docs, forums, issue responsiveness, security contact.                          
  DR/rollback                      Have a rollback plan if workflows break.                                       
```

## Installation
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

### 5) Behind a proxy that does SSL inspection?
```bash
# Disable TLS verification for all HTTP(S) calls this script makes
python mcp_quality_audit.py --list --skipssl

# Fuzzy audit + skip SSL verification
python mcp_quality_audit.py filesystem --fuzzy --skipssl
```
> ⚠️ **Safety note:** `--skipssl` disables certificate verification. Only use it in a trusted network (e.g., corporate proxy with SSL inspection). If you can, prefer installing your proxy’s root CA so you don’t need this flag.

---

## Scoring & Risk Rating (the tiny version)
- We score five areas (0–100): `publisher_trust`, `security_posture`, `maintenance`, `license`, `privacy_signal`.
- We combine them with weights (defaults: `0.30, 0.30, 0.25, 0.10, 0.05`).
- That yields an **overall score** (0–100), which maps to a **risk label**.
- Want the full story? **[Read CALCULATION.md](./CALCULATION.md)** — it’s funny *and* educational.

### Customize the knobs
```bash
# Adjust weights (normalized if they don't sum to 1)
python mcp_quality_audit.py filesystem --fuzzy \
  --weights '{"publisher_trust":0.25,"security_posture":0.35,"maintenance":0.25,"license":0.10,"privacy_signal":0.05}'

# Adjust thresholds (min score for each label)
python mcp_quality_audit.py fetch --fuzzy \
  --risk-thresholds '{"very_low":90,"low":75,"medium":60,"high":40,"critical":0}'
```

---

## Exit Codes (so your CI can judge harshly)
- `0` — Success / results found
- `2` — No results / input error / registry said “nope”

---

## Tips & Tricks
- Set `GITHUB_TOKEN` to avoid rate‑limit grumpiness.
- For big listings: `--limit 1000 --page-size 100`
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
