# MCP Quality Audit 🕵️‍♀️✨
*A CLI that judges Model Context Protocol (MCP) servers with the subtlety of a reality TV judge.*

---

## What is this?
`mcp_quality_audit.py` is a **command-line tool** that:
- Fetches MCP server entries from the **official registry**
- Cross-checks their linked **GitHub repos** for signals
- Runs a **shallow secret scan** (regex only, promise)
- Produces an **overall score** and **risk rating**:
  - 🟢 Low  
  - 🟡 Medium  
  - 🟠 High  
  - 🔴 Critical  

Designed for **due diligence** before adoption. Not a lawyer. Not your security team. Definitely not a substitute for coffee.

---

## Features
- ✅ **Registry lookups** — `--list`, `--search`, `--csv`
- ✅ **Single-server audit** with GitHub enrichment
- ✅ **Risk scoring** across:
  - Publisher trust
  - Security posture
  - Maintenance
  - License sanity
  - Privacy signal
- ✅ **Explainable results** with `--explain-risk`
- ✅ **Optional PDF reports** (pretty heatmaps for managers)
- ✅ **Configurable weights & thresholds**
- ✅ **Safe defaults** with options to tune
- ✅ **Jokes included** at no extra charge

---

## Example

```bash
python mcp_quality_audit.py filesystem --fuzzy
```

Output:
```
╭────────────────────────────────────────────────────╮
│ MCP Quality Assessment                             │
│ filesystem                                         │
│ Registry: https://registry.modelcontextprotocol.io │
│ Risk Rating: High  •  Score: 48.2/100              │
╰────────────────────────────────────────────────────╯
```

Want to see the math receipts? Run with:
```bash
python mcp_quality_audit.py filesystem --explain-risk
```

---

## Installation
```bash
pip install -r requirements.txt
```

### Requirements
- **Core**: `requests`, `urllib3`, `python-dateutil`, `rich`  
- **Optional (for PDF)**: `matplotlib`

Set your GitHub token if you want fewer “rate limit” scoldings:
```bash
export GITHUB_TOKEN=ghp_yourTokenHere
```

---

## Scoring & Risk
We take **five scores (0–100)**, multiply by weights, sum them up, and call it an “overall score.”  
Then we map that score to a label using thresholds.  

**Curious about how this works?**  
See [CALCULATION.md](CALCULATION.md) — it’s like the director’s cut of the math, complete with sarcasm.  

---

## Exit Codes
- `0` → Success  
- `2` → Input error / no results  

---

## License
MIT. Because life is short and **lawyers are expensive**.

---

## Disclaimer
This script gives you **signals, not guarantees**. Use your staging environment, use your brain, and remember: if your lawyers ask, this README never existed.

---

## Hilarious FAQ 🤡

**Q: Will this tool guarantee my MCP is safe?**  
A: Absolutely not. It will, however, guarantee you some smugness when you say, “Well, *our* audit said medium risk.”

**Q: Why does the secret scanner look for AWS keys?**  
A: Because people keep committing AWS keys. Stop doing that. Please. Jeff Bezos does not need more hobbies.

**Q: Can I use this tool in production?**  
A: Yes, but also… why would you? Think of it like a metal detector: useful before boarding the plane, not mid-flight.

**Q: Why does it sometimes yell about rate limits?**  
A: Because GitHub is not your unlimited buffet. Bring a `GITHUB_TOKEN`, tip your API, and pace yourself.

**Q: My score is “critical.” Should I panic?**  
A: Don’t panic. Unless you like panic. In which case, panic responsibly and write a retro afterwards.

**Q: Why is there a PDF option?**  
A: Because managers love PDFs. They can’t grep them, but boy do they love stapling them to PowerPoints.

**Q: Does this replace a proper security team?**  
A: No. This tool is like a snarky intern: it spots obvious problems but should never be put in charge of your firewall.

**Q: Will using this tool make me more attractive?**  
A: Only to other people who read README files for fun. Which, frankly, is the hottest demographic.
