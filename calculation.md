# CALCULATION.md 🧮✨
*The highly scientific* (™) *way this tool turns vibes into numbers and numbers into a risk label.*

> “Math is just poetry for spreadsheets.” — someone who has definitely been left alone with `jq` for too long

---

## TL;DR (for busy humans and caffeinated raccoons)
We grade an MCP server on **five things** (0–100 each), mix them with **weights**, get an **overall score**, then translate that into a **risk rating**:  
**Low → Medium → High → Critical**.  
High score = relax. Low score = maybe hide under your desk.

---

## The Five Ingredients (chef’s kiss)
1. **Publisher Trust** — Does the namespace look verified and does the GitHub org seem like real adults are in charge?
2. **Security Posture** — Any “security/CVE” drama in issues? Any *oopsie* secrets in code? (We do a regex sniff. Nosy, not creepy.)
3. **Maintenance** — When was the last commit? Are there real humans contributing? Fresh repos smell like fresh bread.
4. **License** — MIT/Apache/BSD/MPL: ⭐⭐⭐⭐⭐. GPL/AGPL/LGPL: “depends on policy.” No license: side-eye and a sigh.
5. **Privacy Signal** — README mentions “privacy”, “GDPR”, or “EU data”? Homepage links a privacy policy? It’s a vibe check, not legal advice. (We’re a script, not your lawyer.)

Each gets a score from **0–100**. We don’t argue with you; we just judge silently.

---

## The Secret Sauce (weights)
Default weighting of the five ingredients:
```
publisher_trust  : 0.30
security_posture : 0.30
maintenance      : 0.25
license          : 0.10
privacy_signal   : 0.05
```
If yours don’t add up to 1.0, we **normalize** them. (Think of it as topping up your coffee until the cup is full again.)

Change them any time:
```bash
--weights '{"publisher_trust":0.25,"security_posture":0.35,"maintenance":0.25,"license":0.10,"privacy_signal":0.05}'
# or
--weights-file weights.json
```

---

## The Math (abracadabra, but with decimals)
We do a **weighted average**, then round to one decimal:

```
overall = 0.30*publisher_trust
        + 0.30*security_posture
        + 0.25*maintenance
        + 0.10*license
        + 0.05*privacy_signal
```

That’s it. No neural networks, no dice rolls. Just arithmetic with a side of sass.

---

## Risk Rating (the rainbow of nope)
We map the **overall** score → a label using **thresholds** (defaults below).  
We pick the **highest** label whose minimum ≤ score.

```
low      : 75
medium   : 60
high     : 40
critical : 0
```

Tweak them to match your risk appetite:
```bash
--risk-thresholds '{"low":80,"medium":65,"high":45,"critical":0}'
# or
--risk-thresholds-file thresholds.json
```

**Translations for humans:**
- **Low** — Deploy with joy. Maybe even whistle.
- **Medium** — Add logging, snacks, and maybe a contingency plan.
- **High** — You’re living dangerously. Expect pager alerts at 3 a.m.
- **Critical** — Put it down. Back away slowly. Make the sign of the cross with your keyboard.

---

## Tiny Example (math with vibes)
Scores: trust=80, security=70, maintenance=65, license=100, privacy=60  
Weights: 0.30, 0.30, 0.25, 0.10, 0.05

```
80*0.30 = 24.00
70*0.30 = 21.00
65*0.25 = 16.25
100*0.10 = 10.00
60*0.05 = 3.00
Total = 74.25 → rating “Medium”
```

Useful? Yes. Perfect? No. Like duct tape, but for governance.

---

## What’s Automated vs. “Please Use Your Brain”
- ✅ Automated: registry lookups, GitHub stats, security keyword search, secret sniff, README keyword check, license parsing.
- 🧠 Manual sanity: actual GDPR compliance, data residency guarantees, permissions alignment, and whether deploying this will make your on-call cry.

Pro tip: **Test in staging.** If it explodes, that’s a data point.

---

## Step-by-Step Explainability
If you run with `--explain-risk`, you get:
- Per-dimension breakdowns (how each score was built, deltas, caps, penalties).
- Weighted contribution table (see which dimension carried you).
- Threshold mapping (why you ended up Medium instead of Low).

Basically: math receipts you can wave in meetings.

---

## FAQ (Frequently Argued Quibbles)
**Q. Can I game the score?**  
A. You can try. But if you push secrets to GitHub, the regex goblins will find them. Again.

**Q. Why is privacy only 5%?**  
A. Because signals are weak without contracts. Want it higher? Bump the weight. Audit like you mean it.

**Q. The score is 74.9 and says Medium. I demand Low.**  
A. Either adjust thresholds… or ship better code. Preferably both.

**Q. Is this a replacement for a security review?**  
A. No. This is the early warning intern. Your security team is still the adult in the room.

---

## Final Word
This file contains **feelings about math**.  
Use it to prioritize and guide conversations, not to end them.  
May your pipelines be green and your secrets forever `.gitignored`.  
