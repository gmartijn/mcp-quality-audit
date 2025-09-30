# CALCULATION.md 🧮✨
*The highly scientific* (™) *way this tool turns vibes into numbers and numbers into a risk label.*

> “Math is just poetry for spreadsheets.” — someone who has definitely been left alone with `jq` for too long

---

## TL;DR (for busy humans and thirsty cacti)
We grade an MCP server on **five things** (0–100 each), mix them with **weights**, get an **overall score**, then translate that into a **risk rating**:  
**Very Low → Low → Medium → High → Critical**.  
High score = chill. Low score = nope.

---

## The Five Ingredients (chef’s kiss)
1. **Publisher Trust** — Does the namespace look verified and does the GitHub org seem like real adults are in charge?
2. **Security Posture** — Any “security/CVE” drama in issues? Any *oopsie* secrets in code? (We do a small regex sniff. We’re nosy, not creepy.)
3. **Maintenance** — When was the last commit? Fresh code is like fresh bread: smells better and grows less mold.
4. **License** — MIT/Apache/BSD/MPL: ⭐⭐⭐⭐⭐. GPL/AGPL/LGPL: “depends on policy.” Unknown license: side‑eye.
5. **Privacy Signal** — Do docs even whisper “privacy”, “GDPR”, or “EU data”? It’s a hint, not legal advice. (We’re a script, not your lawyer.)

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
If yours don’t add up to 1.0, we **normalize** them. (Think of it as refilling the pot so your cactus doesn’t tip over.)

Change them any time:
```bash
--weights '{"publisher_trust":0.25,"security_posture":0.35,"maintenance":0.25,"license":0.10,"privacy_signal":0.05}'
# or
--weights-file weights.json
```

---

## The Math (nothing up our sleeves)
We do a **weighted average**, then round to one decimal:

```
overall = 0.30*publisher_trust
        + 0.30*security_posture
        + 0.25*maintenance
        + 0.10*license
        + 0.05*privacy_signal
```

That’s it. No secret blockchain. No AI deciding your horoscope. Just polite arithmetic.

---

## Risk Rating (what you actually wanted)
We map the **overall** score → a label using **thresholds** (defaults below). We pick the **highest** label whose minimum ≤ score.

```
very_low : 90
low      : 75
medium   : 60
high     : 40
critical : 0
```

Tweak them to suit your appetite for chaos:
```bash
--risk-thresholds '{"very_low":92,"low":80,"medium":65,"high":45,"critical":0}'
# or
--risk-thresholds-file thresholds.json
```

**Translations for humans:**
- **Very Low** — Go ahead. Deploy it. Name your pipeline “YOLO” if you must.
- **Low** — Sensible. Maybe wear a helmet in staging.
- **Medium** — Reasonable people could disagree. Add logging. Add snacks.
- **High** — Proceed only if you enjoy whack‑a‑mole.
- **Critical** — Put it down. Back away. Unplug the keyboard.

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

Is it perfect? No. Is it useful? Absolutely. Like duct tape, but for governance.

---

## What’s Automated vs. “Please Use Your Brain”
- ✅ Automated: registry lookups, basic GitHub stats, best‑effort security keyword search, light secret sniff, README keyword check.
- 🧠 Manual sanity: actual GDPR compliance, data residency guarantees, permissions review, and whether deploying this will make the on‑call cry.

Pro tip: **Test in staging.** If it explodes, that’s a data point.

---

## FAQ (Frequently Asked Quibbles)
**Q. Can I game the score?**  
A. You can try. But if you push secrets to GitHub, the regex goblins will find them.

**Q. Why is privacy only 5%?**  
A. Because signals are weak without contracts. Want it higher? Bump the weight. Be the change you want to audit.

**Q. The score is 74.9 and says Medium. I demand Low.**  
A. Adjust thresholds or ship better software. Preferably both.

**Q. Is this a replacement for security review?**  
A. No. It’s an **early warning system** with good bedside manner.

---

## Final Word
This file contains **feelings about math**. Use it to prioritize work and guide conversations, not to end them. May your pipelines be green and your secrets be `.gitignored`.
