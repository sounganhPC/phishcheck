---
name: phishcheck
description: Verdict-check whether a link is phishing/impersonation without ever visiting it. Use immediately when the user asks "is this site legit?", shows a suspicious URL, or shares a strange link from email/SMS. Scores Korean official domains (go.kr), free DDNS, shorteners, lookalike strings, email tracking tokens, domain age, and offshore IPs into clean/caution/danger.
---

# phishcheck — link safety check

## Hard rule

- **Never visit or fetch the URL being checked.** Email/token query params
  are click trackers — fetching confirms the target is live. All verdicts
  come from passive lookups only (DNS, RDAP, geo-IP, pattern analysis).

## Usage

```bash
python phishcheck.py "<url>"          # human-readable verdict + reasons
python phishcheck.py "<url>" --json   # structured output
```

## Reading the output

- `정상` (clean, <20) / `주의` (caution, 20–49) / `위험` (danger, ≥50)
- Reasons are additive score entries — quote the 2–3 most damning ones
- Shortener verdicts mean "expand first": resolve the redirect target
  (e.g. `curl -I`) and re-run on the destination

## Answering the user

1. One-line verdict → 2. The clearest 2–3 reasons → 3. Action steps.
   If they clicked **and** typed credentials: change the password on the
   real site immediately, review login history, enable 2FA.
   If they clicked but typed nothing: only the "email is alive" signal
   leaked — expect more phishing, stay dismissive.

## Known limits

- Domain age resolves for `.kr`/`.com`/`.net` only (RDAP)
- Extend `DDNS` / `SHORTENERS` / `TRUSTED` constants as new patterns appear
- Geo-IP is a supporting signal, not proof
