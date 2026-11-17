# phishcheck

Score a suspicious link **without ever visiting it** — phishing URL checker
built for AI agents and the people who keep getting "your tax notice is ready"
texts.

## The problem it solves

Phishing links almost always carry a tracking token — your email, a campaign
ID, a click marker. *Opening* the link already tells the attacker "this target
is alive." So checking a sketchy URL by visiting it is self-defeating.

`phishcheck.py` never fetches the URL. It judges purely from passive evidence:
who owns the domain, how old it is, where the IP lives, and the structural
patterns phishers can't stop themselves from using.

## Install

```bash
pip install -r requirements.txt   # requests, tldextract
```

Python 3.10+, one file, no API keys needed.

## Usage

```bash
python phishcheck.py "https://verify861.aadpoly.dynu.net/eps/?echk=you@naver.com"
python phishcheck.py "<url>" --json    # machine-readable, for agents
```

```
판정: 위험 (80점) - dynu.net
  +45점: 무료 동적DNS 도메인 (dynu.net) — 피싱 단골
  +15점: 의심 키워드 ['verify', 'echk', 'eps']
  +20점: URL에 이메일/추적토큰 파라미터
  정보: IP 152.32.243.163 (KR, Ucloud ...)
```

Score ≥ 50 → **danger**, 20–49 → **caution**, below → **clean**.
Reasons print in Korean (it's a Korea-focused tool); `--json` gives the
structured breakdown.

## What it actually checks

| Signal | Why it matters |
|---|---|
| `go.kr` / `korea.kr` / `or.kr` whitelist | Korean government never uses anything else — huge trust anchor |
| Free DDNS hosts (dynu, duckdns, no-ip…) | Disposable phishing infrastructure; nobody legit verifies accounts there |
| Lookalike embedding (`naver.com.evil.com` class) | tldextract splits the real registered domain from disguise subdomains |
| Suspicious keywords (`verify`, `echk`, `login`…) | Campaign URL vocabulary |
| Email/token in query string | Click-tracking parameters — the phishing signature that motivated this tool |
| Domain age via RDAP (`.kr`, `.com`, `.net`) | <30 days old = classic throwaway phish |
| DNS → IP geolocation | "Korean ministry" hosted offshore is a red flag (weak signal — CDNs exist) |
| IP-literal hosts, punycode, subdomain stuffing | More costume jewelry |

Shorteners (bit.ly etc.) score as *caution* — expand them and re-check the
destination. Everything runs on heuristics, not blocklists, so it works on
campaigns that are minutes old.

## For AI agents

`--json` is the intended interface: an agent receiving mail/chat/scan output
can call this before ever touching a link, then explain the verdict to the
user. See [SKILL.md](SKILL.md) for a drop-in agent skill definition.

## Limitations

- Domain age only resolves for `.kr`, `.com`, `.net` (RDAP); other TLDs skip
- Geo-IP is a hint, not a verdict — legit Korean services do use foreign CDNs
- It scores the *URL*, not the content. A perfectly-registered domain hosting
  a phishing clone will need other signals (e.g. the brand it impersonates)

## License

MIT — see [LICENSE](LICENSE).

---

Built by **성안컴퓨터 (SeongAn Computer)** — a neighborhood computer shop in
South Korea that writes its own tools instead of buying them.
More of our work at [sounganh.com](https://sounganh.com).
