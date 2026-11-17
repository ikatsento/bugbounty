# 🕵️ Bug Bounty Toolkit

**Passive Recon · Active Testing · AI-Assisted Triage · Payload Library**

> ⚠️ Use only on targets you have explicit written permission to test.

---

## Quick Start

```bash
# Install dependencies
pip install httpx dnspython rich anthropic playwright
playwright install chromium

# Full passive recon
python3 bounty_recon.py -t target.com --out-dir ./reports

# Full scan (all modules)
python3 bounty_recon.py -t target.com --full --out-dir ./reports

# Specific modules
python3 bounty_recon.py -t target.com --js --graphql --waf --ssrf --cve

# AI-assisted triage
python3 agentic/claude_hunter.py -t target.com

# Analyze existing report with AI
python3 agentic/claude_hunter.py -t target.com --findings-file reports/report.md

# AI payload suggestion
python3 agentic/claude_hunter.py -t target.com --tech "Next.js Auth.js" --vuln "SSTI"
```

---

## Repository Structure

```
bugbounty/
├── bounty_recon.py          ← Main scanner (v3.0)
├── agentic/
│   └── claude_hunter.py     ← AI-assisted recon loop (Claude API)
├── payloads/
│   ├── xss.txt              ← XSS: basic, WAF bypass, ATO chain, blind
│   ├── ssti.txt             ← SSTI: detection canaries + per-engine RCE
│   ├── sqli.txt             ← SQLi: union, blind, NoSQL, header injection
│   ├── ssrf.txt             ← SSRF: cloud metadata, protocol smuggling
│   ├── lfi.txt              ← LFI: traversal, PHP wrappers, log poisoning
│   ├── cmd_injection.txt    ← Cmd injection: space bypass, OOB, Windows
│   ├── waf_bypass.txt       ← WAF bypass: Cloudflare, Akamai, Imperva
│   └── xxe/
│       ├── basic.xml        ← XXE: file read, OOB, SSRF, SOAP
│       ├── svg_xxe.svg      ← SVG XXE for file upload endpoints
│       └── docx_xxe.py      ← DOCX XXE injector script
├── checklist/
│   ├── 2026_methodology.md  ← Full bug bounty methodology (Phase 1–5)
│   └── modern_surface.md    ← GraphQL, WebSocket, OAuth, Prototype Pollution, LLM
├── exploit_chains/
│   ├── xss_to_ato.md        ← XSS → Account Takeover chains A/B/C/D
│   └── ssrf_to_rce.md       ← SSRF → AWS Credentials → RCE
└── report_templates/
    └── report.md            ← HackerOne/Bugcrowd report template
```

---

## bounty_recon.py v3.0 — Module Reference

| Flag | Module | Description |
|------|--------|-------------|
| *(default)* | Subdomain enum | crt.sh + HackerTarget + AlienVault + Anubis + RapidDNS |
| *(default)* | DNS + Takeover | A/CNAME/MX + SPF/DMARC/CAA + 23 service fingerprints |
| *(default)* | Live hosts | HTTPS/HTTP reachability + tech fingerprinting |
| *(default)* | Endpoint sweep | 80+ sensitive paths with Soft-404 filter |
| *(default)* | Security headers | 9 required headers + CSP analysis |
| *(default)* | TLS check | Cert expiry + TLS 1.0/1.1 + weak ciphers |
| *(default)* | CORS | Reflected origin + Allow-Credentials |
| *(default)* | Exposures | JWKS, source maps, .git |
| `--graphql` | GraphQL | Introspection, batching, unauth ops |
| `--waf` | WAF fingerprint | Vendor + bypass tips |
| `--ssrf` | SSRF | Parameter name detection |
| `--ssrf-callback URL` | SSRF active | OOB probe injection |
| `--open-redirect` | Open redirect | 25 param names, reflected test |
| `--ssti` | SSTI canary | {{7*7}} injection, per-engine |
| `--proto-pollution` | Prototype pollution | __proto__ + constructor probe |
| `--race` | Race conditions | Coupon/transfer endpoint hints |
| `--idor` | IDOR | Numeric/UUID ID in API responses |
| `--lfi-xxe` | LFI/XXE surface | Param names + upload forms |
| `--js` | JS secrets | 22-pattern scan + endpoint extraction |
| `--wayback` | Wayback | Historical parameterised URLs |
| `--param-mine` | Param mining | Unique param name extraction |
| `--idn` | IDN | Homoglyph domain registration check |
| `--cve` | CVE fingerprints | 11 products (passive, no exploitation) |
| `--s3` | Cloud storage | S3 + GCS bucket permutations |
| `--nuclei` | nuclei | misconfig/exposure/headers/ssl templates |
| `--playwright` | Browser crawl | Dynamic SPA + XHR capture |
| `--import-dalfox FILE` | Import | Parse Dalfox XSS output |
| `--import-nuclei FILE` | Import | Parse nuclei JSONL output |
| `--full` | All modules | Enables every optional module |
| `--json` | JSON output | Write structured JSON report |

---

## AI Modules (claude_hunter.py)

| Mode | Command |
|------|---------|
| Full recon | `--target domain.com` |
| Subdomain triage | reads from subfinder/amass |
| Tech analysis | reads from httpx output |
| Findings analysis | `--findings-file report.md` |
| Payload suggestion | `--tech "Next.js" --vuln "SSRF"` |
| Stdin subdomains | `cat subs.txt \| python3 claude_hunter.py -t domain --stdin` |

---

## Recommended Tool Stack

```bash
# Recon
subfinder  — subdomain enumeration
amass      — additional passive DNS
httpx      — live host + tech detection
gau        — historical URLs from multiple sources
waybackurls — Wayback Machine URL extraction

# Scanning
nuclei     — vulnerability templates
dalfox     — XSS scanning
sqlmap     — SQL injection
ffuf       — directory / parameter fuzzing
param-miner (Burp) — hidden parameter discovery

# Manual
Burp Suite Professional
Caido (alternative to Burp)
Postman / Insomnia (API testing)

# OOB
interactsh-client  — OOB callback listener
Burp Collaborator  — OOB via Burp

# Install all Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

---

## Requirements

```
# Python
pip install httpx dnspython rich anthropic playwright

# Playwright browser
playwright install chromium

# Environment variables (optional)
export GITHUB_TOKEN=ghp_...
export SECURITYTRAILS_API_KEY=...
export ANTHROPIC_API_KEY=sk-ant-...  # for claude_hunter.py
```

---

*All tools and payloads are for authorized security testing only.*  
*Unauthorized use against systems you don't own is illegal.*
