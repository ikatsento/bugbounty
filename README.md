# bounty_recon

**Bug Bounty Passive Recon & Misconfiguration Scanner**  
Single-file Python tool for HackerOne / Bugcrowd recon and misconfiguration discovery.  
Inspired by [AutoAR](https://github.com/h0tak88r/AutoAR) — Python edition, no Go required.

---

## Features

| Module | Description |
|--------|-------------|
| Subdomain enum | crt.sh + SecurityTrails (optional API key) |
| DNS resolution | A / CNAME / MX records via dnspython |
| DNS takeover | Dangling CNAME detection (20+ services) |
| Live host check | HTTPS/HTTP reachability + redirect follow |
| Tech fingerprint | Server headers, X-Powered-By, CDN detection |
| Endpoint sweep | 60+ sensitive paths, HTML false-positive filter |
| Security headers | 9 headers × all live hosts |
| TLS check | Expiry, TLS 1.0/1.1, weak ciphers |
| CORS check | Reflected origin + Allow-Credentials |
| JWKS / source map | Exposure detection |
| JS secrets scan | 13 secret patterns across collected JS files |
| S3 buckets | 30 bucket name permutations |
| GitHub recon | Repo/org secret search via Code Search API |
| nuclei wrapper | Read-only: misconfig, headers, ssl, exposure |
| Report | Markdown + JSON structured output |

---

## Installation

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/bounty_recon.git
cd bounty_recon

# Install Python deps
pip3 install httpx dnspython rich

# Optional: nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## Usage

```bash
# Basic scan
python3 bounty_recon.py -t example.com

# Full scan — subdomains + JS secrets + S3 + nuclei
python3 bounty_recon.py -t example.com --nuclei --js --s3 --json --out-dir ./reports

# Custom CORS origin to test
python3 bounty_recon.py -t example.com \
  --cors-origin https://bo.example.com \
  --cors-origin https://admin.example.com

# Skip subdomain enum (faster — single host only)
python3 bounty_recon.py -t example.com --no-subdomains

# GitHub repo secret scan
python3 bounty_recon.py -t example.com \
  --github-repo owner/repo \
  --github-token ghp_xxxx

# API keys via env vars
export GITHUB_TOKEN=ghp_xxxx
export SECURITYTRAILS_API_KEY=xxxx
python3 bounty_recon.py -t example.com --js --s3

# Full output
python3 bounty_recon.py -t example.com \
  --nuclei --js --s3 \
  --cors-origin https://bo.example.com \
  --out-dir ./reports \
  --json
```

---

## Output

```
reports/
├── example_com_20261031_0541.md    ← Markdown report
└── example_com_20261031_0541.json  ← JSON (with --json)
nuclei_output.jsonl                 ← raw nuclei output (if --nuclei)
```

---

## Example Findings

```
🔴 [Critical] DNS takeover — github.io
   CNAME docs.example.com → example.github.io (unclaimed)

🔴 [Critical] Secret in JS: OpenAI Key
   https://example.com/static/js/main.chunk.js
   Pattern: sk-[a-zA-Z0-9]{20,}

🟠 [High] Sensitive endpoint exposed: health
   curl -si "https://api.example.com/api/v1/health"
   → HTTP 200 {"status":"ok","env":"prod","version":"0.1.0"}

🟠 [High] CORS reflects origin with Allow-Credentials:true
   curl -si -H "Origin: https://bo.example.com" "https://api.example.com/health"
   → ACAO: https://bo.example.com | ACAC: true

🟠 [High] TLS: backend accepts TLS 1.0 — PCI-DSS violation

🟡 [Medium] JWKS endpoint exposed — RSA public key disclosed
   curl -si "https://api.example.com/.well-known/jwks.json"
   → HTTP 200 {"keys":[{"kty":"RSA","alg":"RS256"...}]}

🟡 [Medium] n8n /rest/settings exposed
   → passwordMinLength:8, MFA disabled, communityNodesEnabled:true
```

---

## Modules Reference

### Subdomain Enumeration
- **crt.sh**: Free certificate transparency search (no key needed)
- **SecurityTrails**: Set `--securitytrails-key` or `SECURITYTRAILS_API_KEY` env var

### DNS Takeover Detection
Checks CNAME targets against 20+ service fingerprints including:
GitHub Pages, Heroku, Shopify, Fastly, AWS S3, Azure, CloudFront, Bitbucket, Zendesk, Ghost, Surge, Tumblr, WordPress, and more.

### JS Secrets Scan (`--js`)
Collects all `<script src>` references from the target page, then scans each for:
AWS keys, OpenAI keys, Google API keys, GitHub tokens, JWT tokens, Bearer tokens, Slack tokens, Stripe keys, SendGrid keys, generic API keys and secrets.

### S3 Bucket Check (`--s3`)
Tests 30 permutations of the domain name as S3 bucket names (with common prefixes: dev-, staging-, prod-, backup-, data-, assets-, etc.)

### GitHub Recon (`--github-repo` / `--github-token`)
Uses GitHub Code Search API to find matches for sensitive keywords (password, secret, api_key, token, ACCESS_KEY) in a specified repository.

### nuclei (`--nuclei`)
Wraps nuclei with read-only tags: `misconfig,exposure,config,headers,ssl,file,token,generic`
Rate limited to 50 req/s, 10 concurrent — safe for bug bounty.

---

## Requirements

- **Python 3.9+**
- `httpx` — async HTTP client
- `dnspython` — DNS resolution
- `rich` — pretty terminal output (optional but recommended)
- `nuclei` — vulnerability scanner (optional, for `--nuclei` flag)

```
pip3 install httpx dnspython rich
```

---

## Environment Variables

| Variable | Usage |
|----------|-------|
| `GITHUB_TOKEN` | GitHub personal access token for `--github-repo` |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API key for subdomain enum |

---

## Ethical Use

This tool performs **read-only, unauthenticated GET probes only**.

- No credentials submitted
- No state modified
- No payloads injected
- No webhooks or workflows triggered
- Rate-limited nuclei (50 req/s max)

**Use only on targets where you have explicit written permission or in-scope bug bounty programs.**

---

## Comparison with AutoAR

| Feature | bounty_recon | AutoAR |
|---------|-------------|--------|
| Language | Python 3 | Go |
| Install | `pip install` | Go build / Docker |
| Single file | ✅ | ❌ (multi-module) |
| Subdomain enum | crt.sh + SecurityTrails | 15+ sources |
| DNS takeover | ✅ 20 services | ✅ full suite |
| JS secrets | ✅ 13 patterns | ✅ |
| nuclei | ✅ wrapper | ✅ native |
| S3 buckets | ✅ basic | ✅ full |
| GitHub recon | ✅ Code Search | ✅ full + org |
| Web dashboard | ❌ | ✅ v4.1+ |
| AI agent | ❌ | ✅ |
| Docker | ❌ | ✅ |

---

## License

MIT

## Disclaimer

For authorised security testing only. The author assumes no liability for misuse.
