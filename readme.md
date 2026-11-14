# bounty_recon v2.5.0

**Bug Bounty Passive Recon & Misconfiguration Scanner**  
Single-file Python — HackerOne / Bugcrowd ready.  
Inspired by AutoAR (h0tak88r) and the AI Bug Hunting Framework approach.

---

## Installation

```bash
pip3 install httpx dnspython rich
# Optional: nuclei, dalfox
```

---

## Usage

```bash
# Basic scan
python3 bounty_recon.py -t example.com

# Full scan + JS secrets
python3 bounty_recon.py -t example.com --js --json --out-dir ./reports

# With CORS origin to test
python3 bounty_recon.py -t example.com \
  --cors-origin https://bo.example.com \
  --no-subdomains --js --json

# Import Dalfox output (deduplicated, confidence-filtered)
dalfox url https://example.com > dalfox_out.txt
python3 bounty_recon.py -t example.com \
  --import-dalfox dalfox_out.txt \
  --min-confidence 1.0

# Import nuclei JSONL output
nuclei -u https://example.com -jsonl -o nuclei.jsonl
python3 bounty_recon.py -t example.com \
  --import-nuclei nuclei.jsonl

# Full combo
python3 bounty_recon.py -t example.com \
  --no-subdomains --js \
  --cors-origin https://bo.example.com \
  --import-dalfox dalfox_out.txt \
  --import-nuclei nuclei.jsonl \
  --min-confidence 1.0 \
  --json --out-dir ./reports
```

---

## Modules

| # | Module | Flag | Description |
|---|--------|------|-------------|
| 1 | Subdomain enum | default | crt.sh + SecurityTrails |
| 2 | DNS + takeover | default | A/CNAME/MX + 20 service fingerprints |
| 3 | Live hosts | default | HTTPS/HTTP reachability |
| 4 | Tech fingerprint | default | Server headers, CDN detection |
| 5 | Endpoint sweep | default | 60+ sensitive paths, HTML FP filter |
| 6 | Security headers | default | 9 headers × all hosts |
| 7 | TLS check | default | Expiry, TLS 1.0/1.1, weak ciphers |
| 8 | CORS | default | Reflected origin + credentials |
| 9 | Exposures | default | JWKS, source maps, .git |
| 10 | JS secrets | `--js` | 13 patterns across JS bundles |
| 11 | S3 buckets | `--s3` | 30 name permutations |
| 12 | GitHub recon | `--github-repo` | Code Search API secret scan |
| 13 | nuclei | `--nuclei` | Read-only wrapper |
| 14 | Dalfox import | `--import-dalfox` | XSS results → deduplicated findings |
| 15 | nuclei import | `--import-nuclei` | JSONL → structured findings |

---

## False Positive Filtering

| Issue | Fix in v2.5 |
|-------|-------------|
| `Password in URL` from Next.js bundles | Expanded DUMMY_HOSTS + substring filter + min length 6 |
| CSP `unsafe-inline` with nonce | Downgraded to Low (nonce gates execution) |
| CSP `unsafe-eval` with nonce | Downgraded to Low |
| Dalfox: 94 hits on same params | Deduplicated by parameter name, highest confidence kept |

---

## Dalfox Integration

Run Dalfox separately, import output:

```bash
# Install
go install github.com/hahwul/dalfox/v2@latest

# Run (save output to file)
dalfox url "https://cody.fluttercee.com" \
  --follow-redirects \
  --output dalfox_cody.txt

# Import into report (confidence >= 1.0 = High/Medium only)
python3 bounty_recon.py -t cody.fluttercee.com \
  --import-dalfox dalfox_cody.txt \
  --min-confidence 1.0 \
  --no-subdomains --json
```

Confidence mapping:
- `>= 1.4` → **High**
- `>= 1.0` → **Medium**
- `< 1.0` → **Low** (filtered out by default with `--min-confidence 1.0`)

---

## Output

```
reports/
├── target_com_YYYYMMDD_HHMM.md    ← Markdown report
└── target_com_YYYYMMDD_HHMM.json  ← JSON (--json flag)
```

---

## Ethics

Read-only passive scanning only. No credentials submitted, no payloads injected, no state modified.  
Use only on **authorised targets** (bug bounty in-scope, owned assets, explicit written permission).

---

## License

MIT

---

## CVE Fingerprint Detection (`--cve`)

Passive detection of known vulnerable products. No payloads, no exploitation.

```bash
# Basic CVE scan
python3 bounty_recon.py -t example.com --cve --no-subdomains

# Full combo with Dalfox import
python3 bounty_recon.py -t example.com \
  --no-subdomains --js --cve \
  --import-dalfox dalfox_out.txt \
  --min-confidence 1.0 \
  --json --out-dir ./reports
```

| CVE / ID | Product | Severity |
|----------|---------|----------|
| CVE-2024-1709 | ConnectWise ScreenConnect | Critical |
| Oracle-Security 0-Day | N-Central N-Able MMS | Critical |
| Oracle-Security 0-Day | N-Central Account Enum | Medium |
| CVE-2026-12943 | IBM HMC | Critical |
| Oracle-Security 0-Day | IBM PowerVM Novalink | Critical |
| CVE-2018-14486 | DotNetNuke (DNN) | High |
| CVE-2023-5204 | WordPress Chatbot Plugin | High |
| CVE-2023-6737 | WordPress Enable Media Replace | High |
| CVE-2023-49833 | WordPress Spectra Plugin | Medium |
| CVE-2023-38826/38827 | Follett Destiny | Critical |
| CVE-2023-51062–51071 | QStar Archive Solutions | Critical |
| INFO | phpMyAdmin exposed | High |
| INFO | Spring Boot Actuator env | High |

All checks are **passive fingerprinting only** — URL probe + response body/header matching.
No exploit payloads are sent.
