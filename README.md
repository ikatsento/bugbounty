# 🕵️ Bug Bounty Toolkit

**One script: Recon · Scanning · AI-Assisted Triage · Reporting — plus a payload/checklist library.**

> ⚠️ Use only on targets you have explicit written permission to test. Active
> modules send injection/probe traffic; keep them off (`--profile passive`)
> unless the target is in scope.

---

## Quick Start

```bash
# Install
pip install -r requirements.txt
# (optional) browser crawl:  playwright install chromium

# Read-only recon (safe default)
python3 bounty_recon.py -t target.com --profile passive --out-dir ./reports

# Safe non-destructive probes (headers, CORS, cache, open-redirect, nuclei)
python3 bounty_recon.py -t target.com --profile safe --html --out-dir ./reports

# Everything, including active injection + OOB probes (authorised targets only)
python3 bounty_recon.py -t target.com --profile aggressive \
    --ssrf-callback https://your.interactsh.com --html --json

# Pick individual modules
python3 bounty_recon.py -t target.com --js --graphql --waf --cache-poison --lib-versions

# AI triage + attack plan on the findings (auto-detects Ollama/Groq/Anthropic)
python3 bounty_recon.py -t target.com --profile safe --ai-triage --ai-plan
```

Everything is now **one file** — `bounty_recon.py`. The old `claude_hunter.py`
and `artemis_triage.py` have been merged into it (`--ai-triage` / `--ai-plan`).

`--html` now writes an **interactive dashboard** (v4.1): severity donut, stat tiles,
live text/severity filtering, collapsible findings with copy-to-clipboard, and
foldable recon sections (subdomains, live hosts, tech, params, WAF, AI plan). It's
a single self-contained file — open it anywhere, no server, no external assets.

**v4.2 — fewer false positives + inline verification.** The CVE fingerprinter now
rejects catch-all 404/error pages, SPA indexes, path-echo matches, and substring
bleed (e.g. `nable` in `enable`), so it only flags a *live product page*. SSTI
uses a randomized differential (random `a*b` + baseline + reflected-literal check)
instead of a fixed `{{7*7}}`→`49`. And every actionable finding now prints its
**copy-paste verification commands** (`↳ verify:` lines) right in the terminal —
what to run and how, per class (SSRF, XSS, IDOR, SSTI, CORS, CSP, …).

**v4.3 — framework mapping.** Every finding is now tagged to **MITRE ATT&CK**,
**OWASP Top 10 (2021)** and **OWASP WSTG** (the `🗺` line in the terminal, chips in
the HTML report, a `**Framework:**` line in Markdown) — reports that speak the
language triagers trust. See [`METHODOLOGY.md`](./METHODOLOGY.md). *(Mapping inspired
by [BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon), Apache-2.0.)*

**v4.4 — tests, SARIF, deeper JWT, more secrets.** A **pytest suite** now covers
the pure logic (JWT audit, secret library, SARIF, cookies, entropy, dedup,
severity order) — run `pip install -r requirements-dev.txt && pytest -q`.
`--sarif` writes a **SARIF 2.1.0** report for CI / code-scanning. The JWT audit
gained **alg-confusion (RS/ES→HS), `kid` injection and `jku`/`x5u` key-injection**
detection. The secret library added **20+ distinctive 2020-2026 token formats**
(GitLab/npm/fine-grained-GitHub PATs, Telegram, Discord, DigitalOcean, Vault,
Square, PyPI, Postman, `sk-ant-`, private-key blocks…). Modern 2020-2026
technique recipes (request smuggling/H2 desync, web cache deception, OAuth/SAML,
client-side gadgets) were added to [`ARSENAL.md`](./ARSENAL.md) as verified
recipes — deliberately **not** FP-prone auto-probes.

**v4.6 — unauthenticated-only (login replay removed).** This tool is
**no-login by design**: it never sends a cookie, session or auth header — every
module is pure unauthenticated black-box discovery. (The `--cookie` /
`--auth-state` / `--header` login flags briefly added in v4.5 were removed.)
Two unauthenticated checks, generalised from an authorised engagement, remain:
- **`--access-bypass`** — on endpoints that answer 401/403, retry with
  path-normalisation (`/%2e/`, `..;/`, `//`) **and** trusted-proxy header spoofs
  (`X-Forwarded-For`, `X-Original-URL`, …); report a High if a variant returns
  200 (confirm by hand). No credentials needed — it tests whether the edge/origin
  ACL can be tricked.
- **`--tls-downgrade`** — flags https endpoints that 3xx-redirect to cleartext
  `http://`. Both are in the `safe`/`full` profiles.

**v4.7 — reflected-XSS surface + richer SSRF.** Attack-surface techniques drawn
from [XSSRush](https://github.com/N45HT/XSSRush) and
[SSRFmap](https://github.com/swisskyrepo/SSRFmap), re-implemented to fit the
unauthenticated, no-browser design:
- **`--xss`** — reflects a unique canary plus a special-character matrix
  (`<>"'`` ` ``(){};=/`) through query params, then reports which **breakout
  chars survive unescaped** and classifies the context (`html-tag` / `attribute`
  / `javascript`). HTTP-only, so it's an XSS **lead to confirm in a browser** —
  it never claims execution (no false "alert fired"). In the `safe`/`full` profiles.
- **Richer SSRF** — the cloud-metadata target set grew (Alibaba `100.100.100.200`,
  Oracle OCI, Packet) and a `SSRF_BYPASS_PAYLOADS` list (decimal/hex/IPv6
  loopback, `gopher://`/`dict://`/`file://`) now feeds the manual SSRF recipe.
  32 tests, green.

---

## Repository Structure

```
bugbounty/
├── bounty_recon.py          ← the whole tool (recon + scan + AI triage + report)
├── ARSENAL.md               ← payloads, oneliners, WAF bypass, technique radar, submission rules
├── TOOLS.md                 ← ~400-tool catalog by phase + one-shot install
├── METHODOLOGY.md           ← MITRE ATT&CK / OWASP Top-10 / WSTG framework mapping
├── requirements.txt
├── Payloads/                ← payload library
│   ├── xss.txt   ssti.txt   sqli.txt   ssrf.txt
│   ├── lfi.txt   cmd_injection.txt      waf_bypass.txt
├── xxe/
│   ├── basic.xml  svg_xxe.svg  docx_xxe.py
├── Checklist/
│   ├── 2026_methodology.md  modern_surface.md
├── exploit_chains/
│   ├── xss_to_ato.md  ssrf_to_rce.md
└── report_templates/
    └── report.md
```

---

## Scan Profiles

| Profile | What runs | Traffic |
|---------|-----------|---------|
| `passive` | subdomains, DNS, live hosts, tech, endpoint sweep, headers, TLS, CORS, exposures, JS secrets, wayback, params, CVE fingerprint, lib-versions | read-only |
| `safe` | passive **+** open-redirect, IDOR, LFI/XXE surface, race hints, cache-poison, nuclei | non-destructive probes |
| `aggressive` | **all** modules + SSTI/prototype-pollution injection + active SSRF OOB (implies `--active`) | intrusive |

Individual `--<module>` flags still work and can be combined with any profile.

---

## Key Flags

| Flag | Purpose |
|------|---------|
| `--profile passive\|safe\|aggressive` | module bundle + safety posture |
| `--active` | allow intrusive out-of-band probes |
| `--threads N` / `--rate R` / `--retries N` / `--timeout S` | concurrency, global req/s cap, retry/backoff |
| `--ssrf-callback URL` | OOB listener for active SSRF (needs `--active`) |
| `--ai-triage` / `--ai-plan` | 3-phase AI triage / attack plan over findings |
| `--ai-provider auto\|ollama\|groq\|anthropic` / `--ai-model` / `--ai-min-sev` | AI backend + scope |
| `--html` / `--json` / `--sarif` | extra report formats (Markdown always written; SARIF 2.1.0 for CI) |
| `--access-bypass` / `--tls-downgrade` | unauthenticated: 401/403 path-norm + header-spoof bypass; https→http downgrade detection |
| `--xss` | reflected-XSS surface: canary + metachar reflection matrix, context-classified (HTTP-only lead) |
| `--full` | enable every module (read-only + active) |

Run `python3 bounty_recon.py --help` for the complete list.

---

## Module Reference (highlights)

Subdomain enum (crt.sh/HackerTarget/AlienVault/Anubis/RapidDNS/SecurityTrails) ·
DNS + dangling-CNAME takeover (22 services) · live-host + tech fingerprint ·
80+ sensitive-path sweep with soft-404 filter · security headers + CSP analysis ·
TLS (expiry, TLS 1.0/1.1, weak ciphers) · **CORS bypass matrix** · exposures
(.git, source maps, JWKS) · GraphQL audit · WAF fingerprint · SSRF · open redirect ·
SSTI · prototype pollution · race hints · IDOR · LFI/XXE surface · **cache poisoning** ·
**outdated-JS-lib (retire.js-lite)** · entropy-gated JS secret scan · JWT audit ·
Wayback + param mining · IDN homoglyph · CVE fingerprints · nuclei wrapper (OAST on) ·
Dalfox/nuclei import · **AI 3-phase triage** · **AI attack plan**.

---

## AI Triage

`--ai-triage` runs a 3-phase review (worth pursuing? → reproduce → CVSS severity &
report) on each in-memory finding at or above `--ai-min-sev`, then writes the
confirmed set into the Markdown/JSON/HTML report. Providers, in auto-detect order:

```bash
# Local & free
brew install ollama && ollama pull llama3.2 && ollama serve
# Groq
export GROQ_API_KEY=gsk_...
# Anthropic (override model with ANTHROPIC_MODEL, default claude-sonnet-5-5)
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Recommended External Tool Stack

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

Pair with Burp Suite / Caido for manual testing and `interactsh-client` for OOB.

For the **full stack** (ProjectDiscovery + tomnomnom + per-class exploit tools,
~400 tools by category) and a one-shot installer, see **[`TOOLS.md`](./TOOLS.md)**.
For payloads, modern oneliners and the technique radar, see **[`ARSENAL.md`](./ARSENAL.md)**.

---

*All tools and payloads are for authorized security testing only.
Unauthorized use against systems you don't own is illegal.*
