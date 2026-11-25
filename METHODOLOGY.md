# 🗺️ Methodology & Framework Mapping

A professional engagement maps every action and every finding to a recognized
framework. Triagers trust reports that speak this language, and it keeps your
own coverage honest. This page maps the phases and the scanner's modules to
**MITRE ATT&CK**, **OWASP Top 10 (2021)**, **OWASP WSTG**, **PTES**, and
**NIST SP 800-115**.

> `bounty_recon.py` now tags every finding automatically (`🗺` line in the
> terminal, framework chips in the HTML report, a `**Framework:**` line in
> Markdown). This doc is the human reference behind those tags.
>
> *Framework mapping inspired by [BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon)'s
> red-team recon methodology (Apache-2.0). MITRE ATT&CK, OWASP Top 10 and OWASP
> WSTG are public standards.*

---

## The 5 phases (PTES / NIST, aligned)

| # | Phase | PTES | NIST SP 800-115 | This repo |
|---|-------|------|-----------------|-----------|
| 1 | Scope & plan | Pre-engagement | Planning | `scope.md`, bbscope, program policy |
| 2 | Recon | Intelligence Gathering | Information Gathering | `--profile passive` |
| 3 | Vuln analysis | Threat / Vuln Modeling | Vulnerability Analysis | `--profile safe` + `--ai-triage` |
| 4 | Exploitation | Exploitation | Exploitation | manual + `--profile aggressive` |
| 5 | Report | Reporting | Post-Testing | Markdown / HTML / `report_templates/` |

---

## Phase 2 — Reconnaissance → MITRE ATT&CK (TA0043)

| Technique | Name | How we / you do it |
|---|---|---|
| T1595.001 | Scanning IP Blocks | naabu, masscan, nmap on resolved ranges |
| T1595.002 | Vulnerability Scanning | nuclei, CVE fingerprints, `--cve` |
| T1595.003 | Wordlist Scanning | ffuf, feroxbuster, endpoint sweep |
| T1592 | Gather Victim Host Info | httpx tech-detect, `deep_fingerprint_tech` |
| T1590 | Gather Victim Network Info | DNS, ASN (asnmap), WAF fingerprint |
| T1593 | Search Open Websites/Domains | crt.sh, GitHub search, Google dorks |
| T1594 | Search Victim-Owned Websites | katana/gau crawl, JS analysis |
| T1596 | Search Open Technical Databases | Shodan, Censys, Chaos, CT logs |

**Always resolve before probing.** Pipe subdomains through `puredns`/`dnsx`
before `httpx` so dead names don't become phantom "live hosts" — a classic
source of false positives.

---

## Finding categories → framework tags

This is the exact table the scanner uses to tag findings.

| Category | MITRE ATT&CK | OWASP Top 10 (2021) | OWASP WSTG |
|---|---|---|---|
| SSRF | T1190 Exploit Public-Facing App | A10 SSRF | WSTG-INPV-19 |
| IDOR | T1190 | A01 Broken Access Control | WSTG-ATHZ-04 |
| XSS | T1059 Command & Scripting | A03 Injection | WSTG-CLNT-01 |
| SSTI | T1190 | A03 Injection | WSTG-INPV-18 |
| SQLi | T1190 | A03 Injection | WSTG-INPV-05 |
| LFI / traversal | T1083 File & Directory Discovery | A01 Broken Access Control | WSTG-ATHZ-01 |
| XXE | T1190 | A05 Security Misconfig | WSTG-INPV-07 |
| Open redirect | T1190 | A01 Broken Access Control | WSTG-CLNT-04 |
| CORS | T1190 | A05 Security Misconfig | WSTG-CLNT-07 |
| Missing headers | — | A05 Security Misconfig | WSTG-CONF-01 |
| CVE fingerprint | T1595.002 Vulnerability Scanning | A06 Vulnerable Components | WSTG-INFO-09 |
| Outdated JS lib | T1595.002 | A06 Vulnerable Components | WSTG-INFO-09 |
| Cache poisoning | T1190 | A05 Security Misconfig | WSTG-INPV-19 |
| GraphQL | T1190 | API8:2023 Security Misconfig | WSTG-APIT-01 |
| JWT | T1550 Use Alternate Auth Material | A07 Auth Failures | WSTG-SESS-01 |
| Subdomain takeover | T1584.001 Compromise Domains | A05 Security Misconfig | WSTG-CONF-10 |
| S3 / bucket | T1530 Data from Cloud Storage | A05 Security Misconfig | WSTG-CONF-11 |
| Exposure (.git/.env) | T1592 Gather Victim Host Info | A05 Security Misconfig | WSTG-CONF-04 |
| TLS weakness | — | A02 Cryptographic Failures | WSTG-CRYP-01 |
| Cookie flags | T1539 Steal Web Session Cookie | A07 Auth Failures | WSTG-SESS-02 |
| Prototype pollution | T1059 | A03 Injection | WSTG-INPV-11 |
| Race condition | T1190 | A04 Insecure Design | WSTG-BUSL-13 |
| JS secrets | T1552 Unsecured Credentials | A05 Security Misconfig | WSTG-CONF-04 |

---

## OWASP WSTG — Information Gathering checklist (Phase 2)

Run through these on every target; the scanner automates most of them.

- [ ] **WSTG-INFO-01** Search-engine discovery (Google dorks, cached pages)
- [ ] **WSTG-INFO-02** Fingerprint web server (banners, headers) — *automated*
- [ ] **WSTG-INFO-03** Review metafiles (`robots.txt`, `sitemap.xml`, `security.txt`) — *automated*
- [ ] **WSTG-INFO-04** Enumerate applications (vhosts, non-standard ports)
- [ ] **WSTG-INFO-05** Review webpage content (comments, metadata, JS) — *partly automated*
- [ ] **WSTG-INFO-06** Identify entry points (params, headers, POST bodies) — *param mining*
- [ ] **WSTG-INFO-07** Map execution paths (app flow, state)
- [ ] **WSTG-INFO-08** Fingerprint framework — *automated*
- [ ] **WSTG-INFO-09** Fingerprint web application / version — *automated (CVE fingerprints)*
- [ ] **WSTG-INFO-10** Map application architecture (LB, WAF, proxy) — *WAF fingerprint*
- [ ] **WSTG-APIT-01** API recon (OpenAPI/Swagger discovery, endpoint enum) — *GraphQL/JS endpoints*

---

*For the full hunting playbook see [`ARSENAL.md`](./ARSENAL.md); for the tool
catalog see [`TOOLS.md`](./TOOLS.md). Authorized targets only.*
