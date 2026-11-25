# Bounty Recon Report — adjarabetarena.com

| | |
|---|---|
| **Generated** | 2026-11-25T15:44:51Z |
| **Tool** | bounty_recon.py v4.0.0 |
| **Vantage** | Open internet, no proxy, read-only |

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 **Critical** | 0 |
| 🟠 **High** | 7 |
| 🟡 **Medium** | 8 |
| 🔵 **Low** | 28 |
| ⚪ **Info** | 1 |
| ✅ Passed | 552 |

## Discovered Subdomains

- `adjarabetarena.com`
- `bms-lb.adjarabetarena.com`
- `bms.adjarabetarena.com`
- `bmsstatic.adjarabetarena.com`
- `setantasports.adjarabetarena.com`
- `www.adjarabetarena.com`

## Live Hosts

| URL | Status | Server |
|-----|--------|--------|
| `https://adjarabetarena.com` | 202 | `cloudflare` |
| `https://bms.adjarabetarena.com` | 200 | `cloudflare` |
| `https://www.adjarabetarena.com` | 202 | `cloudflare` |
| `https://bms-lb.adjarabetarena.com` | 403 | `cloudflare` |
| `https://setantasports.adjarabetarena.com` | 525 | `cloudflare` |
| `https://bmsstatic.adjarabetarena.com` | 403 | `cloudflare` |

## Technologies Detected

- `adjarabetarena.com`: Cloudflare CDN & WAF, Server: cloudflare
- `bms.adjarabetarena.com`: Cloudflare CDN & WAF, Server: cloudflare
- `www.adjarabetarena.com`: Cloudflare CDN & WAF, Server: cloudflare
- `bms-lb.adjarabetarena.com`: Cloudflare CDN & WAF, Server: cloudflare
- `setantasports.adjarabetarena.com`: Cloudflare CDN & WAF, Server: cloudflare
- `bmsstatic.adjarabetarena.com`: Cloudflare CDN & WAF, Server: cloudflare

## Findings

### 1. 🟠 [High] Sensitive endpoint: metrics

**Severity:** High  
**Target:** `https://bms.adjarabetarena.com/metrics`  
**Category:** `exposure`  
**Tool:** `bounty_recon`  
**Evidence:**
```
HTTP 200 | text/plain; charset=utf-8; version=0.0.4 | # HELP process_cpu_user_seconds_total Total user CPU time spent in seconds. # TYPE process_cpu_user_
```
**Reproduce:**
```bash
curl -si --noproxy "*" "https://bms.adjarabetarena.com/metrics"
```
**Remediation:** Restrict to internal or add auth

### 2. 🟠 [High] Sensitive endpoint: robots.txt

**Severity:** High  
**Target:** `https://bms.adjarabetarena.com/robots.txt`  
**Category:** `exposure`  
**Tool:** `bounty_recon`  
**Evidence:**
```
HTTP 200 | text/plain; charset=utf-8 | User-agent: * Disallow: /
```
**Reproduce:**
```bash
curl -si --noproxy "*" "https://bms.adjarabetarena.com/robots.txt"
```
**Remediation:** Restrict to internal or add auth

### 3. 🟠 [High] Header: content-security-policy

**Severity:** High  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'content-security-policy' missing | Impact: CSP missing — XSS risk increased
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 4. 🟠 [High] Header: content-security-policy

**Severity:** High  
**Target:** `https://bms-lb.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'content-security-policy' missing | Impact: CSP missing — XSS risk increased
```
**Reproduce:**
```bash
curl -sI "https://bms-lb.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 5. 🟠 [High] Header: content-security-policy

**Severity:** High  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'content-security-policy' missing | Impact: CSP missing — XSS risk increased
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 6. 🟠 [High] Header: content-security-policy

**Severity:** High  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'content-security-policy' missing | Impact: CSP missing — XSS risk increased
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 7. 🟠 [High] Header: content-security-policy

**Severity:** High  
**Target:** `https://setantasports.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'content-security-policy' missing | Impact: CSP missing — XSS risk increased
```
**Reproduce:**
```bash
curl -sI "https://setantasports.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 8. 🟡 [Medium] Header: x-frame-options

**Severity:** Medium  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-frame-options' missing | Impact: Clickjacking possible
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 9. 🟡 [Medium] Header: strict-transport-security

**Severity:** Medium  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'strict-transport-security' missing | Impact: HSTS missing — MITM risk
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 10. 🟡 [Medium] Header: strict-transport-security

**Severity:** Medium  
**Target:** `https://bms-lb.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'strict-transport-security' missing | Impact: HSTS missing — MITM risk
```
**Reproduce:**
```bash
curl -sI "https://bms-lb.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 11. 🟡 [Medium] Header: x-frame-options

**Severity:** Medium  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-frame-options' missing | Impact: Clickjacking possible
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 12. 🟡 [Medium] Header: strict-transport-security

**Severity:** Medium  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'strict-transport-security' missing | Impact: HSTS missing — MITM risk
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 13. 🟡 [Medium] Header: x-frame-options

**Severity:** Medium  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-frame-options' missing | Impact: Clickjacking possible
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 14. 🟡 [Medium] Header: strict-transport-security

**Severity:** Medium  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'strict-transport-security' missing | Impact: HSTS missing — MITM risk
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 15. 🟡 [Medium] Header: strict-transport-security

**Severity:** Medium  
**Target:** `https://setantasports.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'strict-transport-security' missing | Impact: HSTS missing — MITM risk
```
**Reproduce:**
```bash
curl -sI "https://setantasports.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 16. 🔵 [Low] Header: x-content-type-options

**Severity:** Low  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-content-type-options' missing | Impact: MIME-type sniffing enabled
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 17. 🔵 [Low] Header: permissions-policy

**Severity:** Low  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'permissions-policy' missing | Impact: Browser feature policy not set
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 18. 🔵 [Low] Header: referrer-policy

**Severity:** Low  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'referrer-policy' missing | Impact: Referrer data may leak to third parties
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 19. 🔵 [Low] Header: cross-origin-opener-policy

**Severity:** Low  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-opener-policy' missing | Impact: COOP missing
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 20. 🔵 [Low] Header: cross-origin-embedder-policy

**Severity:** Low  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-embedder-policy' missing | Impact: COEP missing
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 21. 🔵 [Low] Header: cross-origin-resource-policy

**Severity:** Low  
**Target:** `https://bms.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-resource-policy' missing | Impact: CORP missing
```
**Reproduce:**
```bash
curl -sI "https://bms.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 22. 🔵 [Low] Header: x-content-type-options

**Severity:** Low  
**Target:** `https://bms-lb.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-content-type-options' missing | Impact: MIME-type sniffing enabled
```
**Reproduce:**
```bash
curl -sI "https://bms-lb.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 23. 🔵 [Low] Header: permissions-policy

**Severity:** Low  
**Target:** `https://bms-lb.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'permissions-policy' missing | Impact: Browser feature policy not set
```
**Reproduce:**
```bash
curl -sI "https://bms-lb.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 24. 🔵 [Low] Header: cross-origin-opener-policy

**Severity:** Low  
**Target:** `https://bms-lb.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-opener-policy' missing | Impact: COOP missing
```
**Reproduce:**
```bash
curl -sI "https://bms-lb.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 25. 🔵 [Low] Header: cross-origin-embedder-policy

**Severity:** Low  
**Target:** `https://bms-lb.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-embedder-policy' missing | Impact: COEP missing
```
**Reproduce:**
```bash
curl -sI "https://bms-lb.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 26. 🔵 [Low] Header: cross-origin-resource-policy

**Severity:** Low  
**Target:** `https://bms-lb.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-resource-policy' missing | Impact: CORP missing
```
**Reproduce:**
```bash
curl -sI "https://bms-lb.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 27. 🔵 [Low] Header: x-content-type-options

**Severity:** Low  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-content-type-options' missing | Impact: MIME-type sniffing enabled
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 28. 🔵 [Low] Header: permissions-policy

**Severity:** Low  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'permissions-policy' missing | Impact: Browser feature policy not set
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 29. 🔵 [Low] Header: referrer-policy

**Severity:** Low  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'referrer-policy' missing | Impact: Referrer data may leak to third parties
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 30. 🔵 [Low] Header: cross-origin-opener-policy

**Severity:** Low  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-opener-policy' missing | Impact: COOP missing
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 31. 🔵 [Low] Header: cross-origin-embedder-policy

**Severity:** Low  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-embedder-policy' missing | Impact: COEP missing
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 32. 🔵 [Low] Header: cross-origin-resource-policy

**Severity:** Low  
**Target:** `https://bmsstatic.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-resource-policy' missing | Impact: CORP missing
```
**Reproduce:**
```bash
curl -sI "https://bmsstatic.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 33. 🔵 [Low] Header: x-content-type-options

**Severity:** Low  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-content-type-options' missing | Impact: MIME-type sniffing enabled
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 34. 🔵 [Low] Header: permissions-policy

**Severity:** Low  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'permissions-policy' missing | Impact: Browser feature policy not set
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 35. 🔵 [Low] Header: referrer-policy

**Severity:** Low  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'referrer-policy' missing | Impact: Referrer data may leak to third parties
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 36. 🔵 [Low] Header: cross-origin-opener-policy

**Severity:** Low  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-opener-policy' missing | Impact: COOP missing
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 37. 🔵 [Low] Header: cross-origin-embedder-policy

**Severity:** Low  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-embedder-policy' missing | Impact: COEP missing
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 38. 🔵 [Low] Header: cross-origin-resource-policy

**Severity:** Low  
**Target:** `https://www.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-resource-policy' missing | Impact: CORP missing
```
**Reproduce:**
```bash
curl -sI "https://www.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 39. 🔵 [Low] Header: x-content-type-options

**Severity:** Low  
**Target:** `https://setantasports.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'x-content-type-options' missing | Impact: MIME-type sniffing enabled
```
**Reproduce:**
```bash
curl -sI "https://setantasports.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 40. 🔵 [Low] Header: permissions-policy

**Severity:** Low  
**Target:** `https://setantasports.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'permissions-policy' missing | Impact: Browser feature policy not set
```
**Reproduce:**
```bash
curl -sI "https://setantasports.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 41. 🔵 [Low] Header: cross-origin-opener-policy

**Severity:** Low  
**Target:** `https://setantasports.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-opener-policy' missing | Impact: COOP missing
```
**Reproduce:**
```bash
curl -sI "https://setantasports.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 42. 🔵 [Low] Header: cross-origin-embedder-policy

**Severity:** Low  
**Target:** `https://setantasports.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-embedder-policy' missing | Impact: COEP missing
```
**Reproduce:**
```bash
curl -sI "https://setantasports.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 43. 🔵 [Low] Header: cross-origin-resource-policy

**Severity:** Low  
**Target:** `https://setantasports.adjarabetarena.com`  
**Category:** `headers`  
**Tool:** `bounty_recon`  
**Evidence:**
```
Header 'cross-origin-resource-policy' missing | Impact: CORP missing
```
**Reproduce:**
```bash
curl -sI "https://setantasports.adjarabetarena.com"
```
**Remediation:** Add via Cloudflare Transform Rule or web server config

### 44. ⚪ [Info] DNS: CAA record not configured

**Severity:** Info  
**Target:** `dns://adjarabetarena.com`  
**Category:** `dns-sec`  
**Tool:** `bounty_recon`  
**Evidence:**
```
No CAA records
```
**Reproduce:**
```bash
dig +short CAA adjarabetarena.com
```
**Remediation:** Configure CAA records

## Passed Checks

```
https://bms.adjarabetarena.com/.env → 404
https://bms.adjarabetarena.com/.env.production → 404
https://bms.adjarabetarena.com/config.yaml → 404
https://bms.adjarabetarena.com/.git/HEAD → 404
https://bms.adjarabetarena.com/.env.dev → 404
https://bms.adjarabetarena.com/.git/COMMIT_EDITMSG → 404
https://bms.adjarabetarena.com/settings.json → 404
https://bms.adjarabetarena.com/.env.staging → 404
https://bms.adjarabetarena.com/.git/config → 404
https://bms.adjarabetarena.com/.git/logs/HEAD → 404
https://bms.adjarabetarena.com/backup.sql → 404
https://bms.adjarabetarena.com/.git/index → 404
https://bms.adjarabetarena.com/db.sqlite → 404
https://bms.adjarabetarena.com/database.sqlite → 404
https://bms.adjarabetarena.com/app.json → 404
https://bms.adjarabetarena.com/config.json → 404
https://bms.adjarabetarena.com/dump.sql → 404
https://bms.adjarabetarena.com/app.config.js → 404
https://bms.adjarabetarena.com/app.js.map → 404
https://bms.adjarabetarena.com/vendor.js.map → 404
https://bms.adjarabetarena.com/db_backup.sql → 404
https://bms.adjarabetarena.com/static/js/main.chunk.js.map → 404
https://bms.adjarabetarena.com/main.js.map → 404
https://bms.adjarabetarena.com/static/js/bundle.js.map → 404
https://bms.adjarabetarena.com/bundle.js.map → 404
https://bms.adjarabetarena.com/.well-known/jwks.json → 404
https://bms.adjarabetarena.com/api/v1/env → 404
https://bms.adjarabetarena.com/api/v1/ready → 404
https://bms.adjarabetarena.com/.well-known/openid-configuration → 404
https://bms.adjarabetarena.com/.well-known/change-password → 404
https://bms.adjarabetarena.com/api/v1/config → 404
https://bms.adjarabetarena.com/.well-known/security.txt → 404
https://bms.adjarabetarena.com/api/v1/health → 404
https://bms.adjarabetarena.com/api/v1/debug → 404
https://bms.adjarabetarena.com/api/v1/metrics → 404
https://bms.adjarabetarena.com/api/v1/stream/demo → 404
https://bms.adjarabetarena.com/api/v1/users → 404
https://bms.adjarabetarena.com/api/v1/admin → 404
https://bms.adjarabetarena.com/api/v1/info → 404
https://bms.adjarabetarena.com/api/v2/health → 404
https://bms.adjarabetarena.com/api/v2/users → 404
https://bms.adjarabetarena.com/api/v1/version → 404
https://bms.adjarabetarena.com/api/debug → 404
https://bms.adjarabetarena.com/api/health → 404
https://bms.adjarabetarena.com/api/v2/admin → 404
https://bms.adjarabetarena.com/api/users → 404
https://bms.adjarabetarena.com/api/admin → 404
https://bms.adjarabetarena.com/health → 404
https://bms.adjarabetarena.com/ping → 404
https://bms.adjarabetarena.com/ready → 404
https://bms.adjarabetarena.com/api/status → 404
https://bms.adjarabetarena.com/debug/pprof → 404
https://bms.adjarabetarena.com/debug/vars → 404
https://bms.adjarabetarena.com/prometheus → 404
https://bms.adjarabetarena.com/docs → 404
https://bms.adjarabetarena.com/version → 404
https://bms.adjarabetarena.com/openapi.json → 404
https://bms.adjarabetarena.com/swagger → 404
https://bms.adjarabetarena.com/swagger.json → 404
https://bms.adjarabetarena.com/api-docs → 404
https://bms.adjarabetarena.com/status → 404
https://bms.adjarabetarena.com/swagger-ui.html → 404
https://bms.adjarabetarena.com/backup.zip → 404
https://bms.adjarabetarena.com/redoc → 404
https://bms.adjarabetarena.com/admin/login → 404
https://bms.adjarabetarena.com/admin → 404
https://bms.adjarabetarena.com/graphiql → 404
https://bms.adjarabetarena.com/graphql → 404
https://bms.adjarabetarena.com/graph → 404
https://bms.adjarabetarena.com/admin/dashboard → 404
https://bms.adjarabetarena.com/_metrics → 404
https://bms.adjarabetarena.com/adminer.php → 404
https://bms.adjarabetarena.com/_admin → 404
https://bms.adjarabetarena.com/rest/settings → 404
https://bms.adjarabetarena.com/wp-login.php → 404
https://bms.adjarabetarena.com/phpmyadmin → 404
https://bms.adjarabetarena.com/wp-admin → 404
https://bms.adjarabetarena.com/rest/license → 404
https://bms.adjarabetarena.com/_debug → 404
https://bms.adjarabetarena.com/rest/users → 404
```

---
*bounty_recon.py v4.0.0 — read-only passive scanner — use on authorised targets only*