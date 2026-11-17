# Bug Bounty Methodology 2026
*Based on: XSS-Rat 2026 Guide + OWASP API Top 10 2023 + personal additions*

---

## Phase 1 — Reconnaissance

### Passive
- [ ] crt.sh subdomain enumeration: `crt.sh/?q=%.domain.com&output=json`
- [ ] AlienVault OTX passive DNS
- [ ] Wayback Machine parameterised URL extraction
- [ ] GitHub dork: `org:company "api_key"`, `"password"`, `"secret"`
- [ ] Google dork: `site:domain.com filetype:env`, `site:domain.com inurl:config`
- [ ] Shodan / Censys / FOFA for exposed services
- [ ] cert transparency logs (crtsh, certspotter, facebook CT)
- [ ] ASN / IP range mapping via RIPE / ARIN
- [ ] Check for IDN lookalike domains

### Active
- [ ] subfinder + amass passive → deduplicate
- [ ] httpx for live host + tech detection
- [ ] nuclei -tags misconfig,exposure on all live hosts
- [ ] Crawl with Playwright for dynamic endpoints
- [ ] JavaScript file analysis (LinkFinder, JSScanner)
- [ ] `gau + waybackurls` → parameterised URL wordlist
- [ ] ffuf / feroxbuster directory brute-force on interesting hosts

---

## Phase 2 — Mapping

### Technology Fingerprinting
- [ ] Server headers (Server, X-Powered-By, X-Generator)
- [ ] Framework detection (Next.js build manifest, React, Vue, Angular)
- [ ] CDN detection (Cloudflare, Akamai, Fastly, CloudFront)
- [ ] Auth library (Auth.js, Passport, Devise, Flask-Login)
- [ ] Payment provider (Stripe, Braintree, Square)

### API Discovery
- [ ] `/openapi.json`, `/swagger.json`, `/api-docs`
- [ ] GraphQL introspection at `/graphql`, `/graph`, `/api/graphql`
- [ ] Next.js `_buildManifest.js` for all routes
- [ ] JS bundle analysis for hardcoded API paths
- [ ] Wayback + gau parameter name mining

---

## Phase 3 — Vulnerability Testing

### Authentication & Session
- [ ] Default credentials on admin panels
- [ ] Username enumeration (login, password reset, registration)
- [ ] Password reset: predictable token? host header injection? CRLF?
- [ ] MFA bypass: response manipulation, code reuse, backup codes
- [ ] Session fixation / session not invalidated on logout
- [ ] Cookie flags: Secure, HttpOnly, SameSite, __Host- prefix
- [ ] JWT: alg:none, algorithm confusion (RS256→HS256), weak secret
- [ ] OAuth: missing state → CSRF, redirect_uri open redirect, PKCE absent

### Access Control
- [ ] IDOR: change numeric/UUID object ID in API calls across two accounts
- [ ] Mass assignment: add `role`, `admin`, `is_admin` to POST body
- [ ] Broken function-level auth: access admin endpoints with low-priv token
- [ ] BOLA/BFLA (OWASP API1/5): test all HTTP methods on every endpoint
- [ ] Path traversal to other tenant's resources

### Injection
- [ ] SQLi: all input fields, headers (User-Agent, Referer, X-Forwarded-For), cookies
- [ ] NoSQL: `{$ne: null}`, `{$gt: ""}` in JSON body
- [ ] XSS: reflected, stored, DOM. Test: `<svg onload=alert(1)>`, `{{7*7}}`
- [ ] SSTI: `{{7*7}}`, `${7*7}` — if returns 49, engine is injectable
- [ ] Command injection: `;id`, `|id`, `&&id`, `$(id)`, `\`id\``
- [ ] XXE: XML/SVG/DOCX file uploads + API endpoints accepting XML
- [ ] SSRF: `url=`, `src=`, `redirect=`, `webhook=` params → 169.254.169.254
- [ ] LFI: `file=`, `page=`, `path=`, `include=` params → `../etc/passwd`
- [ ] Prototype Pollution: `?__proto__[admin]=true`
- [ ] CRLF injection: `%0d%0aHeader: value` in URL/redirect params

### Logic & Business
- [ ] Negative price / quantity in cart
- [ ] Skip payment step entirely
- [ ] Coupon race condition (use same coupon twice in parallel)
- [ ] Transfer to self (self-credit)
- [ ] Referral self-abuse
- [ ] Limit bypass (file upload size, API rate limit, free tier)
- [ ] Vote manipulation (downvote to negative / unlimited upvotes)
- [ ] Workflow skip (step 2 of 3 without completing step 1)

### Modern / 2026 Surfaces
- [ ] GraphQL: introspection, batching, alias amplification, mutation auth
- [ ] WebSocket: CSWSH, auth not enforced on WS upgrades
- [ ] gRPC / Protobuf: deserialize unknown fields
- [ ] WASM modules: memory corruption in Rust/C++ compiled to WASM
- [ ] AI/LLM: prompt injection via user-controlled context, indirect injection in RAG
- [ ] Service mesh: mTLS misconfiguration, SPIFFE SVID bypass

---

## Phase 4 — Exploitation Chains

### High-value chains
1. **XSS → ATO**: stored XSS + steal session or chain CSRF to email change
2. **SSRF → Cloud Creds**: SSRF to 169.254.169.254 → IAM role creds → S3/RDS access
3. **IDOR → Account Takeover**: access `/api/users/{other_id}` → change email → reset password
4. **Open Redirect → Phishing**: `redirect=https://evil.com` in OAuth flow → credential harvest
5. **SQLi → File Read → RCE**: LOAD_FILE → into outfile → RCE via webshell
6. **JWT algorithm confusion**: RS256 public key → sign as HS256 → admin token

---

## Phase 5 — Reporting

### Severity Guide (HackerOne / Bugcrowd)
| Impact | Access level | Severity |
|--------|-------------|----------|
| RCE, auth bypass to admin | Full server | Critical |
| SQLi with data exfil, Account Takeover | All user data | High |
| SSRF to internal, stored XSS on admin | Partial data | Medium |
| Self-XSS, info disclosure of non-sensitive data | Current user only | Low |
| Missing headers, version disclosure | None | Informational |

### Report structure
1. **Title**: `[Component] Vuln Type leads to Impact`
2. **Severity + CVSS**
3. **Summary** (2 sentences)
4. **Steps to reproduce** (numbered, copy-paste ready)
5. **PoC** (video or screenshot)
6. **Impact** (what an attacker gains)
7. **Suggested fix**
