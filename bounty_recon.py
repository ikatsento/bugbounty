#!/usr/bin/env python3
"""
bounty_recon.py — Bug Bounty Passive Recon & Misconfiguration Scanner
======================================================================
Version : 3.0.0
License : MIT

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
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
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
VERSION  = "3.0.0"
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

# ── Security headers ──────────────────────────────────────────────────────────
REQUIRED_HEADERS = {
    "content-security-policy":       ("High",   "CSP missing — XSS risk increased"),
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
    "address","target","data","uri","remote","uri","ref","location","continue",
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
    "folder","root","src","resource","path","dir","layout","conf","config",
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
    summary:       dict = field(default_factory=dict)

# ── HTTP helper ───────────────────────────────────────────────────────────────
def http_get(url: str, headers: dict = None, follow: bool = True, timeout: int = TIMEOUT,
             method: str = "GET", body: str = None):
    h = dict(BROWSER_HEADERS)
    if headers:
        h.update(headers)
    if HAS_HTTPX:
        try:
            if method == "POST":
                r = httpx.post(url, headers=h, timeout=timeout, follow_redirects=follow,
                               verify=True, content=body)
            else:
                r = httpx.get(url, headers=h, timeout=timeout, follow_redirects=follow, verify=True)
            return r.status_code, dict(r.headers), r.content
        except Exception as e:
            raise ConnectionError(str(e))
    else:
        import urllib.request as ur, urllib.error as ue, ssl as _ssl
        ctx = _ssl.create_default_context()
        req = ur.Request(url, headers=h, data=body.encode() if body else None, method=method)
        try:
            with ur.urlopen(req, context=ctx, timeout=timeout) as resp:
                body_r = resp.read()
                hdrs = {k.lower(): v for k,v in resp.headers.items()}
                return resp.status, hdrs, body_r
        except ue.HTTPError as e:
            body_r = b""
            try: body_r = e.read()
            except: pass
            hdrs = {k.lower(): v for k,v in e.headers.items()} if e.headers else {}
            return e.code, hdrs, body_r
        except Exception as e:
            raise ConnectionError(str(e))

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

        # Active OOB probe (only if callback provided)
        if ssrf_callback:
            parsed = urlparse(base_url)
            for param in list(SSRF_PARAMS)[:8]:
                probe_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={ssrf_callback}"
                try:
                    http_get(probe_url, timeout=5, follow=False)
                    # If we get here without error, probe was sent
                    findings.append({
                        "severity": "High",
                        "category": "ssrf",
                        "title": f"SSRF OOB probe sent via parameter '{param}'",
                        "url": probe_url,
                        "evidence": f"Request sent to {ssrf_callback} via ?{param}= — check your callback listener",
                        "command": f'curl -si "{probe_url}"',
                        "remediation": "Confirm hit in interactsh/Collaborator. Restrict server-side URL fetching.",
                    })
                    break  # one probe per URL is enough
                except Exception:
                    pass

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
    """
    Inject SSTI canary payloads into discovered parameters.
    Look for arithmetic result (49) reflected in response.
    """
    findings = []

    try:
        status, hdrs, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8","replace")

        # Find query params on page
        param_names = set()
        for m in re.finditer(r'[?&]([a-zA-Z0-9_\-]{2,20})=', text):
            param_names.add(m.group(1))

        if not param_names:
            return findings

        for param in list(param_names)[:5]:
            for payload, expected, engine in SSTI_CANARIES:
                probe = f"{base_url}{'&' if '?' in base_url else '?'}{param}={payload}"
                try:
                    st, _, b = http_get(probe, timeout=6)
                    response_text = b.decode("utf-8","replace")
                    if expected in response_text and payload not in response_text:
                        findings.append({
                            "severity": "High",
                            "category": "ssti",
                            "title": f"SSTI confirmed in parameter '{param}' ({engine})",
                            "url": probe,
                            "evidence": f"Payload {payload!r} → response contains '{expected}' (engine: {engine})",
                            "command": f'curl -s "{probe}"',
                            "remediation": "Never pass user input to template rendering engines. Use template sandboxing (tplmap for exploitation).",
                        })
                        break  # confirmed, skip other canaries for this param
                except Exception:
                    pass

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

def resolve_dns(hosts: list) -> dict:
    records = {}
    for host in hosts:
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
        records[host] = rec
    return records

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

def check_live(hosts: list) -> list:
    live = []
    for host in hosts:
        for scheme in ("https","http"):
            url = f"{scheme}://{host}"
            try:
                status, hdrs, body = http_get(url, follow=True, timeout=8)
                h = norm_headers(hdrs)
                live.append({"host":host,"url":url,"status":status,"server":h.get("server",""),"powered_by":h.get("x-powered-by",""),"redirect":h.get("location","")})
                break
            except Exception: continue
    return live

def sweep_endpoints(base_url: str) -> tuple:
    findings, passed = [], []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            status, hdrs, body = http_get(url, follow=False, timeout=8)
            h = norm_headers(hdrs); ct = h.get("content-type","")
            if status == 200 and not is_html(ct, body):
                body_text = body[:300].decode("utf-8","replace")
                if len(body_text.strip()) < 5: continue
                if path.startswith("/.git/HEAD") and not body_text.startswith("ref:"): continue
                if path.startswith("/.git/config") and "[core]" not in body_text: continue
                if path.startswith("/.env") and ("=" not in body_text or "{" in body_text[:50]): continue
                findings.append({"url":url,"status":status,"content_type":ct,"snippet":body_text.replace("\n"," ").strip()[:180],"command":f'curl -si --noproxy "*" "{url}"'})
            elif status in (401,403):
                is_waf, _ = is_waf_challenge(status, hdrs, body)
                passed.append(f"{url} → {status}" + (" (WAF block)" if is_waf else " (auth/blocked)"))
            else:
                passed.append(f"{url} → {status}")
        except Exception:
            passed.append(f"{url} → error")
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
                sample = matches[0][:60]
            if name == "JWT Token":
                for token_match in matches[:3]:
                    for jf in audit_jwt_token(token_match, js_url):
                        secrets.append({
                            "severity":jf["severity"],"type":jf.get("type","jwt"),
                            "url":js_url,"detail":jf.get("title","JWT issue"),
                            "sample":token_match[:40]+"...","command":jf.get("command",""),
                            "remediation":jf.get("remediation","Rotate token")
                        })
            secrets.append({"severity":"Critical" if name not in ("JWT Token","Firebase URL","Internal IP") else "Low",
                "type":name,"url":js_url,"detail":f"{len(matches)} match(es) of '{name}'","sample":sample,
                "command":f'curl -s "{js_url}" | grep -Eo "{pattern[:40]}"',
                "remediation":"Rotate secret; remove from client-side code"})
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
    cmd = [nuclei_path, "-u", target,"-tags","misconfig,exposure,config,headers,ssl,file,token,generic",
           "-severity","critical,high,medium,info","-jsonl","-o",str(out_file),"-silent","-no-interactsh","-rl","50","-c","10"]
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

def check_cve_fingerprints(base_url: str) -> list:
    findings = []
    base = base_url.rstrip("/")
    for check in CVE_CHECKS:
        matched_url = matched_on = matched_body = None
        for path in check["paths"]:
            url = base + path
            try:
                status, hdrs, body = http_get(url, follow=False, timeout=8)
                h = norm_headers(hdrs)
                decoded = body[:4000].decode("utf-8", errors="replace").lower()
                header_str = " ".join(f"{k}: {v}" for k,v in h.items()).lower()
                combined = decoded + " " + header_str
                for keyword in check["match"]:
                    if keyword.lower() in combined:
                        matched_url = url; matched_on = keyword; matched_body = decoded[:200].replace("\n"," ").strip(); break
                if matched_url: break
            except Exception: continue
        if matched_url:
            findings.append({"severity":check["severity"],"category":"cve-fingerprint",
                "title":f"{check['cve']} — {check['product']}","url":matched_url,
                "evidence":f"Fingerprint: '{matched_on}' | URL: {matched_url} | Body: {matched_body[:150]}",
                "command":f'curl -si "{matched_url}"',"remediation":check["remediation"]})
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

    lines += ["## Findings",""]
    sorted_f = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.get("severity","Info"),4))
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity","Info")
        title = f.get("title") or f.get("detail") or f.get("header","") or "Finding"
        url   = f.get("url") or f.get("host","")
        lines += [f"### {i}. {SEV_EMOJI.get(sev,'')} [{sev}] {title}","",f"**Severity:** {sev}  "]
        if url: lines.append(f"**Target:** `{url}`  ")
        ev = f.get("evidence") or f.get("snippet") or f.get("detail","")
        if ev: lines += ["**Evidence:**","```",ev[:300],"```"]
        if f.get("command"): lines += ["**Reproduce:**","```bash",f["command"],"```"]
        if f.get("remediation"): lines.append(f"**Remediation:** {f['remediation']}")
        lines += [""]

    lines += ["## Passed Checks","","```"] + result.passed[:80] + ["```","",
              "---",f"*bounty_recon.py v{VERSION} — read-only passive scanner — use on authorised targets only*"]
    out_path.write_text("\n".join(lines), encoding="utf-8")

def generate_json(result: ScanResult, out_path: Path):
    out_path.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")

def print_finding(f: dict):
    sev = f.get("severity","Info"); em = SEV_EMOJI.get(sev,"⚪")
    t   = f.get("title") or f.get("detail") or f.get("header","")
    url = f.get("url") or f.get("host","")
    ev  = (f.get("evidence") or f.get("snippet") or "")[:100]
    if HAS_RICH:
        console.print(f"  {em} [bold]{sev}[/bold] {t}")
        if url: console.print(f"     [cyan]{url}[/cyan]")
        if ev:  console.print(f"     [green]{ev}[/green]")
    else:
        print(f"  {em} [{sev}] {t}")
        if url: print(f"     {url}")
        if ev:  print(f"     {ev}")

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
    ap.add_argument("--full",                 action="store_true", help="Enable ALL optional modules")
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

    # --full enables everything
    if args.full:
        args.nuclei = args.js = args.s3 = args.graphql = args.waf = True
        args.ssrf = args.open_redirect = args.ssti = args.proto_pollution = True
        args.race = args.idor = args.lfi_xxe = args.wayback = args.param_mine = True
        args.cve = args.idn = True

    domain   = args.target.replace("https://","").replace("http://","").split("/")[0]
    base_url = args.url or f"https://{domain}"
    out_dir  = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem     = args.out or f"{domain.replace('.','_')}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M')}"
    md_path  = out_dir / f"{stem}.md"
    jp       = out_dir / f"{stem}.json"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    if HAS_RICH:
        mods_on = [m for m in ["nuclei","js","s3","graphql","waf","ssrf","ssti","cve","wayback"] if getattr(args,m,False)]
        console.print(Panel(
            f"[bold cyan]bounty_recon.py[/bold cyan] v{VERSION}\n"
            f"Target  : [bold]{domain}[/bold]\n"
            f"Base URL: {base_url}\n"
            f"Modules : {', '.join(mods_on) if mods_on else 'core only'}",
            title="🔍 Bug Bounty Passive Recon v3.0"))
    else:
        print(f"\n{'='*55}\nbounty_recon.py v{VERSION} | {domain}\n{'='*55}")

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
            all_findings.append({"severity":"High","category":"exposure","title":f"Sensitive endpoint: {f['url'].split('/')[-1] or '(root)'}","url":f["url"],"command":f["command"],"evidence":f"HTTP 200 | {f['content_type']} | {f['snippet'][:100]}","remediation":"Restrict to internal or add auth"})
        all_passed.extend(ep_p)

    # 6. Security headers + cookies
    console.print("\n[bold]6. Security Headers & Cookie Audit[/bold]" if HAS_RICH else "\n6. Headers + Cookies")
    for url in scan_urls[:5]:
        hf, hp = check_headers(url)
        for f in hf:
            all_findings.append({"severity":f["severity"],"category":"headers","title":f"Header: {f['header']}","url":f.get("url",url),"command":f.get("command",""),"evidence":f.get("evidence",""),"remediation":f.get("remediation","")})
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
    test_origins = list(set(args.cors_origins + sub_origins + ["https://evil.example.com","null",f"https://attacker.{domain}"]))
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
    result.findings = all_findings
    result.passed   = all_passed
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

if __name__ == "__main__":
    main()
