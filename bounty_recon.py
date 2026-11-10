#!/usr/bin/env python3
"""
bounty_recon.py — Bug Bounty Passive Recon & Misconfiguration Scanner
======================================================================
Version : 3.0.0 — Oracle-Security/CVEs 0day Integration
License : MIT
Inspired by AutoAR (h0tak88r/AutoAR) — Python single-file edition

Modules:
  1-15. (See original)
  16. 0day & CVE Fingerprinting (Oracle-Security/CVEs + known exploits):
       - N-able N-central (Able2Shell, 33 0day + CVE-2026-86218)
       - IBM PowerVM Novalink (CVE-2026-12943 / CVE-2026-14971)
       - ConnectWise ScreenConnect (CVE-2024-1709)
       - DotNetNuke (CVE-2018-14486)
       - Parallels RAS (CVE-2023-45894)
       - QStar Archive (CVE-2023-51062…51070)
       - MOVEit Transfer (CVE-2023-34362)
       - Citrix NetScaler (CVE-2023-4966 — Citrix Bleed)
       - Apache OFBiz (CVE-2023-51467)
       - WordPress (REST user enumeration)
"""

import sys, ssl, json, socket, asyncio, datetime, subprocess, argparse, re, os, warnings, base64
from urllib.parse import urljoin, urlparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

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

# JS secret patterns
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
    "Square Access Token":   r'sq0atp-[0-9A-Za-z\-_]{22}',
    "Firebase URL":          r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Generic API Key":       r'["\']api[_-]?key["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Generic Secret":        r'["\']secret["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Password in URL":       r'https?://[a-zA-Z0-9_\-\.%]+:[^@/?#\s"\'`<>{}]{3,}@[a-zA-Z0-9_\-\.]+(?::\d+)?(?:/[^"\'`\s<>{}]*)?',
}

# Dummy filters
DUMMY_USERS = {
    "user", "username", "login", "name", "admin", "root", "test",
    "demo", "guest", "foo", "git", "john", "alice", "email", "null", "undefined", "account"
}
DUMMY_PASSWORDS = {
    "pass", "password", "secret", "admin", "root", "test", "demo",
    "guest", "bar", "baz", "123456", "changeme", "dummy", "xxx", "token", "null", "undefined", "placeholder"
}
DUMMY_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "example.com", "example.org", "example.net",
    "test.com", "test.org", "test.net", "test.local",
    "domain.com", "sample.com", "foo.com", "bar.com",
    "w3.org", "schema.org", "iana.org", "ietf.org",
    "invalid", "local", "internal", "placeholder.com",
    "your-domain.com", "yourdomain.com", "mydomain.com",
    "hostname.com", "mysite.com", "acme.com",
    "user.example", "auth.example", "api.example",
    "db.example", "redis.example", "mongo.example",
}
_DUMMY_HOST_SUBSTRINGS = (
    "example", "placeholder", "yoursite", "yourdomain",
    "localhost", "127.0.0", "acme.test", "demo.test",
)

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
        if any(m in passwd for m in ["${", "{{", "<%", "<", ">", "%s", "%d",
                                      "todo", "replace", "changeme", "xxx",
                                      "your_", "insert_", "put_your", "password"]):
            return False
        if user in DUMMY_USERS: return False
        return True
    except Exception:
        return False

def mask_url_password(matched_url: str) -> str:
    try:
        p = urlparse(matched_url)
        if p.password:
            masked_netloc = f"{p.username or ''}:*****@{p.hostname or ''}"
            if p.port: masked_netloc += f":{p.port}"
            from urllib.parse import urlunparse
            return urlunparse((p.scheme, masked_netloc, p.path, p.params, p.query, p.fragment))
    except Exception:
        pass
    return matched_url[:50] + "..."

# CNAME takeover fingerprints
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
}

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.dev",
    "/config.json", "/config.yaml", "/settings.json", "/app.json",
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/index",
    "/backup.sql", "/dump.sql", "/db.sqlite", "/database.sqlite", "/backup.zip",
    "/main.js.map", "/app.js.map", "/bundle.js.map", "/vendor.js.map",
    "/static/js/main.chunk.js.map", "/static/js/bundle.js.map",
    "/.well-known/jwks.json", "/.well-known/openid-configuration",
    "/.well-known/security.txt", "/.well-known/change-password",
    "/api/v1/health", "/api/v1/ready", "/api/v1/debug", "/api/v1/env",
    "/api/v1/config", "/api/v1/metrics", "/api/v1/stream/demo",
    "/api/v1/version", "/api/v1/info", "/api/v1/admin",
    "/api/health", "/api/status", "/api/debug",
    "/health", "/ready", "/status", "/ping",
    "/metrics", "/prometheus", "/debug/pprof",
    "/docs", "/openapi.json", "/swagger", "/swagger.json", "/swagger-ui.html",
    "/api-docs", "/redoc", "/graphql",
    "/admin", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer.php",
    "/_admin", "/_debug", "/_metrics",
    "/rest/settings", "/rest/license", "/rest/owner",
    "/rest/debug", "/rest/users", "/rest/api-keys",
    "/rest/workflows", "/rest/credentials",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/info", "/actuator/mappings",
    "/server-status", "/server-info",
    "/_next/static/", "/__webpack_hmr",
]

# ── 0day Detection Constants (Oracle-Security/CVEs) ─────────────────────────
NCENTRAL_VERSION_RE  = re.compile(
    r'ncentralVersion["\']?\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)["\']'
)
NCENTRAL_VULN_MAX    = (2026, 3, 1, 14)  # < This version is vulnerable to Able2Shell
IBM_NOVALINK_PORT    = 1657
SCREENCONNECT_PATH   = "/SetupWizard.aspx/"
DNN_VERSION_RE       = re.compile(r'DotNetNuke[^\d]*([0-9]+\.[0-9]+\.[0-9]+)', re.I)
PARALLELS_VERSION_RE = re.compile(r'Parallels(?:\s+RAS)?[^\d]*([0-9]+\.[0-9]+\.[0-9]+)', re.I)
QSTAR_PATHS = ["/qnme-ajax?method=tree_table", "/QStarWeb/", "/qstar/"]
CITRIX_BLEED_PATH = "/oauth/idp/.well-known/openid-configuration"
OFBIZ_PATH = "/webtools/control/ProgramExport"

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

def s3_permutations(domain: str) -> list:
    base = domain.split(".")[0]
    parts = [base, domain.replace(".", "-"), domain.replace(".", "")]
    prefixes = ["", "dev-", "staging-", "prod-", "backup-", "data-", "assets-",
                "media-", "static-", "files-", "uploads-", "logs-"]
    buckets = set()
    for p in parts:
        for pref in prefixes:
            buckets.add(f"{pref}{p}")
            buckets.add(f"{p}-{pref.rstrip('-')}" if pref else p)
    return list(buckets)[:30]

# ── Data models ───────────────────────────────────────────────────────────────
@dataclass
class Finding:
    id:           str
    severity:     str
    category:     str
    title:        str
    target:       str
    evidence:     str = ""
    command:      str = ""
    remediation:  str = ""

@dataclass
class ScanResult:
    target:       str
    timestamp:    str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    subdomains:   list = field(default_factory=list)
    dns_records:  dict = field(default_factory=dict)
    live_hosts:   list = field(default_factory=list)
    technologies: dict = field(default_factory=dict)
    findings:     list = field(default_factory=list)
    passed:       list = field(default_factory=list)
    routes:       list = field(default_factory=list)
    endpoints:    list = field(default_factory=list)
    oauth_params: list = field(default_factory=list)
    summary:      dict = field(default_factory=dict)

SEV_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
SEV_EMOJI = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}

# ── HTTP helper ───────────────────────────────────────────────────────────────
def http_get(url: str, headers: dict = None, follow: bool = True, timeout: int = TIMEOUT):
    h = dict(BROWSER_HEADERS)
    if headers: h.update(headers)
    if HAS_HTTPX:
        try:
            r = httpx.get(url, headers=h, timeout=timeout, follow_redirects=follow, verify=True)
            return r.status_code, dict(r.headers), r.content
        except Exception as e:
            raise ConnectionError(str(e))
    else:
        import urllib.request as ur, urllib.error as ue, ssl as _ssl
        ctx = _ssl.create_default_context()
        req = ur.Request(url, headers=h)
        try:
            with ur.urlopen(req, context=ctx, timeout=timeout) as resp:
                body = resp.read()
                hdrs = {k.lower(): v for k,v in resp.headers.items()}
                return resp.status, hdrs, body
        except ue.HTTPError as e:
            body = b""
            try: body = e.read()
            except: pass
            hdrs = {k.lower(): v for k,v in e.headers.items()} if e.headers else {}
            return e.code, hdrs, body
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
    server = h.get("server", "").lower()
    cf_ray = h.get("cf-ray", "")
    body_text = body[:3000].decode("utf-8", "replace").lower()
    if status == 403:
        if "attention required! | cloudflare" in body_text or "sorry, you have been blocked" in body_text or "cf-error-details" in body_text:
            return True, "Cloudflare WAF Block Page (HTTP 403)"
        if "access denied" in body_text and (cf_ray or "cloudflare" in server):
            return True, "Cloudflare Access Denied (HTTP 403)"
        if "incapsula" in body_text or "imperva" in body_text:
            return True, "Imperva/Incapsula WAF Block (HTTP 403)"
        if "akamai" in body_text or "reference&#32;&#35;" in body_text:
            return True, "Akamai WAF Block (HTTP 403)"
    if status in (429, 503):
        if "just a moment..." in body_text or "checking your browser" in body_text or "cf-challenge" in body_text:
            return True, "Cloudflare Anti-Bot / JS Challenge"
    return False, ""

def audit_jwt_token(token: str, source_url: str) -> list:
    findings = []
    parts = token.strip().split(".")
    if len(parts) < 2: return findings
    try:
        hdr_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(hdr_b64).decode("utf-8", "replace"))
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8", "replace"))
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append({
                "severity": "Critical", "category": "jwt",
                "title": "JWT Signature Bypass: 'alg: none' accepted",
                "url": source_url,
                "evidence": f"Header: {json.dumps(header)} | Claims: {list(payload.keys())}",
                "command": f'curl -s "{source_url}" | grep -Eo "{token[:25]}"',
                "remediation": "Reject unauthenticated JWTs with 'alg: none'.",
            })
        elif alg.startswith("hs"):
            findings.append({
                "severity": "Info", "category": "jwt",
                "title": f"JWT uses symmetric HMAC ({alg.upper()})",
                "url": source_url,
                "evidence": f"Header: {json.dumps(header)} | Key count: {len(payload)} claims",
                "command": f'curl -s "{source_url}" | grep -Eo "{token[:25]}"',
                "remediation": "Prefer asymmetric keys (RS256/ES256).",
            })
        sensitive_keys = [k for k in payload.keys() if any(w in k.lower() for w in ["pass", "secret", "priv", "email", "role", "admin"])]
        if sensitive_keys:
            findings.append({
                "severity": "Low", "category": "jwt",
                "title": f"JWT payload exposes: {', '.join(sensitive_keys[:4])}",
                "url": source_url,
                "evidence": f"Claims disclosed: {', '.join(sensitive_keys)}",
                "command": f'curl -s "{source_url}" | grep -Eo "{token[:25]}"',
                "remediation": "Do not store secrets inside unencrypted JWT payloads.",
            })
    except Exception:
        pass
    return findings

def audit_cookie(name: str, value: str, raw_cookie_str: str, base_url: str) -> list:
    findings = []
    parts = [p.strip() for p in raw_cookie_str.split(";")]
    attrs = {p.split("=")[0].lower(): (p.split("=")[1] if "=" in p else True) for p in parts}
    is_session = any(k in name.lower() for k in ["sess", "auth", "token", "jwt", "id", "login", "user", "csrf"])
    if "secure" not in attrs and base_url.startswith("https:"):
        findings.append({"severity": "Medium" if is_session else "Low","category": "cookies",
            "title": f"Insecure Cookie: '{name}' lacks Secure flag","url": base_url,
            "evidence": raw_cookie_str[:120],
            "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
            "remediation": "Add 'Secure' attribute."})
    if is_session and "httponly" not in attrs:
        findings.append({"severity": "Medium","category": "cookies",
            "title": f"XSS Risk: Cookie '{name}' lacks HttpOnly","url": base_url,
            "evidence": raw_cookie_str[:120],
            "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
            "remediation": "Add 'HttpOnly'."})
    if "samesite" not in attrs:
        findings.append({"severity": "Low","category": "cookies",
            "title": f"CSRF Risk: Cookie '{name}' lacks SameSite","url": base_url,
            "evidence": raw_cookie_str[:120],
            "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
            "remediation": "Set SameSite=Lax."})
    if name.startswith("__Host-"):
        if "secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs:
            findings.append({"severity": "Medium","category": "cookies",
                "title": f"Malformed __Host- Cookie: '{name}'","url": base_url,
                "evidence": raw_cookie_str[:120],
                "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
                "remediation": "__Host- requires Secure, Path=/, no Domain."})
    elif name.startswith("__Secure-"):
        if "secure" not in attrs:
            findings.append({"severity": "Medium","category": "cookies",
                "title": f"Malformed __Secure- Cookie: '{name}'","url": base_url,
                "evidence": raw_cookie_str[:120],
                "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
                "remediation": "__Secure- requires Secure."})
    return findings

def audit_dns_security(domain: str) -> list:
    findings = []
    if not HAS_DNS: return findings
    txt_records, dmarc_records, caa_records = [], [], []
    try:
        for r in dns.resolver.resolve(domain, "TXT"): txt_records.append(str(r).strip('"'))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"): dmarc_records.append(str(r).strip('"'))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(domain, "CAA"): caa_records.append(str(r))
    except Exception: pass
    spf = [t for t in txt_records if "v=spf1" in t]
    if not spf:
        findings.append({"severity": "Low","category": "dns-sec","title": f"DNS: Missing SPF on {domain}",
            "url": f"dns://{domain}","evidence": "No 'v=spf1' TXT found","command": f"dig +short TXT {domain}",
            "remediation": "Publish SPF TXT."})
    elif "+all" in spf[0]:
        findings.append({"severity": "Medium","category": "dns-sec","title": f"DNS: Insecure SPF (+all)",
            "url": f"dns://{domain}","evidence": spf[0],"command": f"dig +short TXT {domain}",
            "remediation": "Change +all to -all."})
    if not dmarc_records:
        findings.append({"severity": "Low","category": "dns-sec","title": f"DNS: Missing DMARC",
            "url": f"dns://_dmarc.{domain}","evidence": "No DMARC TXT","command": f"dig +short TXT _dmarc.{domain}",
            "remediation": "Publish DMARC."})
    elif "p=none" in dmarc_records[0]:
        findings.append({"severity": "Info","category": "dns-sec","title": "DNS: DMARC p=none",
            "url": f"dns://_dmarc.{domain}","evidence": dmarc_records[0],"command": f"dig +short TXT _dmarc.{domain}",
            "remediation": "Move to p=quarantine or p=reject."})
    if not caa_records:
        findings.append({"severity": "Info","category": "dns-sec","title": f"DNS: No CAA for {domain}",
            "url": f"dns://{domain}","evidence": "No CAA","command": f"dig +short CAA {domain}",
            "remediation": "Configure CAA records."})
    return findings

def deep_fingerprint_tech(url: str, hdrs: dict, html_text: str = "") -> list:
    h = norm_headers(hdrs); tech = set()
    if h.get("server"): tech.add(f"Server: {h.get('server')}")
    if h.get("cf-ray") or h.get("server") == "cloudflare": tech.add("Cloudflare CDN & WAF")
    if h.get("x-vercel-id"): tech.add("Vercel Edge Platform")
    if h.get("x-amz-request-id") or "amazonaws.com" in h.get("x-amz-id-2", ""): tech.add("Amazon Web Services (AWS)")
    if h.get("x-powered-by"): tech.add(f"Powered-By: {h.get('x-powered-by')}")
    if html_text:
        if "__NEXT_DATA__" in html_text or "/_next/" in html_text:
            m = re.search(r'content=["\']Next\.js\s*([0-9\.]+)["\']', html_text)
            v = f" v{m.group(1)}" if m else ""
            tech.add(f"Next.js (React){v}")
        elif "react" in html_text.lower() or "data-reactroot" in html_text:
            tech.add("React.js")
        if "tailwind" in html_text.lower() or any(c in html_text for c in ["flex ", "grid ", "items-center", "justify-center"]):
            tech.add("Tailwind CSS")
        if "authjs" in html_text.lower() or "__host-authjs" in str(hdrs).lower():
            tech.add("Auth.js / NextAuth")
        if "sentry" in html_text.lower() or "@sentry" in html_text:
            tech.add("Sentry Error Tracking")
        if "google-analytics.com" in html_text or "googletagmanager.com" in html_text:
            tech.add("Google Analytics / GTM")
    return sorted(list(tech))

OAUTH_REDIRECT_PATTERN = re.compile(
    r"""(?:['"])([^"'\s]*(?:callbackUrl|redirect_uri|redirect_url|return_to|next|returnTo)[^"'\s]*|/api/auth/callback/[a-zA-Z0-9_\-]+|[a-zA-Z0-9_\-]+\.apps\.googleusercontent\.com)(?:['"])"""
)

def extract_oauth_and_redirects(js_text: str) -> list:
    results = set()
    for m in OAUTH_REDIRECT_PATTERN.finditer(js_text):
        for g in m.groups():
            if g and len(g) > 4: results.add(g.strip())
    return sorted(list(results))

API_ENDPOINT_PATTERN = re.compile(
    r'["\'](/(?:api|v[0-9]|rest|graphql|admin|auth|oauth|user|webhook|settings|config)[a-zA-Z0-9_\-/\.]+[\?a-zA-Z0-9_\-=&]*)["\']'
)

def extract_endpoints_from_js(text: str) -> list:
    endpoints = set()
    for m in API_ENDPOINT_PATTERN.finditer(text):
        path = m.group(1).strip()
        if len(path) > 4 and not path.endswith(".js") and not path.endswith(".css"):
            endpoints.add(path)
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
                m_text = body.decode("utf-8", "replace")
                for r in re.findall(r'["\'](/[^"\']*)["\']\s*:\s*\[', m_text):
                    if not r.startswith("/_"): routes.add(r)
                for c in re.findall(r'["\'](static/chunks/[^"\']+\.js)["\']', m_text):
                    chunks.add(f"{base_url.rstrip('/')}/_next/{c}")
    except Exception:
        pass
    return sorted(routes), sorted(chunks)

def crawl_with_playwright(url: str, timeout: int = 15) -> dict:
    res = {"scripts": [], "links": [], "api_calls": [], "storage": {}, "error": None}
    if not HAS_PLAYWRIGHT:
        res["error"] = "Playwright not installed — run: pip install playwright && playwright install chromium"
        return res
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            context = browser.new_context(user_agent=UA, ignore_https_errors=True)
            page = context.new_page()
            captured_requests = []
            page.on("request", lambda req: captured_requests.append(req.url))
            page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
            dom_scripts = page.evaluate("() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)")
            dom_links = page.evaluate("() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)")
            storage = page.evaluate("""() => {
                const ls = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    ls[k] = localStorage.getItem(k);
                }
                return ls;
            }""")
            res["scripts"] = list(set(dom_scripts))
            res["links"] = list(set([l for l in dom_links if l.startswith("http")]))
            api_kw = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", ".json"]
            res["api_calls"] = list(set([r for r in captured_requests if any(k in r for k in api_kw)]))
            res["storage"] = storage
            browser.close()
    except Exception as e:
        res["error"] = str(e)
    return res

# ── Subdomain enumeration ─────────────────────────────────────────────────────
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
            text = body.decode("utf-8","replace")
            for m in re.finditer(rf'<td>([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})</td>', text):
                subs.add(m.group(1).lower())
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
            data = json.loads(body)
            for entry in data.get("passive_dns", []):
                h = entry.get("hostname", "").strip().lower()
                if h.endswith(f".{domain}") or h == domain: subs.add(h)
    except Exception: pass
    return subs

def enum_subdomains_crtsh(domain: str) -> set:
    subs = set()
    try:
        status, _, body = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if status == 200:
            for entry in json.loads(body):
                for n in entry.get("name_value","").split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") or n == domain: subs.add(n.lower())
    except Exception as e:
        console.print(f"  crt.sh error: {e}")
    return subs

def enum_subdomains_securitytrails(domain: str, api_key: str) -> set:
    subs = set()
    if not api_key: return subs
    try:
        status, _, body = http_get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                                    headers={"APIKEY": api_key}, timeout=15)
        if status == 200:
            data = json.loads(body)
            for s in data.get("subdomains", []): subs.add(f"{s}.{domain}")
    except Exception as e:
        console.print(f"  SecurityTrails error: {e}")
    return subs

def enum_subdomains(domain: str, api_key: str = "") -> list:
    console.print("  → crt.sh + HackerTarget + AlienVault + Anubis + RapidDNS")
    subs = enum_subdomains_crtsh(domain)
    subs |= enum_subdomains_hackertarget(domain)
    subs |= enum_subdomains_alienvault(domain)
    subs |= enum_subdomains_anubis(domain)
    subs |= enum_subdomains_rapiddns(domain)
    if api_key:
        console.print("  → SecurityTrails API")
        subs |= enum_subdomains_securitytrails(domain, api_key)
    if domain not in subs: subs.add(domain)
    console.print(f"  Found {len(subs)} subdomain(s)")
    return sorted(subs)

def resolve_dns(hosts: list) -> dict:
    records = {}
    for host in hosts:
        rec = {"A":[], "CNAME":[], "MX":[], "live":False}
        try:
            if HAS_DNS:
                for rtype in ("A","CNAME","MX"):
                    try:
                        for r in dns.resolver.resolve(host, rtype):
                            rec[rtype].append(str(r))
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
                        return {"host": host, "cname": cname, "service": svc,
                                "fingerprint": fingerprint, "command": f'curl -si "https://{host}"'}
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
                live.append({"host": host, "url": url, "status": status,
                             "server": h.get("server",""),
                             "powered_by": h.get("x-powered-by",""),
                             "redirect": h.get("location","")})
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
                if len(body_text.strip()) < 5:
                    passed.append(f"{url} → 200 (empty)"); continue
                if path.startswith("/.git/HEAD") and not body_text.startswith("ref:"):
                    passed.append(f"{url} → 200 (not git ref)"); continue
                if path.startswith("/.git/config") and "[core]" not in body_text:
                    passed.append(f"{url} → 200 (not git config)"); continue
                if path.startswith("/.env") and ("=" not in body_text or "{" in body_text[:50]):
                    passed.append(f"{url} → 200 (not env)"); continue
                snippet = body_text.replace("\n"," ").strip()
                findings.append({"url": url, "status": status, "content_type": ct,
                                 "snippet": snippet[:180],
                                 "command": f'curl -si --noproxy "*" "{url}"'})
            elif status == 200:
                passed.append(f"{url} → 200 html/SPA (FP)")
            elif status in (301, 302, 307, 308):
                loc = h.get("location","")
                passed.append(f"{url} → {status} (→ {loc[:35]})" if loc else f"{url} → {status}")
            elif status in (401, 403):
                is_waf, waf_name = is_waf_challenge(status, hdrs, body)
                passed.append(f"{url} → 403 ({waf_name})" if is_waf else f"{url} → {status} (auth)")
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
                findings.append({"severity": sev, "header": hdr, "url": base_url,
                    "detail": impact,
                    "evidence": f"Header '{hdr}' missing | Impact: {impact}",
                    "command": f'curl -sI --noproxy "*" "{base_url}"',
                    "remediation": "Add via Cloudflare Transform Rule or server config."})
            else:
                passed.append(f"{hdr}: {val[:60]}")
        csp = h.get("content-security-policy","")
        if csp:
            curl_cmd = f'curl -sI --noproxy "*" "{base_url}" | grep -i content-security-policy'
            csp_snippet = csp if len(csp) <= 250 else csp[:247] + "..."
            directives = {}
            for part in csp.split(";"):
                part = part.strip()
                if part:
                    tokens = part.split()
                    if tokens: directives[tokens[0].lower()] = tokens[1:]
            script_vals = directives.get("script-src", directives.get("default-src", []))
            has_nonce = (any("nonce-" in v for v in script_vals) or "'strict-dynamic'" in csp
                         or re.search(r"'nonce-[A-Za-z0-9+/=]+'", csp) is not None)
            has_unsafe_eval = "'unsafe-eval'" in script_vals or '"unsafe-eval"' in script_vals
            if has_unsafe_eval:
                script_dirs = [d.strip() for d in csp.split(";") if d.strip().startswith("script-src")]
                eval_ev = f"Directive: {script_dirs[0]}" if script_dirs else f"CSP: {csp_snippet}"
                eval_sev = "Low" if has_nonce else "Medium"
                eval_note = " (nonce present — eval is secondary)" if has_nonce else ""
                findings.append({"severity": eval_sev, "header": "CSP-unsafe-eval", "url": base_url,
                    "detail": f"CSP 'unsafe-eval' in script-src{eval_note}",
                    "evidence": eval_ev, "command": curl_cmd,
                    "remediation": "Remove 'unsafe-eval'."})
            has_unsafe_inline = "'unsafe-inline'" in script_vals or '"unsafe-inline"' in script_vals
            if has_unsafe_inline:
                script_dirs = [d.strip() for d in csp.split(";") if d.strip().startswith("script-src")]
                inline_ev = f"Directive: {script_dirs[0]}" if script_dirs else f"CSP: {csp_snippet}"
                if has_nonce:
                    findings.append({"severity": "Low", "header": "CSP-unsafe-inline-legacy", "url": base_url,
                        "detail": "'unsafe-inline' alongside nonce (legacy browsers only)",
                        "evidence": inline_ev, "command": curl_cmd,
                        "remediation": "Safe to keep or remove."})
                else:
                    findings.append({"severity": "Medium", "header": "CSP-unsafe-inline", "url": base_url,
                        "detail": "'unsafe-inline' in script-src — XSS possible",
                        "evidence": inline_ev, "command": curl_cmd,
                        "remediation": "Use nonces/hashes."})
            default_vals = directives.get("default-src", [])
            if "*" in default_vals or re.search(r"default-src\s+\*", csp):
                findings.append({"severity": "High", "header": "CSP-wildcard", "url": base_url,
                    "detail": "CSP default-src is wildcard (*)",
                    "evidence": f"CSP: {csp_snippet}", "command": curl_cmd,
                    "remediation": "Lock to specific origins."})
        server = h.get("server","")
        if server and any(c.isdigit() for c in server):
            findings.append({"severity":"Low","header":"server-version","url":base_url,
                "detail":f"Server version disclosed: {server}",
                "evidence":f"Server: {server}",
                "command":f'curl -sI "{base_url}"',
                "remediation":"Strip or genericise Server header."})
    except Exception as e:
        passed.append(f"Header check error: {e}")
    return findings, passed

def check_tls(host: str) -> tuple:
    findings, passed = [], []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                not_after = cert.get("notAfter","")
                if not_after:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    days = (exp - now_utc).days
                    if days < 30:
                        findings.append({"severity":"High","check":"cert-expiry","host":host,
                            "detail":f"Cert expires in {days} days ({not_after})",
                            "command":f"echo | openssl s_client -connect {host}:443 2>/dev/null | openssl x509 -noout -dates"})
                    else:
                        passed.append(f"TLS cert valid {days} days")
                cipher = s.cipher()
                passed.append(f"Cipher: {cipher[0]} / {cipher[1]}")
                if cipher[0] and any(w in cipher[0].upper() for w in ["RC4","DES","NULL","EXPORT","MD5"]):
                    findings.append({"severity":"High","check":"weak-cipher","host":host,
                        "detail":f"Weak cipher: {cipher[0]}","command":"",
                        "remediation":"Disable weak ciphers."})
    except Exception as e:
        passed.append(f"TLS check error: {e}")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for ver_name, attr in [("TLS 1.0","TLSv1"),("TLS 1.1","TLSv1_1")]:
            ver = getattr(ssl.TLSVersion, attr, None)
            if ver is None:
                passed.append(f"{ver_name}: not testable"); continue
            try:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
                ctx2.minimum_version = ver; ctx2.maximum_version = ver
                with socket.create_connection((host, 443), timeout=8) as sock:
                    with ctx2.wrap_socket(sock, server_hostname=host):
                        findings.append({"severity":"High","check":"legacy-tls","host":host,
                            "detail":f"{host} accepts {ver_name} — PCI-DSS 4.0 violation",
                            "command":f"openssl s_client -connect {host}:443 -{attr.lower()}",
                            "remediation":"Set Cloudflare minimum TLS to 1.2."})
            except ssl.SSLError:
                passed.append(f"{ver_name}: rejected ✓")
            except Exception as e:
                passed.append(f"{ver_name}: {e}")
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
                findings.append({"origin":origin,"severity":"Info","url":base_url,
                    "detail":"CORS wildcard (*) — public endpoint",
                    "evidence":f"ACAO: {acao}",
                    "command":f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation":"Restrict allowed origins if sensitive."})
            elif origin in acao and "true" in acac.lower():
                findings.append({"origin":origin,"severity":"High","url":base_url,
                    "detail":"CORS reflects origin with Allow-Credentials:true",
                    "evidence":f"ACAO: {acao} | ACAC: {acac}",
                    "command":f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation":"Remove Allow-Credentials or use token auth."})
            elif origin in acao:
                findings.append({"origin":origin,"severity":"Low","url":base_url,
                    "detail":"CORS reflects custom origin (no creds)",
                    "evidence":f"ACAO: {acao}",
                    "command":f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation":"Restrict to known origins."})
        except Exception: pass
    return findings

def check_exposures(base_url: str) -> list:
    findings = []
    checks = [
        ("/.well-known/jwks.json",           "Info",     "JWKS endpoint exposed"),
        ("/.well-known/openid-configuration","Info",     "OIDC config exposed"),
        ("/main.js.map",                     "Medium",   "Webpack source map exposed"),
        ("/app.js.map",                      "Medium",   "Webpack source map exposed"),
        ("/static/js/bundle.js.map",         "Medium",   "Webpack source map exposed"),
        ("/.git/HEAD",                       "Critical", "Git repo HEAD exposed"),
        ("/.git/config",                     "Critical", "Git config exposed"),
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
                snippet = body_text.replace("\n"," ").strip()
                findings.append({"severity":sev,"title":title,"url":url,"content_type":ct,
                                 "snippet":snippet[:150],
                                 "command":f'curl -si --noproxy "*" "{url}"',
                                 "remediation":"Block via WAF or remove from webroot."})
        except Exception: pass
    return findings

def github_scan_repo(owner_repo: str, token: str) -> list:
    findings = []
    if not token: return [{"detail":"GitHub token required"}]
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    patterns = ["password", "secret", "api_key", "apikey", "token", "ACCESS_KEY"]
    for pat in patterns[:5]:
        try:
            url = f"https://api.github.com/search/code?q={pat}+repo:{owner_repo}"
            status, _, body = http_get(url, headers=headers, timeout=10)
            if status == 200:
                data = json.loads(body)
                total = data.get("total_count",0)
                if total > 0:
                    findings.append({"severity":"High","pattern":pat,
                        "total_matches":total,"repo":owner_repo,
                        "detail":f"Found {total} matches for '{pat}' in {owner_repo}",
                        "command":f"gh search code '{pat}' --repo {owner_repo}"})
        except Exception as e:
            findings.append({"detail":f"GitHub API error: {e}"})
    return findings

def check_s3_buckets(domain: str) -> list:
    findings = []
    buckets = s3_permutations(domain)
    for bucket in buckets[:20]:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            status, _, body = http_get(url, timeout=5)
            snippet = body[:200].decode("utf-8","replace")
            if status == 200:
                findings.append({"severity":"Critical","bucket":bucket,
                    "detail":f"S3 bucket publicly readable: {bucket}",
                    "snippet":snippet[:100],
                    "command":f'curl -si "{url}"',
                    "remediation":"Set ACL private; use bucket policy."})
            elif status == 403:
                findings.append({"severity":"Info","bucket":bucket,
                    "detail":f"S3 bucket exists but denied: {bucket}",
                    "command":f'curl -si "{url}"'})
        except Exception: pass
    return findings

def collect_js_urls(base_url: str) -> tuple:
    js_urls = set(); routes = set()
    try:
        _, _, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8", "replace")
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', text):
            src = m.group(1)
            if src.startswith("http"): js_urls.add(src)
            elif src.startswith("//"): js_urls.add("https:" + src)
            elif src.startswith("/"):
                p = urlparse(base_url)
                js_urls.add(f"{p.scheme}://{p.netloc}{src}")
        nxt_routes, nxt_chunks = extract_nextjs_routes_and_chunks(base_url, text)
        routes.update(nxt_routes); js_urls.update(nxt_chunks)
    except Exception: pass
    return sorted(list(js_urls))[:60], sorted(list(routes))

def scan_js_secrets(js_url: str) -> tuple:
    secrets = []; endpoints = []
    try:
        status, _, body = http_get(js_url, timeout=10)
        if status != 200: return secrets, endpoints
        text = body.decode("utf-8","replace")
        endpoints = extract_endpoints_from_js(text)
        for name, pattern in JS_SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if not matches: continue
            if name == "Password in URL":
                valid_matches = [m for m in matches if is_valid_secret_url(m)]
                if not valid_matches: continue
                matches = valid_matches
                sample = mask_url_password(matches[0])
            else:
                sample = matches[0][:60]
            if name == "JWT Token":
                for token_match in matches[:3]:
                    for jf in audit_jwt_token(token_match, js_url):
                        secrets.append({
                            "severity": jf["severity"],
                            "type": jf.get("category", "jwt"),
                            "url": js_url,
                            "detail": jf.get("title", ""),
                            "sample": token_match[:40] + "...",
                            "command": jf["command"],
                            "remediation": jf["remediation"],
                        })
            secrets.append({
                "severity":"Critical" if name not in ("JWT Token", "Firebase URL") else "Info",
                "type":name,"url":js_url,
                "detail":f"{len(matches)} match(es) of '{name}' pattern",
                "sample":sample,
                "command":f'curl -s "{js_url}" | grep -Eo "{pattern[:40]}"',
                "remediation":"Rotate secret; remove from client-side code."})
    except Exception: pass
    return secrets, endpoints

def run_nuclei(target: str, out_dir: Path) -> list:
    findings = []
    nuclei_path = subprocess.run(["which","nuclei"], capture_output=True, text=True).stdout.strip()
    if not nuclei_path:
        return [{"error":"nuclei not found"}]
    out_file = out_dir / "nuclei_output.jsonl"
    cmd = [nuclei_path, "-u", target,
           "-tags", "misconfig,exposure,config,headers,ssl,file,token,generic",
           "-severity", "critical,high,medium,info",
           "-jsonl", "-o", str(out_file), "-silent", "-no-interactsh",
           "-rl", "50", "-c", "10"]
    try:
        subprocess.run(cmd, timeout=240, capture_output=True)
        if out_file.exists():
            for line in out_file.read_text().splitlines():
                try:
                    n = json.loads(line)
                    findings.append({"severity": n.get("info",{}).get("severity","info").capitalize(),
                        "category": "nuclei",
                        "title": n.get("info",{}).get("name","nuclei finding"),
                        "url": n.get("matched-at", target),
                        "detail": n.get("info",{}).get("description",""),
                        "command": f"nuclei -u {target} -id {n.get('template-id','')}",
                        "remediation": n.get("info",{}).get("remediation","")})
                except Exception: pass
    except subprocess.TimeoutExpired:
        findings.append({"error":"nuclei timed out (240s)"})
    except Exception as e:
        findings.append({"error": str(e)})
    return findings

def parse_dalfox_output(text: str, min_confidence: float = 0.8) -> list:
    findings = []
    block_re = re.compile(
        r'\((\d+)\)\s+(\S+)\s+\[(\w+)\]\s*\n'
        r'.*?url\s*:\s*(\S+)\s*\n'
        r'.*?context\s*:\s*(\S+)\s*\n'
        r'.*?payload\s*:\s*(.+?)\s*\n'
        r'.*?confidence\s*:\s*([\d.]+)', re.DOTALL)
    by_param = {}
    for m in block_re.finditer(text):
        idx, param, method, url, ctx, payload, conf_str = m.groups()
        try: conf = float(conf_str)
        except ValueError: conf = 0.0
        if conf < min_confidence: continue
        key = param.lower()
        if key not in by_param:
            by_param[key] = {"param":param,"method":method,"url":url,
                             "context":ctx,"confidence":conf,"payloads":[],"poc_urls":[]}
        by_param[key]["payloads"].append(payload.strip())
        by_param[key]["confidence"] = max(by_param[key]["confidence"], conf)
        poc_m = re.search(r'poc\s*:\s*(\S+)', m.group(0))
        if poc_m: by_param[key]["poc_urls"].append(poc_m.group(1))
    for key, info in by_param.items():
        param = info["param"]; method = info["method"]
        url_base = info["url"].split("?")[0]; ctx = info["context"]
        conf = info["confidence"]; n_pay = len(info["payloads"])
        poc = info["poc_urls"][0] if info["poc_urls"] else info["url"]
        if conf >= 1.4: sev = "High"
        elif conf >= 1.0: sev = "Medium"
        else: sev = "Low"
        findings.append({"severity":sev,"category":"xss-dalfox",
            "title":f"DOM XSS — param '{param}' [{method}] (conf {conf:.2f})",
            "url":url_base,
            "evidence":(f"Param: {param} | Method: {method} | Context: {ctx}\n"
                        f"Confidence: {conf:.2f} | Payloads: {n_pay}\n"
                        f"Sample: {info['payloads'][0][:120]}"),
            "command":f'# Reproduce: {poc}',
            "remediation":"Sanitise query params. Use textContent. Enforce strict CSP."})
    return findings

def parse_nuclei_jsonl(text: str) -> list:
    findings = []; seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        try: n = json.loads(line)
        except Exception: continue
        tid = n.get("template-id",""); murl = n.get("matched-at","")
        key = f"{tid}:{murl}"
        if key in seen: continue
        seen.add(key)
        info = n.get("info", {}); sev = info.get("severity","info").capitalize()
        if sev.lower() == "info": sev = "Info"
        findings.append({"severity":sev,"category":"nuclei",
            "title":info.get("name", tid),"url":murl,
            "evidence":info.get("description","")[:200],
            "command":f"nuclei -u {murl.split('?')[0]} -id {tid}",
            "remediation":info.get("remediation","")})
    return findings

# ── 0day Detection Functions (Oracle-Security/CVEs) ─────────────────────────
def _version_tuple(v: str):
    try: return tuple(int(x) for x in v.split("."))
    except Exception: return (0, 0, 0, 0)

def detect_ncentral(base_url: str) -> list:
    findings = []; version = None
    for path in ("/", "/login", "/dms/", "/dms/services/ServerUI"):
        try:
            status, _, body = http_get(base_url.rstrip("/") + path, timeout=10)
            if status == 200:
                text = body.decode("utf-8", "replace")
                m = NCENTRAL_VERSION_RE.search(text)
                if m:
                    version = m.group(1); break
        except Exception:
            continue
    if version:
        vulnerable = _version_tuple(version) < NCENTRAL_VULN_MAX
        findings.append({
            "severity": "Critical" if vulnerable else "Info",
            "category": "0day-ncentral",
            "title": (f"N-able N-central {version} — VULNERABLE to Able2Shell (pre-auth RCE)"
                      if vulnerable else f"N-able N-central {version} detected"),
            "url": base_url,
            "evidence": f"Pre-auth version disclosure: ncentralVersion={version}",
            "command": f'curl -s "{base_url}/" | grep -o "ncentralVersion[^,]*"',
            "remediation": "Upgrade to >= 2026.3.1.14. Block /dms/ externally.",
        })
        return findings
    try:
        status, _, body = http_get(base_url.rstrip("/") + "/dms/services/ServerUI", timeout=8)
        if status in (200, 500) and b"ServerUI" in body:
            findings.append({
                "severity": "High",
                "category": "0day-ncentral",
                "title": "N-central ServerUI exposed (Able2Shell attack surface)",
                "url": base_url + "/dms/services/ServerUI",
                "evidence": f"HTTP {status} from /dms/services/ServerUI",
                "command": f'curl -si "{base_url}/dms/services/ServerUI"',
                "remediation": "Restrict management interface to trusted networks.",
            })
    except Exception:
        pass
    return findings

def detect_novalink(host: str) -> list:
    findings = []
    try:
        sock = socket.create_connection((host, IBM_NOVALINK_PORT), timeout=5)
        sock.close()
        findings.append({
            "severity": "Critical",
            "category": "0day-novalink",
            "title": "IBM Novalink port 1657 open — unauthenticated RCE risk",
            "url": f"tcp://{host}:{IBM_NOVALINK_PORT}",
            "evidence": "TCP port 1657 reachable (CVE-2026-12943 / CVE-2026-14971)",
            "command": f"nc -zv {host} {IBM_NOVALINK_PORT}",
            "remediation": "Restrict port 1657. Apply IBM PowerVM patches.",
        })
    except Exception:
        pass
    return findings

def detect_screenconnect(base_url: str) -> list:
    findings = []
    try:
        status, _, body = http_get(base_url.rstrip("/") + SCREENCONNECT_PATH, timeout=8)
        text = body.decode("utf-8", "replace").lower()
        if status == 200 and ("setupwizard" in text or "screenconnect" in text):
            findings.append({
                "severity": "Critical",
                "category": "0day-screenconnect",
                "title": "ConnectWise ScreenConnect — CVE-2024-1709 auth bypass",
                "url": base_url + SCREENCONNECT_PATH,
                "evidence": "SetupWizard accessible HTTP 200 — instance likely < 23.9.8",
                "command": f'curl -si "{base_url}{SCREENCONNECT_PATH}"',
                "remediation": "Upgrade ScreenConnect to >= 23.9.8.",
            })
    except Exception:
        pass
    return findings

def detect_dnn(base_url: str) -> list:
    findings = []
    try:
        status, _, body = http_get(base_url.rstrip("/") + "/Login", timeout=6)
        if status == 200:
            text = body.decode("utf-8", "replace")
            m = DNN_VERSION_RE.search(text)
            if m:
                findings.append({
                    "severity": "High",
                    "category": "0day-dnn",
                    "title": f"DotNetNuke {m.group(1)} — check CVE-2018-14486",
                    "url": base_url,
                    "evidence": f"DNN version: {m.group(1)}",
                    "command": f'curl -s "{base_url}/Login" | grep -i "DotNetNuke"',
                    "remediation": "Upgrade DNN to >= 9.2.0.",
                })
    except Exception:
        pass
    return findings

def detect_parallels(base_url: str) -> list:
    findings = []
    for path in ("/", "/Admin/", "/RASHTML5/", "/RASHTML5Gateway/"):
        try:
            status, _, body = http_get(base_url.rstrip("/") + path, timeout=8)
            if status == 200:
                text = body.decode("utf-8", "replace")
                m = PARALLELS_VERSION_RE.search(text)
                if m:
                    findings.append({
                        "severity": "High",
                        "category": "0day-parallels",
                        "title": f"Parallels RAS {m.group(1)} — check CVE-2023-45894 (sandbox escape)",
                        "url": base_url + path,
                        "evidence": f"Parallels RAS version: {m.group(1)}. Fixed in 19.2.23975",
                        "command": f'curl -s "{base_url}{path}" | grep -i Parallels',
                        "remediation": "Upgrade Parallels RAS to >= 19.2.23975.",
                    })
                    return findings
        except Exception:
            continue
    return findings

def detect_qstar(base_url: str) -> list:
    findings = []
    for path in QSTAR_PATHS:
        try:
            status, _, body = http_get(base_url.rstrip("/") + path, timeout=8)
            if status in (200, 302):
                findings.append({
                    "severity": "Medium",
                    "category": "0day-qstar",
                    "title": f"QStar Archive endpoint exposed: {path}",
                    "url": base_url + path,
                    "evidence": f"HTTP {status} — check CVE-2023-51062…51070",
                    "command": f'curl -si "{base_url}{path}"',
                    "remediation": "Apply QStar patches; restrict external access.",
                })
        except Exception:
            pass
    return findings

def detect_moveit(base_url: str) -> list:
    findings = []
    try:
        status, _, body = http_get(base_url.rstrip("/") + "/human.aspx", timeout=8)
        text = body.decode("utf-8", "replace")
        if status == 200 and "moveit" in text.lower():
            findings.append({
                "severity": "Critical",
                "category": "0day-moveit",
                "title": "MOVEit Transfer exposed — check CVE-2023-34362 (SQLi→RCE)",
                "url": base_url + "/human.aspx",
                "evidence": "MOVEit Transfer login page detected",
                "command": f'curl -si "{base_url}/human.aspx"',
                "remediation": "Apply MOVEit patches; block /human.aspx externally.",
            })
    except Exception:
        pass
    return findings

def detect_citrix_bleed(base_url: str) -> list:
    findings = []
    try:
        status, hdrs, body = http_get(base_url.rstrip("/") + CITRIX_BLEED_PATH,
                                       headers={"Host": "localhost"}, timeout=8)
        text = body.decode("utf-8", "replace").lower()
        if status in (200, 302) and ("citrix" in text or "netscaler" in text):
            findings.append({
                "severity": "High",
                "category": "0day-citrix",
                "title": "Citrix NetScaler exposed — check CVE-2023-4966 (Citrix Bleed)",
                "url": base_url + CITRIX_BLEED_PATH,
                "evidence": "Citrix ADC/Gateway OIDC endpoint responds",
                "command": f'curl -si -H "Host: localhost" "{base_url}{CITRIX_BLEED_PATH}"',
                "remediation": "Upgrade NetScaler to patched build; rotate sessions.",
            })
    except Exception:
        pass
    return findings

def detect_ofbiz(base_url: str) -> list:
    findings = []
    try:
        status, _, body = http_get(base_url.rstrip("/") + OFBIZ_PATH, timeout=8)
        text = body.decode("utf-8", "replace").lower()
        if status == 200 and ("ofbiz" in text or "programexport" in text):
            findings.append({
                "severity": "High",
                "category": "0day-ofbiz",
                "title": "Apache OFBiz exposed — check CVE-2023-51467 (auth bypass)",
                "url": base_url + OFBIZ_PATH,
                "evidence": "OFBiz ProgramExport endpoint reachable",
                "command": f'curl -si "{base_url}{OFBIZ_PATH}"',
                "remediation": "Upgrade OFBiz to >= 18.12.11.",
            })
    except Exception:
        pass
    return findings

def detect_wordpress(base_url: str) -> list:
    findings = []
    try:
        status, _, body = http_get(base_url.rstrip("/") + "/wp-json/wp/v2/users", timeout=8)
        if status == 200:
            data = json.loads(body)
            if isinstance(data, list) and data:
                findings.append({
                    "severity": "Low",
                    "category": "0day-wordpress",
                    "title": "WordPress REST API — user enumeration enabled",
                    "url": base_url + "/wp-json/wp/v2/users",
                    "evidence": f"Exposed {len(data)} user(s) via REST API",
                    "command": f'curl -s "{base_url}/wp-json/wp/v2/users"',
                    "remediation": "Disable REST user endpoint or restrict to auth users.",
                })
    except Exception:
        pass
    return findings

# ── Report generation ────────────────────────────────────────────────────────
def generate_markdown(result: ScanResult, out_path: Path):
    sev_counts = {}
    for f in result.findings:
        s = f.get("severity","Info")
        sev_counts[s] = sev_counts.get(s,0) + 1
    lines = [
        f"# Bounty Recon Report — {result.target}", "",
        f"| | |", f"|---|---|",
        f"| **Generated** | {result.timestamp} |",
        f"| **Tool** | bounty_recon.py v{VERSION} |",
        f"| **Vantage** | Open internet, no proxy, read-only |", "",
        "---", "", "## Executive Summary", "",
        "| Severity | Count |", "|----------|-------|",
    ]
    for sev in ["Critical","High","Medium","Low","Info"]:
        c = sev_counts.get(sev,0)
        lines.append(f"| {SEV_EMOJI.get(sev,'')} **{sev}** | {c} |")
    lines += [f"| ✅ Passed | {len(result.passed)} |",""]
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
    if result.routes:
        lines += ["## Discovered Application Routes",""]
        for r in result.routes[:40]: lines.append(f"- `{r}`")
        lines += [""]
    if result.endpoints:
        lines += ["## Discovered API Endpoints",""]
        for ep in result.endpoints[:50]: lines.append(f"- `{ep}`")
        lines += [""]
    if getattr(result, "oauth_params", None):
        lines += ["## OAuth Callbacks & Redirect Targets",""]
        for oa in result.oauth_params[:40]: lines.append(f"- `{oa}`")
        lines += [""]
    lines += ["## Findings",""]
    sorted_f = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.get("severity","Info"),4))
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity","Info")
        title = f.get("title") or f.get("detail") or f.get("header","") or "Finding"
        url = f.get("url") or f.get("host","")
        lines += [f"### {i}. {SEV_EMOJI.get(sev,'')} [{sev}] {title}","",f"**Severity:** {sev}  "]
        if url: lines.append(f"**Target:** `{url}`  ")
        ev = f.get("evidence") or f.get("snippet") or f.get("detail","")
        if ev: lines += ["**Evidence:**","```",ev[:300],"```"]
        if f.get("command"): lines += ["**Reproduce:**","```bash",f["command"],"```"]
        if f.get("remediation"): lines.append(f"**Remediation:** {f['remediation']}")
        lines += [""]
    lines += ["## Passed Checks","","```"]
    lines += result.passed[:80]
    lines += ["```","","---",
              f"*bounty_recon.py v{VERSION} — read-only passive scanner — use on authorised targets only*"]
    out_path.write_text("\n".join(lines), encoding="utf-8")

def generate_json(result: ScanResult, out_path: Path):
    out_path.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")

def print_finding(f: dict):
    sev = f.get("severity","Info"); em = SEV_EMOJI.get(sev,"⚪")
    t = f.get("title") or f.get("detail") or f.get("header","")
    url = f.get("url") or f.get("host","")
    ev = (f.get("evidence") or f.get("snippet") or "")[:100]
    if HAS_RICH:
        console.print(f"  {em} [bold]{sev}[/bold] {t}")
        if url: console.print(f"     [cyan]{url}[/cyan]")
        if ev:  console.print(f"     [green]{ev}[/green]")
    else:
        print(f"  {em} [{sev}] {t}")
        if url: print(f"     {url}")
        if ev:  print(f"     {ev}")

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description=f"bounty_recon.py v{VERSION} — Bug Bounty Passive Recon & Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-t","--target", required=True)
    ap.add_argument("--url", help="Override base URL")
    ap.add_argument("--cors-origin", action="append", default=[], dest="cors_origins")
    ap.add_argument("--nuclei", action="store_true")
    ap.add_argument("--js", action="store_true")
    ap.add_argument("--playwright", action="store_true")
    ap.add_argument("--s3", action="store_true")
    ap.add_argument("--github-repo")
    ap.add_argument("--github-org")
    ap.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN",""))
    ap.add_argument("--securitytrails-key", default=os.environ.get("SECURITYTRAILS_API_KEY",""))
    ap.add_argument("--no-subdomains", action="store_true")
    ap.add_argument("--out", default="")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--import-dalfox", default="", dest="import_dalfox")
    ap.add_argument("--import-nuclei", default="", dest="import_nuclei")
    ap.add_argument("--min-confidence", type=float, default=0.8, dest="min_confidence")
    ap.add_argument("--no-0day", action="store_true",
                    help="Skip 0day/CVE fingerprinting modules")
    args = ap.parse_args()

    domain = args.target.replace("https://","").replace("http://","").split("/")[0]
    base_url = args.url or f"https://{domain}"
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.out or f"{domain.replace('.','_')}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M')}"
    md_path = out_dir / f"{stem}.md"
    jp = out_dir / f"{stem}.json"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    if HAS_RICH:
        console.print(Panel(
            f"[bold cyan]bounty_recon.py[/bold cyan] v{VERSION}\n"
            f"Target  : [bold]{domain}[/bold]\n"
            f"Base URL: {base_url}\n"
            f"nuclei={args.nuclei}  js={args.js}  playwright={args.playwright}  s3={args.s3}  "
            f"0day={'off' if args.no_0day else 'on'}",
            title="🔍 Bug Bounty Passive Recon"))
    else:
        print(f"\n{'='*55}\nbounty_recon.py v{VERSION} | {domain}\n{'='*55}")

    # ── 1. Subdomains ────────────────────────────────────────────────────────
    if not args.no_subdomains:
        console.print("\n[bold]1. Subdomain Enumeration[/bold]" if HAS_RICH else "\n1. Subdomain Enumeration")
        result.subdomains = enum_subdomains(domain, args.securitytrails_key)
    else:
        result.subdomains = [domain]

    # ── 2. DNS + takeover ────────────────────────────────────────────────────
    console.print("\n[bold]2. DNS Resolution + Takeover Check[/bold]" if HAS_RICH else "\n2. DNS + Takeover")
    dns_records = resolve_dns(result.subdomains[:40])
    result.dns_records = dns_records
    for host, rec in list(dns_records.items())[:10]:
        s = "✓ live" if rec["live"] else "✗ dead"
        console.print(f"  {s} {host} A={rec['A'][:2]} CNAME={rec['CNAME'][:1]}")
        if rec["CNAME"]:
            to = check_dns_takeover(host, rec["CNAME"])
            if to:
                all_findings.append({"severity":"Critical","category":"dns-takeover",
                    "title":f"DNS takeover — {to['service']}","url":f"https://{host}",
                    "detail":f"CNAME {to['cname']} → unclaimed {to['service']}",
                    "evidence":f"Fingerprint: '{to['fingerprint']}'",
                    "command":to["command"],
                    "remediation":"Claim the service or remove dangling CNAME."})
    console.print("  → Auditing DNS security (SPF, DMARC, CAA)")
    for df in audit_dns_security(domain):
        all_findings.append(df)
        if HAS_RICH:
            console.print(f"    {SEV_EMOJI.get(df['severity'],'⚪')} [bold]{df['title']}[/bold]")
        else:
            print(f"    [{df['severity']}] {df['title']}")

    # ── 3. Live hosts + tech ─────────────────────────────────────────────────
    console.print("\n[bold]3. Live Host Detection + Tech[/bold]" if HAS_RICH else "\n3. Live Hosts")
    candidate = [h for h,r in dns_records.items() if r["live"]] or [domain]
    live = check_live(candidate[:20])
    result.live_hosts = live
    console.print(f"  {len(live)} live host(s)")
    for lh in live:
        h_resp = {}; html_body = ""
        try:
            _, h_resp, raw_b = http_get(lh["url"], timeout=6)
            html_body = raw_b.decode("utf-8", "replace")
        except Exception: pass
        techs = deep_fingerprint_tech(lh["url"], h_resp, html_body)
        if techs:
            result.technologies[lh["host"]] = techs
            console.print(f"  {lh['host']}: {', '.join(techs)}")

    scan_urls = list({h["url"] for h in live}) or [base_url]
    primary = args.url or scan_urls[0]

    # ── 3b. 0day & CVE Fingerprinting ────────────────────────────────────────
    if not args.no_0day:
        console.print("\n[bold]3b. 0day & CVE Fingerprinting[/bold]" if HAS_RICH
                      else "\n3b. 0day & CVE Fingerprinting")
        hosts_for_0day = list({u.split("://")[1].split("/")[0]
                               for u in scan_urls if "https" in u}) or [domain]
        for url in scan_urls[:3]:
            for detector in (detect_ncentral, detect_screenconnect, detect_dnn,
                             detect_parallels, detect_qstar, detect_moveit,
                             detect_citrix_bleed, detect_ofbiz, detect_wordpress):
                try:
                    for f in detector(url):
                        all_findings.append(f)
                        print_finding(f)
                except Exception:
                    pass
        for host in hosts_for_0day[:3]:
            try:
                for f in detect_novalink(host):
                    all_findings.append(f)
                    print_finding(f)
            except Exception:
                pass

    # ── 4. Endpoint sweep ────────────────────────────────────────────────────
    console.print("\n[bold]4. Sensitive Endpoint Sweep[/bold]" if HAS_RICH else "\n4. Endpoint Sweep")
    for url in scan_urls[:5]:
        ep_f, ep_p = sweep_endpoints(url)
        for f in ep_f:
            all_findings.append({"severity":"High","category":"exposure",
                "title":f"Sensitive endpoint: {f['url'].split('/')[-1] or '(root)'}",
                "url":f["url"],"command":f["command"],
                "evidence":f"HTTP 200 | {f['content_type']} | {f['snippet'][:100]}",
                "remediation":"Restrict to cluster-internal or add auth."})
        all_passed.extend(ep_p)

    # ── 5. Headers + Cookies ─────────────────────────────────────────────────
    console.print("\n[bold]5. Security Headers & Cookie Audit[/bold]" if HAS_RICH else "\n5. Headers & Cookies")
    for url in scan_urls[:5]:
        hf, hp = check_headers(url)
        for f in hf:
            all_findings.append({"severity":f["severity"],"category":"headers",
                "title":f"Header issue: {f['header']}","url":f.get("url",url),
                "command":f.get("command",""),
                "evidence":f.get("evidence") or f.get("detail",""),
                "remediation":f.get("remediation","")})
        all_passed.extend(hp)
        try:
            _, resp_hdrs, _ = http_get(url, timeout=8)
            set_cookie_raw = resp_hdrs.get("set-cookie", "")
            if set_cookie_raw:
                for sc in set_cookie_raw.splitlines():
                    c_name = sc.split("=")[0].strip() if "=" in sc else "unknown"
                    c_val = sc.split("=")[1].split(";")[0].strip() if "=" in sc else ""
                    for cf in audit_cookie(c_name, c_val, sc, url):
                        all_findings.append(cf)
        except Exception: pass

    # ── 6. TLS ───────────────────────────────────────────────────────────────
    console.print("\n[bold]6. TLS Check[/bold]" if HAS_RICH else "\n6. TLS")
    tls_hosts = list({u.split("://")[1].split("/")[0] for u in scan_urls if "https" in u}) or [domain]
    for host in tls_hosts[:5]:
        tf, tp = check_tls(host)
        for f in tf:
            all_findings.append({"severity":f["severity"],"category":"tls",
                "title":f"TLS: {f['detail']}","url":f"https://{f['host']}",
                "command":f.get("command",""),"evidence":f["detail"],
                "remediation":f.get("remediation","Set Cloudflare min TLS to 1.2")})
        all_passed.extend(tp)

    # ── 7. CORS ──────────────────────────────────────────────────────────────
    console.print("\n[bold]7. CORS Check[/bold]" if HAS_RICH else "\n7. CORS")
    sub_origins = [f"https://{s}" for s in result.subdomains[:5]]
    test_origins = list(set(args.cors_origins + sub_origins + [
        "https://evil.example.com", "null", f"https://attacker.{domain}"]))
    cors_urls = [primary + p for p in ["/api/v1/health","/api/health","/health",""]][:3]
    for curl in cors_urls:
        for cf in check_cors(curl, test_origins[:8]):
            all_findings.append({"severity":cf["severity"],"category":"cors",
                "title":f"CORS misconfig — {cf['origin']}","url":curl,
                "command":cf["command"],"evidence":cf["evidence"],
                "remediation":cf["remediation"]})

    # ── 8. Exposures ─────────────────────────────────────────────────────────
    console.print("\n[bold]8. Exposure Check[/bold]" if HAS_RICH else "\n8. Exposures")
    for url in scan_urls[:5]:
        for ef in check_exposures(url):
            all_findings.append({"severity":ef["severity"],"category":"exposure",
                "title":ef["title"],"url":ef["url"],"command":ef["command"],
                "evidence":f"{ef['content_type']} | {ef.get('snippet','')}",
                "remediation":ef["remediation"]})

    # ── 9. JS secrets & endpoints ────────────────────────────────────────────
    all_endpoints = set(); all_routes = set()
    if args.js:
        console.print("\n[bold]9. JS Secrets & Endpoints[/bold]" if HAS_RICH else "\n9. JS Secrets")
        js_urls, nxt_routes = collect_js_urls(primary)
        all_routes.update(nxt_routes)
        if nxt_routes:
            console.print(f"  ⚡ Next.js manifest: {len(nxt_routes)} internal route(s)")
        console.print(f"  Found {len(js_urls)} JS file(s)")
        all_oauth = set()
        for ju in js_urls[:35]:
            sec_list, ep_list = scan_js_secrets(ju)
            all_endpoints.update(ep_list)
            try:
                _, _, js_body = http_get(ju, timeout=8)
                js_t = js_body.decode("utf-8","replace")
                all_oauth.update(extract_oauth_and_redirects(js_t))
            except Exception: pass
            for sf in sec_list:
                sample_ev = f" | Sample: {sf['sample']}" if sf.get('sample') else ""
                all_findings.append({"severity":sf["severity"],"category":"js-secrets",
                    "title":f"Secret in JS: {sf['type']}","url":sf["url"],
                    "command":sf["command"],
                    "evidence":f"{sf['detail']}{sample_ev}",
                    "remediation":sf["remediation"]})
        if all_endpoints:
            console.print(f"  🔍 {len(all_endpoints)} API endpoint(s) in JS")
        if all_oauth:
            console.print(f"  🔑 {len(all_oauth)} OAuth/Redirect param(s)")
            result.oauth_params = sorted(list(all_oauth))

    # ── 10. Playwright ───────────────────────────────────────────────────────
    if args.playwright:
        console.print("\n[bold]10. Playwright Dynamic Crawl[/bold]" if HAS_RICH else "\n10. Playwright")
        pw_res = crawl_with_playwright(primary)
        if pw_res.get("error"):
            console.print(f"  ⚠️  {pw_res['error']}")
        else:
            console.print(f"  Captured {len(pw_res['api_calls'])} API call(s)")
            console.print(f"  Discovered {len(pw_res['scripts'])} script(s)")
            all_endpoints.update(pw_res["api_calls"])
            for l in pw_res.get("links", []):
                p_path = urlparse(l).path
                if p_path and len(p_path) > 1:
                    all_routes.add(p_path)
            storage = pw_res.get("storage", {})
            auth_keys = [k for k in storage.keys() if any(w in k.lower()
                for w in ["token","auth","jwt","secret","key"])]
            if auth_keys:
                all_findings.append({"severity":"Info","category":"storage",
                    "title":"Auth/token keys in localStorage","url":primary,
                    "command":"","evidence":f"Keys: {', '.join(auth_keys)}",
                    "remediation":"Avoid storing JWT in localStorage; use HttpOnly cookies."})

    result.routes = sorted(list(all_routes))
    result.endpoints = sorted(list(all_endpoints))

    # ── 11. S3 ───────────────────────────────────────────────────────────────
    if args.s3:
        console.print("\n[bold]11. S3 Bucket Check[/bold]" if HAS_RICH else "\n11. S3")
        for sf in check_s3_buckets(domain):
            all_findings.append({"severity":sf["severity"],"category":"s3",
                "title":f"S3: {sf['detail']}",
                "url":f"https://{sf['bucket']}.s3.amazonaws.com",
                "command":sf["command"],
                "evidence":sf.get("snippet",""),
                "remediation":sf.get("remediation","")})

    # ── 12. GitHub ───────────────────────────────────────────────────────────
    if args.github_repo and args.github_token:
        console.print("\n[bold]12. GitHub Recon[/bold]" if HAS_RICH else "\n12. GitHub")
        for gf in github_scan_repo(args.github_repo, args.github_token):
            if "error" not in gf and "detail" not in gf:
                all_findings.append({"severity":gf.get("severity","High"),
                    "category":"github",
                    "title":f"GitHub secret: {gf.get('pattern','')} in {gf.get('repo','')}",
                    "url":f"https://github.com/{gf['repo']}",
                    "command":gf.get("command",""),
                    "evidence":gf.get("detail",""),
                    "remediation":"Rotate secret; use GitHub secret scanning."})

    # ── 13. Nuclei ───────────────────────────────────────────────────────────
    if args.nuclei:
        console.print("\n[bold]13. nuclei Scan[/bold]" if HAS_RICH else "\n13. nuclei")
        for url in scan_urls[:3]:
            for n in run_nuclei(url, out_dir):
                if "error" in n:
                    all_passed.append(f"nuclei: {n['error']}")
                else:
                    all_findings.append(n)

    # ── Import Dalfox ────────────────────────────────────────────────────────
    if args.import_dalfox:
        p = Path(args.import_dalfox)
        if p.exists():
            console.print(f"\n[bold]Import: Dalfox ({p.name})[/bold]" if HAS_RICH else f"\nImport Dalfox")
            df = parse_dalfox_output(p.read_text(encoding="utf-8", errors="replace"),
                                     args.min_confidence)
            all_findings.extend(df)
            console.print(f"  Added {len(df)} Dalfox finding(s)")
        else:
            console.print(f"  [yellow]Dalfox file not found: {p}[/yellow]")

    # ── Import nuclei JSONL ──────────────────────────────────────────────────
    if args.import_nuclei:
        p = Path(args.import_nuclei)
        if p.exists():
            console.print(f"\n[bold]Import: nuclei JSONL ({p.name})[/bold]" if HAS_RICH else f"\nImport nuclei")
            nf = parse_nuclei_jsonl(p.read_text(encoding="utf-8", errors="replace"))
            all_findings.extend(nf)
            console.print(f"  Added {len(nf)} nuclei finding(s)")
        else:
            console.print(f"  [yellow]nuclei file not found: {p}[/yellow]")

    # ── Finalise ─────────────────────────────────────────────────────────────
    result.findings = all_findings
    result.passed = all_passed
    result.summary = {
        "total":    len(all_findings),
        "critical": sum(1 for f in all_findings if f.get("severity")=="Critical"),
        "high":     sum(1 for f in all_findings if f.get("severity")=="High"),
        "medium":   sum(1 for f in all_findings if f.get("severity")=="Medium"),
        "low":      sum(1 for f in all_findings if f.get("severity")=="Low"),
        "passed":   len(all_passed),
    }

    if HAS_RICH: console.rule("[bold red]FINDINGS")
    else: print(f"\n{'='*55} FINDINGS")
    for f in sorted(all_findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4)):
        print_finding(f)

    s = result.summary
    if HAS_RICH:
        console.rule("[bold green]SUMMARY")
        console.print(f"  🔴 Critical:{s['critical']}  🟠 High:{s['high']}  "
                      f"🟡 Medium:{s['medium']}  🔵 Low:{s['low']}  ✅ Passed:{s['passed']}")
    else:
        print(f"\nSUMMARY: Critical={s['critical']} High={s['high']} "
              f"Medium={s['medium']} Low={s['low']} Passed={s['passed']}")

    generate_markdown(result, md_path)
    console.print(f"\n📄 Report: {md_path}")
    if args.json:
        generate_json(result, jp)
        console.print(f"📄 JSON  : {jp}")

if __name__ == "__main__":
    main()
