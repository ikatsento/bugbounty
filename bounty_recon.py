#!/usr/bin/env python3
"""
bounty_recon.py — Bug Bounty Passive Recon & Misconfiguration Scanner
======================================================================
Version : 2.0.0
License : MIT
Inspired by AutoAR (h0tak88r/AutoAR) — Python single-file edition

Modules:
  1.  Subdomain enumeration  — crt.sh + SecurityTrails (optional)
  2.  DNS resolution          — A / CNAME / MX records
  3.  Live host detection     — HTTPS/HTTP reachability
  4.  Technology fingerprint  — Server headers, X-Powered-By, generator
  5.  Endpoint sweep          — 60+ sensitive paths, HTML FP filter
  6.  Security headers        — 9 required headers × all hosts
  7.  TLS check               — expiry, TLS 1.0/1.1, weak ciphers
  8.  CORS check              — reflected origin + Allow-Credentials
  9.  JWKS / source map       — exposure detection
  10. GitHub recon            — repo/org secret scanning (optional)
  11. S3 bucket check         — common permutations (optional)
  12. nuclei wrapper          — read-only: misconfig, headers, ssl
  13. JS secrets scan         — URL collection + regex extraction
  14. DNS takeover            — dangling CNAME detection
  15. Markdown + JSON report  — full structured output

Usage:
  python3 bounty_recon.py -t example.com
  python3 bounty_recon.py -t example.com --nuclei --js --s3 --out-dir ./reports
  python3 bounty_recon.py -t example.com --cors-origin https://bo.example.com --json
  python3 bounty_recon.py -t example.com --github-org example --github-token ghp_xxx
  python3 bounty_recon.py --help

Requirements:
  pip install httpx dnspython rich
  nuclei (optional): go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
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
VERSION  = "2.5.0"
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

# JS secret patterns (inspired by AutoAR regexes dir)
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

# Password in URL filter helpers (False Positive reduction)
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
    """Return True only if URL looks like a real credential, not a test/doc/framework string."""
    try:
        from urllib.parse import urlparse
        p = urlparse(matched_url)
        user   = (p.username or "").lower()
        passwd = (p.password or "").lower()
        host   = (p.hostname or "").lower()

        if not host:
            return False
        if host in DUMMY_HOSTS:
            return False
        if any(host.endswith("." + d) for d in DUMMY_HOSTS):
            return False
        # Reject hosts containing doc substrings (e.g. user.example.com, api.example.net)
        if any(sub in host for sub in _DUMMY_HOST_SUBSTRINGS):
            return False
        # Must have proper TLD
        parts = host.split(".")
        if len(parts) < 2 or len(parts[-1]) < 2 or parts[-1].isdigit():
            return False
        # Reject weak/dummy/template passwords
        if not passwd or len(passwd) < 6:
            return False
        if passwd in DUMMY_PASSWORDS:
            return False
        if any(m in passwd for m in ["${", "{{", "<%", "<", ">", "%s", "%d",
                                      "todo", "replace", "changeme", "xxx",
                                      "your_", "insert_", "put_your", "password"]):
            return False
        # Reject dummy users entirely
        if user in DUMMY_USERS:
            return False
        return True
    except Exception:
        return False

def mask_url_password(matched_url: str) -> str:
    try:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(matched_url)
        if p.password:
            masked_netloc = f"{p.username or ''}:*****@{p.hostname or ''}"
            if p.port:
                masked_netloc += f":{p.port}"
            return urlunparse((p.scheme, masked_netloc, p.path, p.params, p.query, p.fragment))
    except Exception:
        pass
    return matched_url[:50] + "..."

# CNAME takeover fingerprints (AutoAR-inspired)
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

# Sensitive paths to sweep
SENSITIVE_PATHS = [
    # Env / config
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.dev",
    "/config.json", "/config.yaml", "/settings.json", "/app.json",
    # Git
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/index",
    # Backups
    "/backup.sql", "/dump.sql", "/db.sqlite", "/database.sqlite", "/backup.zip",
    # Source maps
    "/main.js.map", "/app.js.map", "/bundle.js.map", "/vendor.js.map",
    "/static/js/main.chunk.js.map", "/static/js/bundle.js.map",
    # Well-known
    "/.well-known/jwks.json", "/.well-known/openid-configuration",
    "/.well-known/security.txt", "/.well-known/change-password",
    # API internals
    "/api/v1/health", "/api/v1/ready", "/api/v1/debug", "/api/v1/env",
    "/api/v1/config", "/api/v1/metrics", "/api/v1/stream/demo",
    "/api/v1/version", "/api/v1/info", "/api/v1/admin",
    "/api/health", "/api/status", "/api/debug",
    "/health", "/ready", "/status", "/ping",
    "/metrics", "/prometheus", "/debug/pprof",
    # Docs
    "/docs", "/openapi.json", "/swagger", "/swagger.json", "/swagger-ui.html",
    "/api-docs", "/redoc", "/graphql",
    # Admin panels
    "/admin", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer.php",
    "/_admin", "/_debug", "/_metrics",
    # n8n / automation specific
    "/rest/settings", "/rest/license", "/rest/owner",
    "/rest/debug", "/rest/users", "/rest/api-keys",
    "/rest/workflows", "/rest/credentials",
    # Spring Boot actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/info", "/actuator/mappings",
    # Server info
    "/server-status", "/server-info",
    # Next.js / React
    "/_next/static/", "/__webpack_hmr",
]

# Security headers to check
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

# S3 bucket name patterns
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
    if headers:
        h.update(headers)
    if HAS_HTTPX:
        try:
            r = httpx.get(url, headers=h, timeout=timeout,
                          follow_redirects=follow, verify=True)
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
    """Detect if response is a WAF challenge / block page (Cloudflare, Akamai, Imperva)."""
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
    """Audit JWT token for structural vulnerabilities (alg: none, sensitive claims, expiry)."""
    findings = []
    parts = token.strip().split(".")
    if len(parts) < 2:
        return findings
    try:
        # Base64 decode header
        hdr_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(hdr_b64).decode("utf-8", "replace"))

        # Base64 decode payload
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8", "replace"))

        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append({
                "severity": "Critical",
                "category": "jwt",
                "title": "JWT Signature Bypass: 'alg: none' accepted",
                "url": source_url,
                "evidence": f"Header: {json.dumps(header)} | Claims: {list(payload.keys())}",
                "command": f'curl -s "{source_url}" | grep -Eo "{token[:25]}"',
                "remediation": "Reject unauthenticated JWTs with 'alg: none' and enforce strong cryptographic signatures (RS256/ES256)"
            })
        elif alg.startswith("hs"):
            findings.append({
                "severity": "Info",
                "category": "jwt",
                "title": f"JWT uses symmetric HMAC ({alg.upper()}) algorithm",
                "url": source_url,
                "evidence": f"Header: {json.dumps(header)} | Key count: {len(payload)} claims",
                "command": f'curl -s "{source_url}" | grep -Eo "{token[:25]}"',
                "remediation": "Prefer asymmetric keys (RS256/ES256) so clients only verify public keys"
            })

        # Check for sensitive claims in payload
        sensitive_keys = [k for k in payload.keys() if any(w in k.lower() for w in ["pass", "secret", "priv", "email", "role", "admin"])]
        if sensitive_keys:
            findings.append({
                "severity": "Low",
                "category": "jwt",
                "title": f"JWT payload exposes internal claims: {', '.join(sensitive_keys[:4])}",
                "url": source_url,
                "evidence": f"Claims disclosed in payload: {', '.join(sensitive_keys)}",
                "command": f'curl -s "{source_url}" | grep -Eo "{token[:25]}"',
                "remediation": "Do not store confidential credentials or secrets inside unencrypted JWT payloads"
            })
    except Exception: pass
    return findings

# ── Recon Helpers: Cookie security, DNS sec, Deep Tech & OAuth ────────────────
def audit_cookie(name: str, value: str, raw_cookie_str: str, base_url: str) -> list:
    """Audit security flags of Set-Cookie header (Secure, HttpOnly, SameSite, __Host-)."""
    findings = []
    parts = [p.strip() for p in raw_cookie_str.split(";")]
    attrs = {p.split("=")[0].lower(): (p.split("=")[1] if "=" in p else True) for p in parts}

    is_session = any(k in name.lower() for k in ["sess", "auth", "token", "jwt", "id", "login", "user", "csrf"])

    # 1. Secure flag
    if "secure" not in attrs and base_url.startswith("https:"):
        findings.append({
            "severity": "Medium" if is_session else "Low",
            "category": "cookies",
            "title": f"Insecure Cookie: '{name}' lacks Secure flag",
            "url": base_url,
            "evidence": raw_cookie_str[:120],
            "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
            "remediation": "Add 'Secure' attribute so cookie is never sent over unencrypted HTTP"
        })

    # 2. HttpOnly flag for sensitive cookies
    if is_session and "httponly" not in attrs:
        findings.append({
            "severity": "Medium",
            "category": "cookies",
            "title": f"XSS Risk: Cookie '{name}' lacks HttpOnly flag",
            "url": base_url,
            "evidence": raw_cookie_str[:120],
            "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
            "remediation": "Add 'HttpOnly' attribute to prevent malicious JavaScript access via document.cookie"
        })

    # 3. SameSite attribute
    if "samesite" not in attrs:
        findings.append({
            "severity": "Low",
            "category": "cookies",
            "title": f"CSRF Risk: Cookie '{name}' lacks SameSite attribute",
            "url": base_url,
            "evidence": raw_cookie_str[:120],
            "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
            "remediation": "Set SameSite=Lax (or SameSite=Strict) explicitly"
        })

    # 4. Cookie prefix validation (__Host- and __Secure-)
    if name.startswith("__Host-"):
        if "secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs:
            findings.append({
                "severity": "Medium",
                "category": "cookies",
                "title": f"Malformed __Host- Cookie: '{name}' violates RFC 6265bis",
                "url": base_url,
                "evidence": raw_cookie_str[:120],
                "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
                "remediation": "__Host- prefix requires Secure, Path=/, and MUST NOT include Domain attribute"
            })
    elif name.startswith("__Secure-"):
        if "secure" not in attrs:
            findings.append({
                "severity": "Medium",
                "category": "cookies",
                "title": f"Malformed __Secure- Cookie: '{name}' lacks Secure flag",
                "url": base_url,
                "evidence": raw_cookie_str[:120],
                "command": f'curl -si "{base_url}" | grep -i "Set-Cookie"',
                "remediation": "__Secure- prefix requires the Secure attribute"
            })

    return findings

def audit_dns_security(domain: str) -> list:
    """Audit SPF, DMARC, CAA, and DNSSEC records for email security and spoofing protection."""
    findings = []
    if not HAS_DNS:
        return findings

    txt_records = []
    dmarc_records = []
    caa_records = []

    # Query TXT records on apex domain
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            txt_records.append(str(r).strip('"'))
    except Exception: pass

    # Query DMARC at _dmarc.domain
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            dmarc_records.append(str(r).strip('"'))
    except Exception: pass

    # Query CAA records
    try:
        for r in dns.resolver.resolve(domain, "CAA"):
            caa_records.append(str(r))
    except Exception: pass

    # 1. SPF Check
    spf = [t for t in txt_records if "v=spf1" in t]
    if not spf:
        findings.append({
            "severity": "Low",
            "category": "dns-sec",
            "title": f"DNS: Missing SPF record on {domain}",
            "url": f"dns://{domain}",
            "evidence": "No TXT record matching 'v=spf1' found",
            "command": f"dig +short TXT {domain}",
            "remediation": "Publish SPF TXT record (e.g. 'v=spf1 include:... ~all' or 'v=spf1 -all')"
        })
    elif "+all" in spf[0]:
        findings.append({
            "severity": "Medium",
            "category": "dns-sec",
            "title": f"DNS: Insecure SPF record allows any sender (+all)",
            "url": f"dns://{domain}",
            "evidence": spf[0],
            "command": f"dig +short TXT {domain}",
            "remediation": "Change +all to -all (hard fail) or ~all (soft fail)"
        })

    # 2. DMARC Check
    if not dmarc_records:
        findings.append({
            "severity": "Low",
            "category": "dns-sec",
            "title": f"DNS: Missing DMARC record on _dmarc.{domain}",
            "url": f"dns://_dmarc.{domain}",
            "evidence": f"No DMARC TXT record found at _dmarc.{domain}",
            "command": f"dig +short TXT _dmarc.{domain}",
            "remediation": "Publish DMARC record (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc@...')"
        })
    else:
        dm = dmarc_records[0]
        if "p=none" in dm:
            findings.append({
                "severity": "Info",
                "category": "dns-sec",
                "title": f"DNS: DMARC policy is monitoring only (p=none)",
                "url": f"dns://_dmarc.{domain}",
                "evidence": dm,
                "command": f"dig +short TXT _dmarc.{domain}",
                "remediation": "Transition DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'"
            })

    # 3. CAA Check
    if not caa_records:
        findings.append({
            "severity": "Info",
            "category": "dns-sec",
            "title": f"DNS: CAA record not configured for {domain}",
            "url": f"dns://{domain}",
            "evidence": "No CAA records configured",
            "command": f"dig +short CAA {domain}",
            "remediation": "Configure CAA records to specify Certificate Authorities permitted to issue certificates"
        })

    return findings

def deep_fingerprint_tech(url: str, hdrs: dict, html_text: str = "") -> list:
    """Deep passive technology fingerprinting (frameworks, CDNs, analytics, auth, UI)."""
    h = norm_headers(hdrs)
    tech = set()

    # Base signatures
    if h.get("server"): tech.add(f"Server: {h.get('server')}")
    if h.get("cf-ray") or h.get("server") == "cloudflare": tech.add("Cloudflare CDN & WAF")
    if h.get("x-vercel-id"): tech.add("Vercel Edge Platform")
    if h.get("x-amz-request-id") or "amazonaws.com" in h.get("x-amz-id-2", ""): tech.add("Amazon Web Services (AWS)")
    if h.get("x-powered-by"): tech.add(f"Powered-By: {h.get('x-powered-by')}")

    # Framework detection via HTML & Headers
    if html_text:
        if "__NEXT_DATA__" in html_text or "/_next/" in html_text:
            m = re.search(r'content=["\']Next\.js\s*([0-9\.]+)["\']', html_text)
            v = f" v{m.group(1)}" if m else ""
            tech.add(f"Next.js (React){v}")
        elif "react" in html_text.lower() or "data-reactroot" in html_text:
            tech.add("React.js")

        if "tailwind" in html_text.lower() or any(c in html_text for c in ["flex ", "grid ", "items-center", "justify-center", "bg-slate-", "text-white"]):
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
    """Extract OAuth client IDs, callbacks, and redirect parameters from JavaScript."""
    results = set()
    for m in OAUTH_REDIRECT_PATTERN.finditer(js_text):
        for g in m.groups():
            if g and len(g) > 4:
                results.add(g.strip())
    return sorted(list(results))

# ── Recon Helpers: Next.js manifest, API endpoint extraction & Playwright ───
API_ENDPOINT_PATTERN = re.compile(
    r'["\'](/(?:api|v[0-9]|rest|graphql|admin|auth|oauth|user|webhook|settings|config)[a-zA-Z0-9_\-/\.]+[\?a-zA-Z0-9_\-=&]*)["\']'
)

def extract_endpoints_from_js(text: str) -> list:
    """Extract backend API paths from JavaScript code (LinkFinder technique)."""
    endpoints = set()
    for m in API_ENDPOINT_PATTERN.finditer(text):
        path = m.group(1).strip()
        if len(path) > 4 and not path.endswith(".js") and not path.endswith(".css"):
            endpoints.add(path)
    return sorted(endpoints)

def extract_nextjs_routes_and_chunks(base_url: str, html_text: str) -> tuple:
    """Extract hidden internal routes and chunks from Next.js _buildManifest.js."""
    routes, chunks = set(), set()
    try:
        manifest_url = None
        build_id_m = re.search(r'"buildId"\s*:\s*"([a-zA-Z0-9_\-]+)"', html_text)
        if build_id_m:
            bid = build_id_m.group(1)
            manifest_url = f"{base_url.rstrip('/')}/_next/static/{bid}/_buildManifest.js"
        else:
            m = re.search(r'src=["\']([^"\']+/_buildManifest\.js[^"\']*)["\']', html_text)
            if m:
                manifest_url = urljoin(base_url, m.group(1))

        if manifest_url:
            status, _, body = http_get(manifest_url, timeout=8)
            if status == 200:
                m_text = body.decode("utf-8", "replace")
                for r in re.findall(r'["\'](/[^"\']*)["\']\s*:\s*\[', m_text):
                    if not r.startswith("/_"):
                        routes.add(r)
                for c in re.findall(r'["\'](static/chunks/[^"\']+\.js)["\']', m_text):
                    chunks.add(f"{base_url.rstrip('/')}/_next/{c}")
    except Exception:
        pass
    return sorted(routes), sorted(chunks)

def crawl_with_playwright(url: str, timeout: int = 15) -> dict:
    """Headless browser dynamic inspection via Playwright (DOM, XHR/Fetch, dynamic scripts, storage)."""
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

            # Extract dynamic scripts and links from DOM
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

# ── 1. Subdomain enumeration ──────────────────────────────────────────────────
def enum_subdomains_anubis(domain: str) -> set:
    subs = set()
    try:
        status, _, body = http_get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=10)
        if status == 200:
            for s in json.loads(body):
                s = s.strip().lower()
                if s.endswith(f".{domain}") or s == domain:
                    subs.add(s)
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
                    if host.endswith(f".{domain}") or host == domain:
                        subs.add(host)
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
                if h.endswith(f".{domain}") or h == domain:
                    subs.add(h)
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
                    if n.endswith(f".{domain}") or n == domain:
                        subs.add(n.lower())
    except Exception as e:
        console.print(f"  crt.sh error: {e}")
    return subs

def enum_subdomains_securitytrails(domain: str, api_key: str) -> set:
    subs = set()
    if not api_key: return subs
    try:
        status, _, body = http_get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": api_key}, timeout=15)
        if status == 200:
            data = json.loads(body)
            for s in data.get("subdomains", []):
                subs.add(f"{s}.{domain}")
    except Exception as e:
        console.print(f"  SecurityTrails error: {e}")
    return subs

def enum_subdomains(domain: str, api_key: str = "") -> list:
    console.print("  → crt.sh + HackerTarget + AlienVault + Anubis + RapidDNS (free passive DNS)")
    subs = enum_subdomains_crtsh(domain)
    subs |= enum_subdomains_hackertarget(domain)
    subs |= enum_subdomains_alienvault(domain)
    subs |= enum_subdomains_anubis(domain)
    subs |= enum_subdomains_rapiddns(domain)
    if api_key:
        console.print("  → SecurityTrails API")
        subs |= enum_subdomains_securitytrails(domain, api_key)
    if domain not in subs:
        subs.add(domain)
    console.print(f"  Found {len(subs)} subdomain(s)")
    return sorted(subs)

# ── 2. DNS resolution + takeover detection ────────────────────────────────────
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
                        return {
                            "host": host, "cname": cname, "service": svc,
                            "fingerprint": fingerprint,
                            "command": f'curl -si "https://{host}"',
                        }
                except Exception: pass
    return None

# ── 3. Live host detection ────────────────────────────────────────────────────
def check_live(hosts: list) -> list:
    live = []
    for host in hosts:
        for scheme in ("https","http"):
            url = f"{scheme}://{host}"
            try:
                status, hdrs, body = http_get(url, follow=True, timeout=8)
                h = norm_headers(hdrs)
                live.append({
                    "host": host, "url": url, "status": status,
                    "server": h.get("server",""),
                    "powered_by": h.get("x-powered-by",""),
                    "redirect": h.get("location",""),
                })
                break
            except Exception: continue
    return live

# ── 4. Technology fingerprint ─────────────────────────────────────────────────
def fingerprint_tech(url: str, hdrs: dict) -> list:
    h = norm_headers(hdrs)
    tech = []
    sigs = {
        "server":        h.get("server",""),
        "x-powered-by":  h.get("x-powered-by",""),
        "x-generator":   h.get("x-generator",""),
        "x-aspnet":      h.get("x-aspnet-version",""),
        "x-drupal":      h.get("x-drupal-cache",""),
        "x-wp":          h.get("x-pingback",""),
        "cf-ray":        "Cloudflare" if h.get("cf-ray") else "",
        "x-vercel":      "Vercel" if h.get("x-vercel-id") else "",
        "x-amz":         "AWS" if h.get("x-amz-request-id") else "",
    }
    for _, val in sigs.items():
        if val: tech.append(val)
    return [t for t in tech if t]

# ── 5. Endpoint sweep ─────────────────────────────────────────────────────────
def sweep_endpoints(base_url: str) -> tuple:
    findings, passed = [], []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            status, hdrs, body = http_get(url, follow=False, timeout=8)
            h = norm_headers(hdrs)
            ct = h.get("content-type","")
            if status == 200 and not is_html(ct, body):
                body_text = body[:300].decode("utf-8","replace")
                # Filter empty or trivial responses
                if len(body_text.strip()) < 5:
                    passed.append(f"{url} → 200 (empty/trivial)")
                    continue
                # Signature check for .git and .env
                if path.startswith("/.git/HEAD") and not body_text.startswith("ref:"):
                    passed.append(f"{url} → 200 (not git ref)")
                    continue
                if path.startswith("/.git/config") and "[core]" not in body_text:
                    passed.append(f"{url} → 200 (not git config)")
                    continue
                if path.startswith("/.env") and ("=" not in body_text or "{" in body_text[:50]):
                    passed.append(f"{url} → 200 (not env key=val)")
                    continue
                snippet = body_text.replace("\n"," ").strip()
                findings.append({
                    "url": url, "status": status, "content_type": ct,
                    "snippet": snippet[:180],
                    "command": f'curl -si --noproxy "*" "{url}"',
                })
            elif status == 200:
                passed.append(f"{url} → 200 html/SPA (FP)")
            elif status in (301, 302, 307, 308):
                loc = h.get("location","")
                passed.append(f"{url} → {status} (redirect to {loc[:35]})" if loc else f"{url} → {status} (redirect)")
            elif status in (401, 403):
                is_waf, waf_name = is_waf_challenge(status, hdrs, body)
                if is_waf:
                    passed.append(f"{url} → 403 (Protected by {waf_name})")
                else:
                    passed.append(f"{url} → {status} (auth/blocked)")
            else:
                passed.append(f"{url} → {status}")
        except Exception as e:
            passed.append(f"{url} → error")
    return findings, passed

# ── 6. Security headers ───────────────────────────────────────────────────────
def check_headers(base_url: str) -> tuple:
    findings, passed = [], []
    try:
        status, hdrs, _ = http_get(base_url, timeout=8)
        h = norm_headers(hdrs)
        for hdr, (sev, impact) in REQUIRED_HEADERS.items():
            val = h.get(hdr,"")
            if not val:
                findings.append({
                    "severity": sev, "header": hdr, "url": base_url,
                    "detail": impact,
                    "evidence": f"Header '{hdr}' missing from HTTP response | Impact: {impact}",
                    "command": f'curl -sI --noproxy "*" "{base_url}"',
                    "remediation": "Add via Cloudflare Transform Rule or web server config",
                })
            else:
                passed.append(f"{hdr}: {val[:60]}")
        # Weak CSP check with accurate directive parsing (no substring false positives)
        csp = h.get("content-security-policy","")
        if csp:
            curl_cmd = f'curl -sI --noproxy "*" "{base_url}" | grep -i content-security-policy'
            csp_snippet = csp if len(csp) <= 250 else csp[:247] + "..."

            # Parse directives into a dictionary: directive_name -> list of tokens
            directives = {}
            for part in csp.split(";"):
                part = part.strip()
                if part:
                    tokens = part.split()
                    if tokens:
                        directives[tokens[0].lower()] = tokens[1:]

            script_vals = directives.get("script-src", directives.get("default-src", []))
            # Detect nonce in parsed tokens AND raw CSP string (handles all quoting forms)
            has_nonce = (
                any("nonce-" in v for v in script_vals)
                or "'strict-dynamic'" in csp
                or re.search(r"'nonce-[A-Za-z0-9+/=]+'", csp) is not None
            )

            # 1. Exact match for 'unsafe-eval' in script-src (avoids false positive on 'wasm-unsafe-eval')
            has_unsafe_eval = "'unsafe-eval'" in script_vals or '"unsafe-eval"' in script_vals
            if has_unsafe_eval:
                script_dirs = [d.strip() for d in csp.split(";") if d.strip().startswith("script-src")]
                eval_ev = f"Directive: {script_dirs[0]}" if script_dirs else f"CSP Header: {csp_snippet}"
                # Downgrade to Low when nonce is present — inline execution already gated
                eval_sev  = "Low"    if has_nonce else "Medium"
                eval_note = " (nonce present — inline execution gated; eval is secondary risk)" if has_nonce else ""
                findings.append({
                    "severity": eval_sev, "header": "CSP-unsafe-eval", "url": base_url,
                    "detail": f"CSP 'unsafe-eval' in script-src — eval() execution permitted{eval_note}",
                    "evidence": eval_ev,
                    "command": curl_cmd,
                    "remediation": "Remove 'unsafe-eval'; use 'wasm-unsafe-eval' if WebAssembly is needed"
                })

            # 2. Check for 'unsafe-inline' in script-src only (avoids false positive on style-src)
            has_unsafe_inline = "'unsafe-inline'" in script_vals or '"unsafe-inline"' in script_vals
            if has_unsafe_inline:
                script_dirs = [d.strip() for d in csp.split(";") if d.strip().startswith("script-src")]
                inline_ev = f"Directive: {script_dirs[0]}" if script_dirs else f"CSP Header: {csp_snippet}"
                if has_nonce:
                    findings.append({
                        "severity": "Low", "header": "CSP-unsafe-inline-legacy", "url": base_url,
                        "detail": "CSP contains 'unsafe-inline' alongside 'nonce' / 'strict-dynamic' in script-src (effective only in legacy browsers)",
                        "evidence": inline_ev,
                        "command": curl_cmd,
                        "remediation": "Safe to keep for legacy browser compatibility, or remove if modern-only"
                    })
                else:
                    findings.append({
                        "severity": "Medium", "header": "CSP-unsafe-inline", "url": base_url,
                        "detail": "CSP 'unsafe-inline' in script-src without nonce/hash — inline script XSS possible",
                        "evidence": inline_ev,
                        "command": curl_cmd,
                        "remediation": "Use nonces or cryptographic hashes instead of 'unsafe-inline' in script-src"
                    })

            # 3. Check for wildcard in default-src
            default_vals = directives.get("default-src", [])
            if "*" in default_vals or re.search(r"default-src\s+\*", csp):
                findings.append({
                    "severity": "High", "header": "CSP-wildcard", "url": base_url,
                    "detail": "CSP default-src is wildcard (*) — CSP defeated",
                    "evidence": f"CSP Header: {csp_snippet}",
                    "command": curl_cmd,
                    "remediation": "Lock to specific origins"
                })
        # Server version disclosure
        server = h.get("server","")
        if server and any(c.isdigit() for c in server):
            findings.append({"severity":"Low","header":"server-version","url":base_url,
                "detail":f"Server version disclosed: {server}",
                "evidence":f"Server header value: {server}",
                "command":f'curl -sI "{base_url}"',
                "remediation":"Strip or genericise the Server header"})
    except Exception as e:
        passed.append(f"Header check error: {e}")
    return findings, passed

# ── 7. TLS check ─────────────────────────────────────────────────────────────
def check_tls(host: str) -> tuple:
    findings, passed = [], []
    # Expiry + cipher
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
                            "detail":f"Certificate expires in {days} days ({not_after})",
                            "command":f"echo | openssl s_client -connect {host}:443 2>/dev/null | openssl x509 -noout -dates"})
                    else:
                        passed.append(f"TLS cert valid {days} days")
                cipher = s.cipher()
                passed.append(f"Cipher: {cipher[0]} / {cipher[1]}")
                # Check for weak ciphers
                if cipher[0] and any(w in cipher[0].upper() for w in ["RC4","DES","NULL","EXPORT","MD5"]):
                    findings.append({"severity":"High","check":"weak-cipher","host":host,
                        "detail":f"Weak cipher in use: {cipher[0]}","command":"",
                        "remediation":"Disable weak ciphers in TLS config"})
    except Exception as e:
        passed.append(f"TLS check error: {e}")

    # Legacy TLS
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
                            "remediation":"Set Cloudflare minimum TLS to 1.2"})
            except ssl.SSLError:
                passed.append(f"{ver_name}: rejected ✓")
            except Exception as e:
                passed.append(f"{ver_name}: {e}")
    return findings, passed

# ── 8. CORS check ─────────────────────────────────────────────────────────────
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
                    "detail":"CORS wildcard (*) — public endpoint, no credentials allowed",
                    "evidence":f"ACAO: {acao}",
                    "command":f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation":"Restrict allowed origins explicitly if sensitive data is returned"})
            elif origin in acao and "true" in acac.lower():
                findings.append({"origin":origin,"severity":"High","url":base_url,
                    "detail":"CORS reflects origin with Allow-Credentials:true",
                    "evidence":f"ACAO: {acao} | ACAC: {acac}",
                    "command":f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation":"Remove Allow-Credentials or use token-based auth"})
            elif origin in acao:
                findings.append({"origin":origin,"severity":"Low","url":base_url,
                    "detail":"CORS reflects custom origin (no credentials)",
                    "evidence":f"ACAO: {acao}",
                    "command":f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation":"Restrict to known origins"})
        except Exception: pass
    return findings

# ── 9. JWKS / source map exposure ────────────────────────────────────────────
def check_exposures(base_url: str) -> list:
    findings = []
    checks = [
        ("/.well-known/jwks.json",           "Info",     "JWKS endpoint exposed (RFC 7517 public keys — normal behavior)"),
        ("/.well-known/openid-configuration","Info",     "OIDC config endpoint exposed (RFC 8414 discovery — normal behavior)"),
        ("/main.js.map",                     "Medium",   "Webpack source map exposed"),
        ("/app.js.map",                      "Medium",   "Webpack source map exposed"),
        ("/static/js/bundle.js.map",         "Medium",   "Webpack source map exposed"),
        ("/.git/HEAD",                       "Critical", "Git repository HEAD exposed — repo may be downloadable"),
        ("/.git/config",                     "Critical", "Git config file exposed"),
    ]
    for path, sev, title in checks:
        url = base_url.rstrip("/") + path
        try:
            status, hdrs, body = http_get(url, follow=False, timeout=8)
            h = norm_headers(hdrs); ct = h.get("content-type","")
            if status == 200 and not is_html(ct, body):
                body_text = body[:300].decode("utf-8","replace")
                if path == "/.git/HEAD" and not body_text.startswith("ref:"):
                    continue
                if path == "/.git/config" and "[core]" not in body_text:
                    continue
                if len(body_text.strip()) == 0:
                    continue
                snippet = body_text.replace("\n"," ").strip()
                findings.append({
                    "severity":sev,"title":title,"url":url,"content_type":ct,
                    "snippet":snippet[:150],
                    "command":f'curl -si --noproxy "*" "{url}"',
                    "remediation":"Block at Cloudflare WAF (URI path filter) or remove from webroot",
                })
        except Exception: pass
    return findings

# ── 10. GitHub recon ─────────────────────────────────────────────────────────
def github_scan_repo(owner_repo: str, token: str) -> list:
    """Search a repo for hardcoded secrets via GitHub Code Search API."""
    findings = []
    if not token:
        return [{"detail":"GitHub token required (--github-token)"}]
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    patterns = ["password", "secret", "api_key", "apikey", "token", "ACCESS_KEY"]
    for pat in patterns[:5]:  # rate-limit safe
        try:
            url = f"https://api.github.com/search/code?q={pat}+repo:{owner_repo}"
            status, _, body = http_get(url, headers=headers, timeout=10)
            if status == 200:
                data = json.loads(body)
                total = data.get("total_count",0)
                if total > 0:
                    findings.append({
                        "severity":"High","pattern":pat,
                        "total_matches":total,"repo":owner_repo,
                        "detail":f"Found {total} matches for '{pat}' in {owner_repo}",
                        "command":f"gh search code '{pat}' --repo {owner_repo}",
                    })
        except Exception as e:
            findings.append({"detail":f"GitHub API error: {e}"})
    return findings

# ── 11. S3 bucket check ───────────────────────────────────────────────────────
def check_s3_buckets(domain: str) -> list:
    findings = []
    buckets = s3_permutations(domain)
    for bucket in buckets[:20]:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            status, _, body = http_get(url, timeout=5)
            snippet = body[:200].decode("utf-8","replace")
            if status == 200:
                findings.append({
                    "severity":"Critical","bucket":bucket,
                    "detail":f"S3 bucket publicly readable: {bucket}",
                    "snippet":snippet[:100],
                    "command":f'curl -si "{url}"',
                    "remediation":"Set bucket ACL to private; use bucket policy to restrict access",
                })
            elif status == 403:
                findings.append({
                    "severity":"Info","bucket":bucket,
                    "detail":f"S3 bucket exists but access denied: {bucket}",
                    "command":f'curl -si "{url}"',
                })
        except Exception: pass
    return findings

# ── 12. JS secrets scan ───────────────────────────────────────────────────────
def collect_js_urls(base_url: str) -> tuple:
    js_urls = set()
    routes = set()
    try:
        _, _, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8", "replace")
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', text):
            src = m.group(1)
            if src.startswith("http"):
                js_urls.add(src)
            elif src.startswith("//"):
                js_urls.add("https:" + src)
            elif src.startswith("/"):
                p = urlparse(base_url)
                js_urls.add(f"{p.scheme}://{p.netloc}{src}")
        nxt_routes, nxt_chunks = extract_nextjs_routes_and_chunks(base_url, text)
        routes.update(nxt_routes)
        js_urls.update(nxt_chunks)
    except Exception: pass
    return sorted(list(js_urls))[:60], sorted(list(routes))

def scan_js_secrets(js_url: str) -> tuple:
    secrets = []
    endpoints = []
    try:
        status, _, body = http_get(js_url, timeout=10)
        if status != 200: return secrets, endpoints
        text = body.decode("utf-8","replace")

        # LinkFinder API endpoint extraction
        endpoints = extract_endpoints_from_js(text)

        for name, pattern in JS_SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if not matches:
                continue

            if name == "Password in URL":
                valid_matches = [m for m in matches if is_valid_secret_url(m)]
                if not valid_matches:
                    continue
                matches = valid_matches
                sample = mask_url_password(matches[0])
            else:
                sample = matches[0][:60]

            # Detailed JWT auditing
            if name == "JWT Token":
                for token_match in matches[:3]:
                    for jf in audit_jwt_token(token_match, js_url):
                        secrets.append({
                            "severity": jf["severity"],
                            "type": jf["type"],
                            "url": js_url,
                            "detail": jf["detail"],
                            "sample": token_match[:40] + "...",
                            "command": jf["command"],
                            "remediation": jf["remediation"]
                        })

            secrets.append({
                "severity":"Critical" if name not in ("JWT Token", "Firebase URL") else "Info",
                "type":name,"url":js_url,
                "detail":f"{len(matches)} match(es) of '{name}' pattern",
                "sample":sample,
                "command":f'curl -s "{js_url}" | grep -Eo "{pattern[:40]}"',
                "remediation":"Rotate secret immediately; remove from client-side code",
            })
    except Exception: pass
    return secrets, endpoints

# ── 13. nuclei wrapper ───────────────────────────────────────────────────────
def run_nuclei(target: str, out_dir: Path) -> list:
    findings = []
    nuclei_path = subprocess.run(["which","nuclei"], capture_output=True, text=True).stdout.strip()
    if not nuclei_path:
        return [{"error":"nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}]
    out_file = out_dir / "nuclei_output.jsonl"
    cmd = [
        nuclei_path, "-u", target,
        "-tags", "misconfig,exposure,config,headers,ssl,file,token,generic",
        "-severity", "critical,high,medium,info",
        "-jsonl", "-o", str(out_file),
        "-silent", "-no-interactsh",
        "-rl", "50", "-c", "10",  # rate limit: 50 req/s, 10 concurrent
    ]
    try:
        subprocess.run(cmd, timeout=240, capture_output=True)
        if out_file.exists():
            for line in out_file.read_text().splitlines():
                try:
                    n = json.loads(line)
                    findings.append({
                        "severity": n.get("info",{}).get("severity","info").capitalize(),
                        "category": "nuclei",
                        "title":    n.get("info",{}).get("name","nuclei finding"),
                        "url":      n.get("matched-at", target),
                        "detail":   n.get("info",{}).get("description",""),
                        "command":  f"nuclei -u {target} -id {n.get('template-id','')}",
                        "remediation": n.get("info",{}).get("remediation",""),
                    })
                except Exception: pass
    except subprocess.TimeoutExpired:
        findings.append({"error":"nuclei timed out (240s)"})
    except Exception as e:
        findings.append({"error": str(e)})
    return findings

# ── 13b. External tool output parsers ────────────────────────────────────────

def parse_dalfox_output(text: str, min_confidence: float = 0.8) -> list:
    """
    Parse Dalfox text output into structured findings.
    Deduplicates by parameter name, keeps only confidence >= min_confidence.
    Groups multiple payloads per parameter into a single finding.
    """
    findings = []
    # Pattern: each result block starts with a numbered line like "(1) param [TYPE]"
    block_re  = re.compile(
        r'\((\d+)\)\s+(\S+)\s+\[(\w+)\]\s*\n'
        r'.*?url\s*:\s*(\S+)\s*\n'
        r'.*?context\s*:\s*(\S+)\s*\n'
        r'.*?payload\s*:\s*(.+?)\s*\n'
        r'.*?confidence\s*:\s*([\d.]+)',
        re.DOTALL
    )
    # Group by parameter name to deduplicate
    by_param: dict = {}
    for m in block_re.finditer(text):
        idx, param, method, url, ctx, payload, conf_str = m.groups()
        try:
            conf = float(conf_str)
        except ValueError:
            conf = 0.0
        if conf < min_confidence:
            continue
        key = param.lower()
        if key not in by_param:
            by_param[key] = {
                "param": param, "method": method, "url": url,
                "context": ctx, "confidence": conf,
                "payloads": [], "poc_urls": [],
            }
        by_param[key]["payloads"].append(payload.strip())
        by_param[key]["confidence"] = max(by_param[key]["confidence"], conf)
        # Extract PoC URL from the block
        poc_m = re.search(r'poc\s*:\s*(\S+)', m.group(0))
        if poc_m:
            by_param[key]["poc_urls"].append(poc_m.group(1))

    for key, info in by_param.items():
        param    = info["param"]
        method   = info["method"]
        url_base = info["url"].split("?")[0]
        ctx      = info["context"]
        conf     = info["confidence"]
        n_pay    = len(info["payloads"])
        poc      = info["poc_urls"][0] if info["poc_urls"] else info["url"]

        # Confidence → severity mapping
        if conf >= 1.4:
            sev = "High"
        elif conf >= 1.0:
            sev = "Medium"
        else:
            sev = "Low"

        findings.append({
            "severity":    sev,
            "category":    "xss-dalfox",
            "title":       f"DOM XSS — parameter '{param}' [{method}] (confidence {conf:.2f})",
            "url":         url_base,
            "evidence":    (
                f"Parameter: {param} | Method: {method} | Context: {ctx}\n"
                f"Confidence: {conf:.2f} | Payloads found: {n_pay}\n"
                f"Sample payload: {info['payloads'][0][:120]}"
            ),
            "command":     f'# Reproduce in browser:\n# {poc}',
            "remediation": (
                "Sanitise/escape all query-parameter values before writing to DOM. "
                "Use textContent instead of innerHTML. "
                "Enforce a strict CSP with nonces (removes unsafe-inline)."
            ),
        })

    return findings


def parse_nuclei_jsonl(text: str) -> list:
    """Parse nuclei -jsonl output into structured findings."""
    findings = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            n = json.loads(line)
        except Exception:
            continue
        tid  = n.get("template-id", "")
        murl = n.get("matched-at", "")
        key  = f"{tid}:{murl}"
        if key in seen:
            continue
        seen.add(key)
        info = n.get("info", {})
        sev  = info.get("severity", "info").capitalize()
        # Normalise nuclei "info" → "Info"
        if sev.lower() == "info":
            sev = "Info"
        findings.append({
            "severity":    sev,
            "category":    "nuclei",
            "title":       info.get("name", tid),
            "url":         murl,
            "evidence":    (
                info.get("description", "")[:200]
                + (f"\nExtracted: {n.get('extracted-results', '')}" if n.get("extracted-results") else "")
            ),
            "command":     f"nuclei -u {murl.split('?')[0]} -id {tid}",
            "remediation": info.get("remediation", ""),
        })
    return findings


# ── 13c. CVE Fingerprint Detection (passive, read-only, no exploitation) ──────
#
# Sources: Oracle-Security/CVEs repo fingerprints (detection only)
# Each check probes a URL and matches version/banner strings.
# NOTHING is sent that modifies state or exploits the vulnerability.

CVE_CHECKS = [
    # ── ConnectWise ScreenConnect CVE-2024-1709 (auth bypass / SetupWizard) ───
    {
        "cve":     "CVE-2024-1709",
        "product": "ConnectWise ScreenConnect",
        "severity":"Critical",
        "paths":   ["/SetupWizard.aspx", "/SetupWizard.aspx/"],
        "match":   ["SetupWizard", "ScreenConnect", "connectwise"],
        "detail":  "ConnectWise ScreenConnect SetupWizard endpoint exposed — CVE-2024-1709 (auth bypass, CVSS 10.0)",
        "remediation": "Upgrade ScreenConnect to 23.9.8 or later immediately. Block /SetupWizard.aspx at edge.",
    },
    # ── N-Central N-Able — MMS2/MMS3 service exposure ─────────────────────────
    {
        "cve":     "N-Central 0-Day (Oracle-Security)",
        "product": "N-Central N-Able",
        "severity":"Critical",
        "paths":   ["/dms2/services/", "/dms/services/ServerMMS2", "/mms3/", "/dms2/"],
        "match":   ["ServerMMS", "N-central", "N-able", "ncentral", "nable"],
        "detail":  "N-Central N-Able MMS service endpoint exposed — multiple unauthenticated RCE 0-days known (Oracle-Security research, unpatched as of 2026)",
        "remediation": "Restrict MMS endpoints to internal/WARP only. Apply latest N-Central patches.",
    },
    # ── N-Central N-Able — password reset account enumeration ─────────────────
    {
        "cve":     "N-Central 0-Day — Account Enumeration",
        "product": "N-Central N-Able",
        "severity":"Medium",
        "paths":   ["/login", "/dms2/services/ServerEI2", "/serverLogin.jnlp"],
        "match":   ["N-central", "serverLogin", "ServerEI2", "N-able"],
        "detail":  "N-Central login/reset endpoint exposed — anonymous account enumeration via password reset differential",
        "remediation": "Restrict login endpoints. Ensure password reset returns identical responses for valid/invalid accounts.",
    },
    # ── IBM HMC CVE-2026-12943 (unauth RCE) ───────────────────────────────────
    {
        "cve":     "CVE-2026-12943",
        "product": "IBM Hardware Management Console (HMC)",
        "severity":"Critical",
        "paths":   ["/cgi-bin/cgi", "/cgi-bin/cgi?form=H_FW_UPGRADE_OLD",
                    "/cgi-bin/cgi?form=H_Login_OLD"],
        "match":   ["Hardware Management Console", "HMC", "IBM Power",
                    "H_FW_UPGRADE", "H_Login"],
        "detail":  "IBM HMC CGI interface exposed — CVE-2026-12943 unauthenticated RCE (hmcgopher)",
        "remediation": "Restrict HMC web interface to management network. Apply IBM security advisory for CVE-2026-12943.",
    },
    # ── IBM Novalink service exposure ─────────────────────────────────────────
    {
        "cve":     "IBM Novalink 0-Day (Oracle-Security)",
        "product": "IBM PowerVM Novalink",
        "severity":"Critical",
        "paths":   ["/api/v1/", "/api/v1/lpars", "/api/v1/info"],
        "match":   ["novalink", "PowerVM", "IBM PowerVM", "prsm"],
        "detail":  "IBM PowerVM Novalink REST API exposed — multiple unauthenticated RCE 0-days (eyeCatcher, mobcod, getremote — Oracle-Security research)",
        "remediation": "Restrict Novalink REST API to management VLAN only. Apply latest firmware.",
    },
    # ── DotNetNuke CVE-2018-14486 ─────────────────────────────────────────────
    {
        "cve":     "CVE-2018-14486",
        "product": "DotNetNuke (DNN)",
        "severity":"High",
        "paths":   ["/DesktopModules/", "/Portals/", "/DesktopModules/DNNspot-Store/"],
        "match":   ["DotNetNuke", "DNN Platform", "X-Powered-By: DNN",
                    "DesktopModules", "__dnnVariable"],
        "detail":  "DotNetNuke installation detected — CVE-2018-14486 XSS/injection vulnerabilities",
        "remediation": "Upgrade DNN to latest version. Apply security patches.",
    },
    # ── WordPress vulnerable plugins ──────────────────────────────────────────
    {
        "cve":     "CVE-2023-5204",
        "product": "WordPress Chatbot Plugin",
        "severity":"High",
        "paths":   ["/wp-content/plugins/chatbot/", "/wp-json/chatbot/v1/"],
        "match":   ["chatbot", "wp-chatbot"],
        "detail":  "WordPress Chatbot plugin detected — CVE-2023-5204 (SQL injection / privilege escalation)",
        "remediation": "Update chatbot plugin to latest version or remove if unused.",
    },
    {
        "cve":     "CVE-2023-6737",
        "product": "WordPress Enable Media Replace Plugin",
        "severity":"High",
        "paths":   ["/wp-content/plugins/enable-media-replace/",
                    "/wp-content/plugins/enable-media-replace/readme.txt"],
        "match":   ["enable-media-replace", "Enable Media Replace"],
        "detail":  "WordPress Enable Media Replace plugin detected — CVE-2023-6737 (authenticated arbitrary file upload → RCE)",
        "remediation": "Update enable-media-replace plugin to 4.1.4 or later.",
    },
    {
        "cve":     "CVE-2023-49833",
        "product": "WordPress Spectra Plugin",
        "severity":"Medium",
        "paths":   ["/wp-content/plugins/ultimate-addons-for-gutenberg/",
                    "/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt"],
        "match":   ["ultimate-addons-for-gutenberg", "Spectra", "Brainstorm Force"],
        "detail":  "WordPress Spectra (Ultimate Addons for Gutenberg) detected — CVE-2023-49833 (XSS)",
        "remediation": "Update Spectra plugin to latest version.",
    },
    {
        "cve":     "CVE-2023-38826 / CVE-2023-38827",
        "product": "Follett Destiny Library Manager",
        "severity":"Critical",
        "paths":   ["/common/", "/common/static/", "/destiny/", "/logon.jsp"],
        "match":   ["Destiny", "Follett", "Library Manager", "destiny/logon"],
        "detail":  "Follett Destiny Library Manager detected — CVE-2023-38826/38827 (unauthenticated RCE via SSRF+deserialization)",
        "remediation": "Apply Follett security patches immediately. Restrict access to known IP ranges.",
    },
    # ── QStar Archive Solutions ────────────────────────────────────────────────
    {
        "cve":     "CVE-2023-51062 through CVE-2023-51071",
        "product": "QStar Archive Solutions",
        "severity":"Critical",
        "paths":   ["/api/", "/qstar/", "/archivemanager/"],
        "match":   ["QStar", "Archive Manager", "qstar"],
        "detail":  "QStar Archive Solutions interface detected — CVE-2023-51062 through 51071 (multiple auth bypass and RCE)",
        "remediation": "Apply QStar security patches. Restrict management interface to internal network.",
    },
    # ── Generic tech exposure checks ──────────────────────────────────────────
    {
        "cve":     "INFO — phpMyAdmin exposed",
        "product": "phpMyAdmin",
        "severity":"High",
        "paths":   ["/phpmyadmin/", "/pma/", "/phpMyAdmin/", "/db/"],
        "match":   ["phpMyAdmin", "pma_username", "PMA_VERSION"],
        "detail":  "phpMyAdmin panel publicly accessible — direct database access possible",
        "remediation": "Restrict phpMyAdmin to localhost or management IP only. Use SSH tunnel.",
    },
    {
        "cve":     "INFO — Exposed admin panel",
        "product": "Generic Admin Panel",
        "severity":"Medium",
        "paths":   ["/admin/", "/admin/login", "/admin/dashboard",
                    "/_admin/", "/administrator/"],
        "match":   ["admin panel", "administration", "dashboard", "login"],
        "detail":  "Admin panel endpoint publicly accessible",
        "remediation": "Restrict admin panel to internal network or VPN. Add IP allowlist.",
    },
    {
        "cve":     "INFO — Spring Boot Actuator exposed",
        "product": "Spring Boot Actuator",
        "severity":"High",
        "paths":   ["/actuator/env", "/actuator/mappings", "/actuator/beans"],
        "match":   ["spring", "actuator", "activeProfiles", "classLoader"],
        "detail":  "Spring Boot Actuator env endpoint exposed — discloses environment variables and configuration",
        "remediation": "Disable Actuator in production or restrict to management port with IP allowlist.",
    },
]


def check_cve_fingerprints(base_url: str) -> list:
    """
    Passive CVE fingerprint detection.
    Probes known paths and matches response content against version/banner strings.
    No payloads sent — detection only.
    """
    findings = []
    base = base_url.rstrip("/")

    for check in CVE_CHECKS:
        matched_url  = None
        matched_on   = None
        matched_body = ""

        for path in check["paths"]:
            url = base + path
            try:
                status, hdrs, body = http_get(url, follow=False, timeout=8)
                h = norm_headers(hdrs)
                ct = h.get("content-type", "")
                # Skip HTML SPA catch-alls
                if status == 200 and is_html(ct, body):
                    # Still check body for fingerprint keywords
                    decoded = body[:4000].decode("utf-8", errors="replace").lower()
                elif status in (200, 401, 403):
                    decoded = body[:4000].decode("utf-8", errors="replace").lower()
                else:
                    decoded = ""

                # Check headers too
                header_str = " ".join(f"{k}: {v}" for k, v in h.items()).lower()
                combined   = decoded + " " + header_str

                for keyword in check["match"]:
                    if keyword.lower() in combined:
                        matched_url  = url
                        matched_on   = keyword
                        matched_body = decoded[:200].replace("\n", " ").strip()
                        break
                if matched_url:
                    break
            except Exception:
                continue

        if matched_url:
            findings.append({
                "severity":    check["severity"],
                "category":    "cve-fingerprint",
                "title":       f"{check['cve']} — {check['product']}",
                "url":         matched_url,
                "evidence":    (
                    f"Fingerprint match: '{matched_on}'\n"
                    f"URL: {matched_url}\n"
                    f"Body snippet: {matched_body[:150]}"
                ),
                "command":     f'curl -si "{matched_url}"',
                "remediation": check["remediation"],
            })

    return findings


# ── 14. Report generation ─────────────────────────────────────────────────────
def generate_markdown(result: ScanResult, out_path: Path):
    sev_counts = {}
    for f in result.findings:
        s = f.get("severity","Info")
        sev_counts[s] = sev_counts.get(s,0) + 1

    lines = [
        f"# Bounty Recon Report — {result.target}",
        f"",
        f"| | |",
        f"|---|---|",
        f"| **Generated** | {result.timestamp} |",
        f"| **Tool** | bounty_recon.py v{VERSION} |",
        f"| **Vantage** | Open internet, no proxy, read-only |",
        f"",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["Critical","High","Medium","Low","Info"]:
        c = sev_counts.get(sev,0)
        lines.append(f"| {SEV_EMOJI.get(sev,'')} **{sev}** | {c} |")
    lines += [f"| ✅ Passed | {len(result.passed)} |",""]

    if result.subdomains:
        lines += ["## Discovered Subdomains",""]
        for s in result.subdomains[:50]:
            lines.append(f"- `{s}`")
        if len(result.subdomains) > 50:
            lines.append(f"- *... and {len(result.subdomains)-50} more*")
        lines += [""]

    if result.live_hosts:
        lines += ["## Live Hosts","",
                  "| URL | Status | Server |",
                  "|-----|--------|--------|"]
        for h in result.live_hosts:
            lines.append(f"| `{h['url']}` | {h['status']} | `{h.get('server','?')}` |")
        lines += [""]

    if result.technologies:
        lines += ["## Technologies Detected",""]
        for host, techs in result.technologies.items():
            lines.append(f"- `{host}`: {', '.join(techs)}")
        lines += [""]

    if result.routes:
        lines += ["## Discovered Application Routes (Next.js / Manifest)",""]
        for r in result.routes[:40]:
            lines.append(f"- `{r}`")
        if len(result.routes) > 40:
            lines.append(f"- *... and {len(result.routes)-40} more*")
        lines += [""]

    if result.endpoints:
        lines += ["## Discovered API Endpoints (LinkFinder Extraction)",""]
        for ep in result.endpoints[:50]:
            lines.append(f"- `{ep}`")
        if len(result.endpoints) > 50:
            lines.append(f"- *... and {len(result.endpoints)-50} more*")
        lines += [""]

    if getattr(result, "oauth_params", None):
        lines += ["## OAuth Callbacks & Redirect Targets Discovered",""]
        for oa in result.oauth_params[:40]:
            lines.append(f"- `{oa}`")
        if len(result.oauth_params) > 40:
            lines.append(f"- *... and {len(result.oauth_params)-40} more*")
        lines += [""]

    lines += ["## Findings",""]
    sorted_f = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.get("severity","Info"),4))
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity","Info")
        title = f.get("title") or f.get("detail") or f.get("header","") or "Finding"
        url   = f.get("url") or f.get("host","")
        lines += [
            f"### {i}. {SEV_EMOJI.get(sev,'')} [{sev}] {title}",
            "",
            f"**Severity:** {sev}  ",
        ]
        if url: lines.append(f"**Target:** `{url}`  ")
        ev = f.get("evidence") or f.get("snippet") or f.get("detail","")
        if ev:
            lines += ["**Evidence:**","```",ev[:300],"```"]
        if f.get("command"):
            lines += ["**Reproduce:**","```bash",f["command"],"```"]
        if f.get("remediation"):
            lines.append(f"**Remediation:** {f['remediation']}")
        lines += [""]

    lines += ["## Passed Checks","","```"]
    lines += result.passed[:80]
    lines += ["```","",
              "---",
              f"*bounty_recon.py v{VERSION} — read-only passive scanner — use on authorised targets only*"]

    out_path.write_text("\n".join(lines), encoding="utf-8")

def generate_json(result: ScanResult, out_path: Path):
    out_path.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")

# ── Terminal output ───────────────────────────────────────────────────────────
def print_finding(f: dict):
    sev = f.get("severity","Info")
    em  = SEV_EMOJI.get(sev,"⚪")
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
    ap.add_argument("-t","--target",         required=True, help="Target domain (e.g. example.com)")
    ap.add_argument("--url",                 help="Override base URL for scanning")
    ap.add_argument("--cors-origin",         action="append", default=[], dest="cors_origins",
                                             help="Extra CORS origin to test (repeatable)")
    ap.add_argument("--nuclei",              action="store_true", help="Run nuclei (must be installed)")
    ap.add_argument("--js",                  action="store_true", help="Scan JavaScript files for secrets & API endpoints")
    ap.add_argument("--playwright",          action="store_true", help="Use headless Playwright browser to crawl dynamic SPA & capture API calls")
    ap.add_argument("--s3",                  action="store_true", help="Check S3 bucket permutations")
    ap.add_argument("--github-repo",         help="GitHub repo to scan for secrets (owner/repo)")
    ap.add_argument("--github-org",          help="GitHub org to scan for secrets")
    ap.add_argument("--github-token",        default=os.environ.get("GITHUB_TOKEN",""),
                                             help="GitHub personal access token (or set GITHUB_TOKEN env)")
    ap.add_argument("--securitytrails-key",  default=os.environ.get("SECURITYTRAILS_API_KEY",""),
                                             help="SecurityTrails API key for subdomain enum")
    ap.add_argument("--no-subdomains",       action="store_true", help="Skip subdomain enumeration")
    ap.add_argument("--out",                 default="", help="Output file stem")
    ap.add_argument("--out-dir",             default=".", help="Output directory (default: .)")
    ap.add_argument("--json",                action="store_true", help="Write JSON report")
    ap.add_argument("--cve",                 action="store_true",
                                             help="Run CVE fingerprint detection (passive, no exploitation)")
    ap.add_argument("--import-dalfox",       default="", dest="import_dalfox",
                                             help="Import Dalfox output file (text) and add XSS findings to report")
    ap.add_argument("--import-nuclei",       default="", dest="import_nuclei",
                                             help="Import nuclei JSONL output file and add findings to report")
    ap.add_argument("--min-confidence",      type=float, default=0.8, dest="min_confidence",
                                             help="Minimum confidence score for Dalfox findings (default: 0.8)")
    args = ap.parse_args()

    domain   = args.target.replace("https://","").replace("http://","").split("/")[0]
    base_url = args.url or f"https://{domain}"
    out_dir  = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem     = args.out or f"{domain.replace('.','_')}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M')}"
    md_path  = out_dir / f"{stem}.md"
    jp       = out_dir / f"{stem}.json"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    if HAS_RICH:
        console.print(Panel(
            f"[bold cyan]bounty_recon.py[/bold cyan] v{VERSION}\n"
            f"Target  : [bold]{domain}[/bold]\n"
            f"Base URL: {base_url}\n"
            f"nuclei={args.nuclei}  js={args.js}  playwright={args.playwright}  s3={args.s3}",
            title="🔍 Bug Bounty Passive Recon"))
    else:
        print(f"\n{'='*55}\nbounty_recon.py v{VERSION} | {domain}\n{'='*55}")

    # ── 1. Subdomains ─────────────────────────────────────────────────────────
    if not args.no_subdomains:
        console.print("\n[bold]1. Subdomain Enumeration[/bold]" if HAS_RICH else "\n1. Subdomain Enumeration")
        subs = enum_subdomains(domain, args.securitytrails_key)
        result.subdomains = subs
    else:
        result.subdomains = [domain]

    # ── 2. DNS + takeover ─────────────────────────────────────────────────────
    console.print("\n[bold]2. DNS Resolution + Takeover Check[/bold]" if HAS_RICH else "\n2. DNS + Takeover")
    dns_records = resolve_dns(result.subdomains[:40])
    result.dns_records = dns_records
    for host, rec in list(dns_records.items())[:10]:
        s = "✓ live" if rec["live"] else "✗ dead"
        console.print(f"  {s} {host} A={rec['A'][:2]} CNAME={rec['CNAME'][:1]}")
        # Takeover check
        if rec["CNAME"]:
            to = check_dns_takeover(host, rec["CNAME"])
            if to:
                all_findings.append({
                    "severity":"Critical","category":"dns-takeover",
                    "title":f"DNS takeover — {to['service']}",
                    "url":f"https://{host}",
                    "detail":f"CNAME {to['cname']} points to unclaimed {to['service']}",
                    "evidence":f"Fingerprint: '{to['fingerprint']}'",
                    "command":to["command"],
                    "remediation":"Claim the service or remove the dangling CNAME record",
                })

    # DNS Security Audit (SPF, DMARC, CAA)
    console.print("  → Auditing DNS security policies (SPF, DMARC, CAA)")
    for df in audit_dns_security(domain):
        all_findings.append(df)
        if HAS_RICH:
            console.print(f"    {SEV_EMOJI.get(df['severity'],'⚪')} [bold]{df['title']}[/bold]")
        else:
            print(f"    [{df['severity']}] {df['title']}")

    # ── 3. Live hosts + tech ──────────────────────────────────────────────────
    console.print("\n[bold]3. Live Host Detection + Tech[/bold]" if HAS_RICH else "\n3. Live Hosts")
    candidate = [h for h,r in dns_records.items() if r["live"]] or [domain]
    live = check_live(candidate[:20])
    result.live_hosts = live
    console.print(f"  {len(live)} live host(s)" if HAS_RICH else f"  {len(live)} live hosts")
    for lh in live:
        h_resp = {}
        html_body = ""
        try:
            _, h_resp, raw_b = http_get(lh["url"], timeout=6)
            html_body = raw_b.decode("utf-8", "replace")
        except: pass
        techs = deep_fingerprint_tech(lh["url"], h_resp, html_body)
        if techs:
            result.technologies[lh["host"]] = techs
            console.print(f"  {lh['host']}: {', '.join(techs)}")

    scan_urls = list({h["url"] for h in live}) or [base_url]
    primary   = args.url or scan_urls[0]

    # ── 4. Endpoint sweep ─────────────────────────────────────────────────────
    console.print("\n[bold]4. Sensitive Endpoint Sweep[/bold]" if HAS_RICH else "\n4. Endpoint Sweep")
    for url in scan_urls[:5]:
        ep_f, ep_p = sweep_endpoints(url)
        for f in ep_f:
            all_findings.append({
                "severity":"High","category":"exposure",
                "title":f"Sensitive endpoint exposed: {f['url'].split('/')[-1] or '(root)'}",
                "url":f["url"],"command":f["command"],
                "evidence":f"HTTP 200 | {f['content_type']} | {f['snippet'][:100]}",
                "remediation":"Restrict to cluster-internal or add authentication",
            })
        all_passed.extend(ep_p)
    console.print(f"  {sum(1 for f in all_findings if f.get('category')=='exposure')} real exposures")

    # ── 5. Security headers & Cookie Audit ─────────────────────────────────────
    console.print("\n[bold]5. Security Headers & Cookie Audit[/bold]" if HAS_RICH else "\n5. Security Headers & Cookies")
    for url in scan_urls[:5]:
        hf, hp = check_headers(url)
        for f in hf:
            all_findings.append({
                "severity":f["severity"],"category":"headers",
                "title":f"Header issue: {f['header']}",
                "url":f.get("url",url),"command":f.get("command",""),
                "evidence":f.get("evidence") or f.get("detail",""),
                "remediation":f.get("remediation",""),
            })
        all_passed.extend(hp)

        # Cookie security audit
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

    # ── 6. TLS ────────────────────────────────────────────────────────────────
    console.print("\n[bold]6. TLS Check[/bold]" if HAS_RICH else "\n6. TLS")
    tls_hosts = list({u.split("://")[1].split("/")[0] for u in scan_urls if "https" in u}) or [domain]
    for host in tls_hosts[:5]:
        tf, tp = check_tls(host)
        for f in tf:
            all_findings.append({
                "severity":f["severity"],"category":"tls",
                "title":f"TLS: {f['detail']}",
                "url":f"https://{f['host']}","command":f.get("command",""),
                "evidence":f["detail"],
                "remediation":f.get("remediation","Set Cloudflare min TLS to 1.2"),
            })
        all_passed.extend(tp)

    # ── 7. CORS ───────────────────────────────────────────────────────────────
    console.print("\n[bold]7. CORS Check[/bold]" if HAS_RICH else "\n7. CORS")
    sub_origins = [f"https://{s}" for s in result.subdomains[:5]]
    test_origins = list(set(args.cors_origins + sub_origins + [
        "https://evil.example.com", "null", f"https://attacker.{domain}"]))
    cors_urls = [primary + p for p in ["/api/v1/health","/api/health","/health",""]][:3]
    for curl in cors_urls:
        for cf in check_cors(curl, test_origins[:8]):
            all_findings.append({
                "severity":cf["severity"],"category":"cors",
                "title":f"CORS misconfiguration — {cf['origin']}",
                "url":curl,"command":cf["command"],
                "evidence":cf["evidence"],
                "remediation":cf["remediation"],
            })

    # ── 8. JWKS / source map ─────────────────────────────────────────────────
    console.print("\n[bold]8. Exposure Check (JWKS, source maps, .git)[/bold]" if HAS_RICH else "\n8. Exposures")
    for url in scan_urls[:5]:
        for ef in check_exposures(url):
            all_findings.append({
                "severity":ef["severity"],"category":"exposure",
                "title":ef["title"],"url":ef["url"],"command":ef["command"],
                "evidence":f"{ef['content_type']} | {ef.get('snippet','')}",
                "remediation":ef["remediation"],
            })

    # ── 9. JS secrets & Endpoint extraction (optional) ────────────────────────
    all_endpoints = set()
    all_routes = set()
    if args.js:
        console.print("\n[bold]9. JS Secrets & Endpoints Scan[/bold]" if HAS_RICH else "\n9. JS Secrets & Endpoints")
        js_urls, nxt_routes = collect_js_urls(primary)
        all_routes.update(nxt_routes)
        if nxt_routes:
            console.print(f"  ⚡ Next.js manifest: found {len(nxt_routes)} internal route(s)")
        console.print(f"  Found {len(js_urls)} JS file(s) to scan")
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
                all_findings.append({
                    "severity":sf["severity"],"category":"js-secrets",
                    "title":f"Secret in JS: {sf['type']}",
                    "url":sf["url"],"command":sf["command"],
                    "evidence":f"{sf['detail']}{sample_ev}",
                    "remediation":sf["remediation"],
                })
        if all_endpoints:
            console.print(f"  🔍 Discovered {len(all_endpoints)} API endpoint(s) in JS")
        if all_oauth:
            console.print(f"  🔑 Discovered {len(all_oauth)} OAuth/Redirect parameter(s)")
            result.oauth_params = sorted(list(all_oauth))

    # ── 10. Playwright Dynamic Crawler (optional) ─────────────────────────────
    if args.playwright:
        console.print("\n[bold]10. Playwright Dynamic Crawl[/bold]" if HAS_RICH else "\n10. Playwright Crawl")
        pw_res = crawl_with_playwright(primary)
        if pw_res.get("error"):
            console.print(f"  ⚠️  {pw_res['error']}")
        else:
            console.print(f"  Captured {len(pw_res['api_calls'])} background API call(s)")
            console.print(f"  Discovered {len(pw_res['scripts'])} dynamic script(s)")
            all_endpoints.update(pw_res["api_calls"])
            for l in pw_res.get("links", []):
                p_path = urlparse(l).path
                if p_path and len(p_path) > 1:
                    all_routes.add(p_path)
            storage = pw_res.get("storage", {})
            auth_keys = [k for k in storage.keys() if any(w in k.lower() for w in ["token","auth","jwt","secret","key"])]
            if auth_keys:
                all_findings.append({
                    "severity":"Info","category":"storage",
                    "title":"Auth/token keys found in browser localStorage",
                    "url":primary,"command":"",
                    "evidence":f"Keys in localStorage: {', '.join(auth_keys)}",
                    "remediation":"Avoid storing sensitive JWT/access tokens in localStorage; use HttpOnly Secure cookies",
                })

    result.routes = sorted(list(all_routes))
    result.endpoints = sorted(list(all_endpoints))

    # ── 11. S3 (optional) ─────────────────────────────────────────────────────
    if args.s3:
        console.print("\n[bold]11. S3 Bucket Check[/bold]" if HAS_RICH else "\n11. S3 Buckets")
        for sf in check_s3_buckets(domain):
            all_findings.append({
                "severity":sf["severity"],"category":"s3",
                "title":f"S3: {sf['detail']}",
                "url":f"https://{sf['bucket']}.s3.amazonaws.com",
                "command":sf["command"],
                "evidence":sf.get("snippet",""),
                "remediation":sf.get("remediation",""),
            })

    # ── 12. GitHub (optional) ─────────────────────────────────────────────────
    if args.github_repo and args.github_token:
        console.print("\n[bold]12. GitHub Recon[/bold]" if HAS_RICH else "\n12. GitHub")
        for gf in github_scan_repo(args.github_repo, args.github_token):
            if "error" not in gf:
                all_findings.append({
                    "severity":gf.get("severity","High"),"category":"github",
                    "title":f"GitHub secret: {gf.get('pattern','')} in {gf.get('repo','')}",
                    "url":f"https://github.com/{gf['repo']}",
                    "command":gf.get("command",""),
                    "evidence":gf.get("detail",""),
                    "remediation":"Rotate secret; use GitHub secret scanning; add .gitignore rules",
                })

    # ── 13. nuclei (optional) ─────────────────────────────────────────────────
    if args.nuclei:
        console.print("\n[bold]13. nuclei Scan[/bold]" if HAS_RICH else "\n13. nuclei")
        for url in scan_urls[:3]:
            for n in run_nuclei(url, out_dir):
                if "error" in n:
                    all_passed.append(f"nuclei: {n['error']}")
                else:
                    all_findings.append(n)

    # ── CVE fingerprint detection ─────────────────────────────────────────────
    if args.cve:
        console.print("\n[bold]CVE Fingerprint Detection[/bold]" if HAS_RICH
                      else "\nCVE Fingerprint Detection")
        console.print(f"  Checking {len(CVE_CHECKS)} CVE signatures across {len(scan_urls[:5])} host(s)…")
        for url in scan_urls[:5]:
            cve_findings = check_cve_fingerprints(url)
            for cf in cve_findings:
                all_findings.append(cf)
            console.print(f"  {url} → {len(cve_findings)} CVE match(es)")
        total_cve = sum(1 for f in all_findings if f.get("category") == "cve-fingerprint")
        console.print(f"  Total CVE fingerprint matches: {total_cve}")

    # ── Import Dalfox output ──────────────────────────────────────────────────
    if args.import_dalfox:
        p = Path(args.import_dalfox)
        if p.exists():
            console.print(f"\n[bold]Import: Dalfox ({p.name})[/bold]" if HAS_RICH
                          else f"\nImport: Dalfox ({p.name})")
            dalfox_findings = parse_dalfox_output(p.read_text(encoding="utf-8", errors="replace"),
                                                   args.min_confidence)
            all_findings.extend(dalfox_findings)
            console.print(f"  Added {len(dalfox_findings)} Dalfox finding(s) "
                          f"(confidence >= {args.min_confidence})")
        else:
            console.print(f"  [yellow]Dalfox file not found: {p}[/yellow]" if HAS_RICH
                          else f"  Dalfox file not found: {p}")

    # ── Import nuclei JSONL ───────────────────────────────────────────────────
    if args.import_nuclei:
        p = Path(args.import_nuclei)
        if p.exists():
            console.print(f"\n[bold]Import: nuclei JSONL ({p.name})[/bold]" if HAS_RICH
                          else f"\nImport: nuclei JSONL ({p.name})")
            nf = parse_nuclei_jsonl(p.read_text(encoding="utf-8", errors="replace"))
            all_findings.extend(nf)
            console.print(f"  Added {len(nf)} nuclei finding(s)")
        else:
            console.print(f"  [yellow]nuclei file not found: {p}[/yellow]" if HAS_RICH
                          else f"  nuclei file not found: {p}")

    # ── Finalise ──────────────────────────────────────────────────────────────
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

    # ── Print ─────────────────────────────────────────────────────────────────
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
