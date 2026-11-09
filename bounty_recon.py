#!/usr/bin/env python3
"""
bounty_recon.py — Bug Bounty Passive Recon & Misconfiguration Scanner
======================================================================
Version : 3.0.0 (Concurrent & Enhanced Edition)
License : MIT
"""

import sys, ssl, json, socket, datetime, subprocess, argparse, re, os, warnings, base64, uuid
from urllib.parse import urljoin, urlparse, urlunparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    from rich.panel import Panel
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self, *a, **kw): print(*a)
        def rule(self, t=""): print(f"\n{'='*55} {t}")
    console = _C()

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION  = "3.0.0"
TIMEOUT  = 10
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Upgrade-Insecure-Requests": "1",
}

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
        if not host or host in DUMMY_HOSTS or any(host.endswith("." + d) for d in DUMMY_HOSTS):
            return False
        if any(sub in host for sub in _DUMMY_HOST_SUBSTRINGS):
            return False
        parts = host.split(".")
        if len(parts) < 2 or len(parts[-1]) < 2 or parts[-1].isdigit():
            return False
        if not passwd or len(passwd) < 6 or passwd in DUMMY_PASSWORDS:
            return False
        if any(m in passwd for m in ["${", "{{", "<%", "<", ">", "%s", "%d", "todo", "replace", "changeme", "xxx", "your_", "insert_", "put_your", "password"]):
            return False
        if user in DUMMY_USERS:
            return False
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
    wayback_urls: list = field(default_factory=list)
    oauth_params: list = field(default_factory=list)
    summary:      dict = field(default_factory=dict)

SEV_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
SEV_EMOJI = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}

# ── HTTP Helpers (GET & POST with optional SSL verification) ──────────────────
def http_get(url: str, headers: dict = None, follow: bool = True, timeout: int = TIMEOUT, verify: bool = True):
    h = dict(BROWSER_HEADERS)
    if headers:
        h.update(headers)
    if HAS_HTTPX:
        try:
            r = httpx.get(url, headers=h, timeout=timeout, follow_redirects=follow, verify=verify)
            return r.status_code, dict(r.headers), r.content
        except Exception as e:
            raise ConnectionError(str(e))
    else:
        import urllib.request as ur, urllib.error as ue, ssl as _ssl
        ctx = _ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
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

def http_post(url: str, json_data: dict, headers: dict = None, timeout: int = TIMEOUT, verify: bool = True):
    h = dict(BROWSER_HEADERS)
    h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    payload = json.dumps(json_data).encode("utf-8")
    if HAS_HTTPX:
        try:
            r = httpx.post(url, content=payload, headers=h, timeout=timeout, follow_redirects=True, verify=verify)
            return r.status_code, dict(r.headers), r.content
        except Exception as e:
            raise ConnectionError(str(e))
    else:
        import urllib.request as ur, urllib.error as ue, ssl as _ssl
        ctx = _ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        req = ur.Request(url, data=payload, headers=h, method="POST")
        try:
            with ur.urlopen(req, context=ctx, timeout=timeout) as resp:
                return resp.status, {k.lower(): v for k,v in resp.headers.items()}, resp.read()
        except ue.HTTPError as e:
            body = b""
            try: body = e.read()
            except: pass
            return e.code, {k.lower(): v for k,v in e.headers.items()} if e.headers else {}, body
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

# ── Recon & Auditing Helpers ──────────────────────────────────────────────────
def audit_jwt_token(token: str, source_url: str) -> list:
    findings = []
    parts = token.strip().split(".")
    if len(parts) < 2:
        return findings
    try:
        hdr_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(hdr_b64).decode("utf-8", "replace"))
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
    except Exception:
        pass
    return findings

def audit_cookie(name: str, value: str, raw_cookie_str: str, base_url: str) -> list:
    findings = []
    parts = [p.strip() for p in raw_cookie_str.split(";")]
    attrs = {p.split("=")[0].lower(): (p.split("=")[1] if "=" in p else True) for p in parts}
    is_session = any(k in name.lower() for k in ["sess", "auth", "token", "jwt", "id", "login", "user", "csrf"])

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
    return findings

def audit_dns_security(domain: str) -> list:
    findings = []
    if not HAS_DNS:
        return findings
    txt_records, dmarc_records, caa_records = [], [], []
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            txt_records.append(str(r).strip('"'))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            dmarc_records.append(str(r).strip('"'))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(domain, "CAA"):
            caa_records.append(str(r))
    except Exception: pass

    spf = [t for t in txt_records if "v=spf1" in t]
    if not spf:
        findings.append({
            "severity": "Low", "category": "dns-sec",
            "title": f"DNS: Missing SPF record on {domain}",
            "url": f"dns://{domain}", "evidence": "No TXT record matching 'v=spf1' found",
            "command": f"dig +short TXT {domain}",
            "remediation": "Publish SPF TXT record (e.g. 'v=spf1 include:... ~all' or 'v=spf1 -all')"
        })
    elif "+all" in spf[0]:
        findings.append({
            "severity": "Medium", "category": "dns-sec",
            "title": "DNS: Insecure SPF record allows any sender (+all)",
            "url": f"dns://{domain}", "evidence": spf[0],
            "command": f"dig +short TXT {domain}",
            "remediation": "Change +all to -all (hard fail) or ~all (soft fail)"
        })

    if not dmarc_records:
        findings.append({
            "severity": "Low", "category": "dns-sec",
            "title": f"DNS: Missing DMARC record on _dmarc.{domain}",
            "url": f"dns://_dmarc.{domain}", "evidence": f"No DMARC TXT record found at _dmarc.{domain}",
            "command": f"dig +short TXT _dmarc.{domain}",
            "remediation": "Publish DMARC record (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc@...')"
        })
    return findings

def deep_fingerprint_tech(url: str, hdrs: dict, html_text: str = "") -> list:
    h = norm_headers(hdrs)
    tech = set()
    if h.get("server"): tech.add(f"Server: {h.get('server')}")
    if h.get("cf-ray") or h.get("server") == "cloudflare": tech.add("Cloudflare CDN & WAF")
    if h.get("x-vercel-id"): tech.add("Vercel Edge Platform")
    if h.get("x-amz-request-id") or "amazonaws.com" in h.get("x-amz-id-2", ""): tech.add("Amazon Web Services (AWS)")
    if h.get("x-powered-by"): tech.add(f"Powered-By: {h.get('x-powered-by')}")
    if html_text:
        if "__NEXT_DATA__" in html_text or "/_next/" in html_text:
            tech.add("Next.js (React)")
        elif "react" in html_text.lower() or "data-reactroot" in html_text:
            tech.add("React.js")
        if "tailwind" in html_text.lower() or "bg-slate-" in html_text:
            tech.add("Tailwind CSS")
        if "sentry" in html_text.lower() or "@sentry" in html_text:
            tech.add("Sentry Error Tracking")
    return sorted(list(tech))

OAUTH_REDIRECT_PATTERN = re.compile(
    r"""(?:['"])([^"'\s]*(?:callbackUrl|redirect_uri|redirect_url|return_to|next|returnTo)[^"'\s]*|/api/auth/callback/[a-zA-Z0-9_\-]+|[a-zA-Z0-9_\-]+\.apps\.googleusercontent\.com)(?:['"])"""
)

def extract_oauth_and_redirects(js_text: str) -> list:
    results = set()
    for m in OAUTH_REDIRECT_PATTERN.finditer(js_text):
        for g in m.groups():
            if g and len(g) > 4:
                results.add(g.strip())
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

# ── 1. Concurrent Subdomain Enumeration ───────────────────────────────────────
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
    except Exception: pass
    return subs

def enum_subdomains_securitytrails(domain: str, api_key: str) -> set:
    subs = set()
    if not api_key: return subs
    try:
        status, _, body = http_get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": api_key}, timeout=15)
        if status == 200:
            for s in json.loads(body).get("subdomains", []):
                subs.add(f"{s}.{domain}")
    except Exception: pass
    return subs

def enum_subdomains(domain: str, api_key: str = "") -> list:
    console.print("  → Querying crt.sh, HackerTarget, AlienVault, Anubis & RapidDNS in parallel...")
    subs = {domain}
    funcs = [enum_subdomains_crtsh, enum_subdomains_hackertarget, enum_subdomains_alienvault, enum_subdomains_anubis, enum_subdomains_rapiddns]
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = [ex.submit(fn, domain) for fn in funcs]
        if api_key:
            futures.append(ex.submit(enum_subdomains_securitytrails, domain, api_key))
        for fut in as_completed(futures):
            try:
                subs |= fut.result()
            except Exception: pass
    console.print(f"  Found {len(subs)} unique subdomain(s)")
    return sorted(subs)

# ── 2. Concurrent DNS Resolution & Takeover Check (with verify=False & HTTP) ─
def _resolve_single_host(host: str) -> tuple:
    rec = {"A":[], "CNAME":[], "MX":[], "live":False}
    try:
        if HAS_DNS:
            for rtype in ("A","CNAME","MX"):
                try:
                    for r in dns.resolver.resolve(host, rtype, lifetime=4):
                        rec[rtype].append(str(r))
                    if rtype == "A": rec["live"] = True
                except Exception: pass
        else:
            ip = socket.gethostbyname(host)
            rec["A"].append(ip); rec["live"] = True
    except Exception: pass
    return host, rec

def resolve_dns(hosts: list, threads: int = 15) -> dict:
    records = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for host, rec in ex.map(_resolve_single_host, hosts):
            records[host] = rec
    return records

def check_dns_takeover(host: str, cnames: list) -> Optional[dict]:
    """Checks both HTTPS (ignoring expired/mismatched certs) and HTTP for takeover fingerprints."""
    for cname in cnames:
        for svc, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if svc in cname.lower():
                for scheme in ("https", "http"):
                    try:
                        _, _, body = http_get(f"{scheme}://{host}", timeout=6, verify=False)
                        if fingerprint.lower() in body.decode("utf-8", "replace").lower():
                            return {
                                "host": host, "cname": cname, "service": svc,
                                "fingerprint": fingerprint,
                                "command": f'curl -sik "{scheme}://{host}"',
                            }
                    except Exception:
                        continue
    return None

# ── 3. Concurrent Live Host Detection ─────────────────────────────────────────
def _check_single_live(host: str) -> Optional[dict]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            status, hdrs, body = http_get(url, follow=True, timeout=7)
            h = norm_headers(hdrs)
            return {
                "host": host, "url": url, "status": status,
                "server": h.get("server", ""),
                "powered_by": h.get("x-powered-by", ""),
                "redirect": h.get("location", ""),
                "headers": h,
                "html": body[:15000].decode("utf-8", "replace")
            }
        except Exception:
            continue
    return None

def check_live(hosts: list, threads: int = 15) -> list:
    live = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(_check_single_live, hosts):
            if res:
                live.append(res)
    return live

# ── 4. Endpoint Sweep with Soft-404 (Baseline) Filter & Concurrency ──────────
def get_soft_404_baseline(base_url: str) -> dict:
    """Probes a random non-existent path to fingerprint custom JSON/text 200 OK 404 responses."""
    rand_slug = f"bounty_recon_404_{uuid.uuid4().hex[:8]}.json"
    url = f"{base_url.rstrip('/')}/{rand_slug}"
    try:
        status, hdrs, body = http_get(url, follow=False, timeout=6)
        h = norm_headers(hdrs)
        return {
            "status": status,
            "content_type": h.get("content-type", ""),
            "length": len(body),
            "sample": body[:120].decode("utf-8", "replace").strip()
        }
    except Exception:
        return {"status": 0, "content_type": "", "length": -1, "sample": ""}

def is_soft_404(status: int, ct: str, body: bytes, baseline: dict) -> bool:
    if status == 200 and baseline.get("status") == 200:
        b_len = baseline.get("length", -1)
        if b_len > 0 and abs(len(body) - b_len) <= max(15, int(b_len * 0.08)):
            return True
    text_low = body[:250].decode("utf-8", "replace").lower()
    if any(fp in text_low for fp in ['"status":404', '"code":404', '"error":"not found"', '"message":"not found"', '"message":"route not found"']):
        return True
    return False

def _probe_single_path(base_url: str, path: str, baseline: dict) -> tuple:
    url = base_url.rstrip("/") + path
    try:
        status, hdrs, body = http_get(url, follow=False, timeout=7)
        h = norm_headers(hdrs)
        ct = h.get("content-type", "")
        if status == 200 and not is_html(ct, body):
            if is_soft_404(status, ct, body, baseline):
                return None, f"{url} → 200 (Soft-404 filtered)"
            body_text = body[:300].decode("utf-8", "replace")
            if len(body_text.strip()) < 5:
                return None, f"{url} → 200 (empty/trivial)"
            if path.startswith("/.git/HEAD") and not body_text.startswith("ref:"):
                return None, f"{url} → 200 (not git ref)"
            if path.startswith("/.git/config") and "[core]" not in body_text:
                return None, f"{url} → 200 (not git config)"
            if path.startswith("/.env") and ("=" not in body_text or "{" in body_text[:50]):
                return None, f"{url} → 200 (not env key=val)"
            snippet = body_text.replace("\n", " ").strip()
            return {
                "url": url, "status": status, "content_type": ct,
                "snippet": snippet[:180],
                "command": f'curl -si --noproxy "*" "{url}"',
            }, None
        elif status == 200:
            return None, f"{url} → 200 html/SPA (FP)"
        elif status in (301, 302, 307, 308):
            loc = h.get("location", "")
            return None, f"{url} → {status} (redirect to {loc[:35]})" if loc else f"{url} → {status} (redirect)"
        elif status in (401, 403):
            is_waf, waf_name = is_waf_challenge(status, hdrs, body)
            return None, f"{url} → 403 (Protected by {waf_name})" if is_waf else f"{url} → {status} (auth/blocked)"
        else:
            return None, f"{url} → {status}"
    except Exception:
        return None, f"{url} → error"

def sweep_endpoints(base_url: str, threads: int = 15) -> tuple:
    findings, passed = [], []
    baseline = get_soft_404_baseline(base_url)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_probe_single_path, base_url, path, baseline) for path in SENSITIVE_PATHS]
        for fut in as_completed(futures):
            f, p = fut.result()
            if f: findings.append(f)
            if p: passed.append(p)
    return findings, passed

# ── 5. GraphQL Introspection Check ────────────────────────────────────────────
def check_graphql_introspection(base_url: str) -> list:
    findings = []
    gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
    query = {"query": "query { __schema { queryType { name } types { name kind } } }"}
    for path in gql_paths:
        url = base_url.rstrip("/") + path
        try:
            status, hdrs, body = http_post(url, query, timeout=7)
            if status == 200 and b'"__schema"' in body and b'"types"' in body:
                data = json.loads(body.decode("utf-8", "replace"))
                types = [t.get("name") for t in data.get("data", {}).get("__schema", {}).get("types", []) if t.get("name") and not t.get("name").startswith("__")]
                findings.append({
                    "severity": "Medium",
                    "category": "graphql",
                    "title": f"GraphQL Introspection Enabled ({path})",
                    "url": url,
                    "evidence": f"Discovered {len(types)} custom schema types: {', '.join(types[:8])}...",
                    "command": f"""curl -s -X POST -H "Content-Type: application/json" -d '{json.dumps(query)}' "{url}" """,
                    "remediation": "Disable GraphQL introspection in production environments"
                })
                break
        except Exception:
            continue
    return findings

# ── 6. Security Headers & TLS ─────────────────────────────────────────────────
def check_headers(base_url: str) -> tuple:
    findings, passed = [], []
    try:
        status, hdrs, _ = http_get(base_url, timeout=8)
        h = norm_headers(hdrs)
        for hdr, (sev, impact) in REQUIRED_HEADERS.items():
            val = h.get(hdr, "")
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
        server = h.get("server", "")
        if server and any(c.isdigit() for c in server):
            findings.append({
                "severity": "Low", "header": "server-version", "url": base_url,
                "detail": f"Server version disclosed: {server}",
                "evidence": f"Server header value: {server}",
                "command": f'curl -sI "{base_url}"',
                "remediation": "Strip or genericise the Server header"
            })
    except Exception as e:
        passed.append(f"Header check error: {e}")
    return findings, passed

def check_tls(host: str) -> tuple:
    findings, passed = [], []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    days = (exp - now_utc).days
                    if days < 30:
                        findings.append({
                            "severity": "High", "check": "cert-expiry", "host": host,
                            "detail": f"Certificate expires in {days} days ({not_after})",
                            "command": f"echo | openssl s_client -connect {host}:443 2>/dev/null | openssl x509 -noout -dates"
                        })
                    else:
                        passed.append(f"TLS cert valid {days} days")
    except Exception as e:
        passed.append(f"TLS check error: {e}")
    return findings, passed

# ── 7. CORS Check (Expanded to Discovered API Endpoints) ─────────────────────
def check_cors(base_url: str, test_origins: list) -> list:
    findings = []
    for origin in test_origins:
        try:
            _, hdrs, _ = http_get(base_url, headers={"Origin": origin}, timeout=6)
            h = norm_headers(hdrs)
            acao = h.get("access-control-allow-origin", "")
            acac = h.get("access-control-allow-credentials", "")
            if acao == "*":
                findings.append({
                    "origin": origin, "severity": "Info", "url": base_url,
                    "detail": "CORS wildcard (*) — public endpoint, no credentials allowed",
                    "evidence": f"ACAO: {acao}",
                    "command": f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation": "Restrict allowed origins explicitly if sensitive data is returned"
                })
            elif origin in acao and "true" in acac.lower():
                findings.append({
                    "origin": origin, "severity": "High", "url": base_url,
                    "detail": "CORS reflects origin with Allow-Credentials:true",
                    "evidence": f"ACAO: {acao} | ACAC: {acac}",
                    "command": f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation": "Remove Allow-Credentials or validate against a strict origin whitelist"
                })
        except Exception:
            pass
    return findings

# ── 8. JS Secrets, Endpoints & Dynamic Source Map Scanner ─────────────────────
def collect_js_urls(base_url: str) -> tuple:
    js_urls, routes = set(), set()
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
    except Exception:
        pass
    return sorted(list(js_urls)), sorted(list(routes))

def check_dynamic_sourcemap(js_url: str, js_text: str) -> Optional[dict]:
    """Checks for //# sourceMappingURL= or .js.map corresponding to a live JS bundle."""
    map_candidates = []
    m = re.search(r'//#\s*sourceMappingURL=([^\s"\']+)', js_text)
    if m and not m.group(1).startswith("data:"):
        map_candidates.append(urljoin(js_url, m.group(1).strip()))
    clean_js = js_url.split("?")[0]
    if clean_js.endswith(".js"):
        map_candidates.append(clean_js + ".map")

    for map_url in dict.fromkeys(map_candidates):
        try:
            status, hdrs, body = http_get(map_url, follow=False, timeout=7)
            ct = norm_headers(hdrs).get("content-type", "")
            if status == 200 and not is_html(ct, body) and b'"sources"' in body[:1500]:
                data = json.loads(body.decode("utf-8", "replace"))
                sources = data.get("sources", [])
                return {
                    "severity": "Medium",
                    "category": "sourcemap",
                    "title": f"Webpack/Vite Source Map Exposed ({map_url.split('/')[-1]})",
                    "url": map_url,
                    "evidence": f"Contains {len(sources)} unminified source files (e.g. {', '.join(sources[:4])})",
                    "command": f'curl -ks "{map_url}" | head -c 300',
                    "remediation": "Disable production source maps (productionBrowserSourceMaps: false) or block *.map at WAF"
                }
        except Exception:
            continue
    return None

def scan_js_secrets(js_url: str) -> tuple:
    secrets, endpoints, oauth_list, map_findings = [], [], [], []
    try:
        status, _, body = http_get(js_url, timeout=10)
        if status != 200:
            return secrets, endpoints, oauth_list, map_findings
        text = body.decode("utf-8", "replace")

        endpoints = extract_endpoints_from_js(text)
        oauth_list = extract_oauth_and_redirects(text)

        sm_finding = check_dynamic_sourcemap(js_url, text)
        if sm_finding:
            map_findings.append(sm_finding)

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

            # Fixed JWT Audit key mapping (title / evidence)
            if name == "JWT Token":
                for token_match in matches[:3]:
                    for jf in audit_jwt_token(token_match, js_url):
                        secrets.append({
                            "severity": jf["severity"],
                            "type": jf["title"],
                            "url": js_url,
                            "detail": jf["evidence"],
                            "sample": token_match[:40] + "...",
                            "command": jf["command"],
                            "remediation": jf["remediation"]
                        })

            secrets.append({
                "severity": "Critical" if name not in ("JWT Token", "Firebase URL") else "Info",
                "type": name,
                "url": js_url,
                "detail": f"{len(matches)} match(es) of '{name}' pattern",
                "sample": sample,
                "command": f'curl -s "{js_url}" | grep -Eo "{pattern[:40]}"',
                "remediation": "Rotate secret immediately; remove from client-side code",
            })
    except Exception:
        pass
    return secrets, endpoints, oauth_list, map_findings

# ── 9. Multi-Cloud Storage Check (AWS S3, Google GCS, Azure Blob) ─────────────
def _probe_single_bucket(bucket: str) -> list:
    found = []
    targets = [
        ("AWS S3",     f"https://{bucket}.s3.amazonaws.com",                  "ListBucketResult"),
        ("Google GCS", f"https://storage.googleapis.com/{bucket}",            "ListBucketResult"),
        ("Azure Blob", f"https://{bucket}.blob.core.windows.net/?comp=list",  "EnumerationResults"),
    ]
    for provider, url, xml_sig in targets:
        try:
            status, _, body = http_get(url, timeout=5)
            text = body[:500].decode("utf-8", "replace")
            if status == 200 and xml_sig in text:
                found.append({
                    "severity": "Critical", "bucket": bucket, "url": url,
                    "detail": f"{provider} bucket publicly listable: {bucket}",
                    "snippet": text[:120].replace("\n", " "),
                    "command": f'curl -si "{url}"',
                    "remediation": f"Disable public access / anonymous listing on {provider} storage bucket"
                })
            elif status == 403 and provider in ("AWS S3", "Google GCS"):
                found.append({
                    "severity": "Info", "bucket": bucket, "url": url,
                    "detail": f"{provider} bucket exists (HTTP 403 Forbidden): {bucket}",
                    "snippet": "",
                    "command": f'curl -si "{url}"',
                    "remediation": "Verify bucket ACLs and policies restrict access to authorized principals only"
                })
        except Exception:
            continue
    return found

def check_cloud_buckets(domain: str, threads: int = 15) -> list:
    findings = []
    buckets = s3_permutations(domain)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(_probe_single_bucket, buckets):
            findings.extend(res)
    return findings

# ── 10. Wayback Machine Passive Historical URLs ───────────────────────────────
def fetch_wayback_urls(domain: str) -> list:
    """Queries archive.org CDX API for interesting parameterized/API/config historical URLs."""
    interesting = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=600"
    try:
        status, _, body = http_get(url, timeout=15)
        if status == 200:
            rows = json.loads(body.decode("utf-8", "replace"))
            keywords = ("/api/", "/v1/", "/v2/", "/graphql", "/admin", ".json", ".xml", ".conf", ".env", ".bak", ".sql", "redirect=", "url=", "next=", "id=", "token=", "key=")
            for row in rows[1:]:
                u = row[0] if isinstance(row, list) and row else ""
                if any(k in u.lower() for k in keywords):
                    interesting.add(u)
    except Exception:
        pass
    return sorted(list(interesting))[:100]

# ── 11. Playwright & External Parsers ─────────────────────────────────────────
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
        "-rl", "50", "-c", "10",
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

# ── 12. Report Generation ─────────────────────────────────────────────────────
def generate_markdown(result: ScanResult, out_path: Path):
    sev_counts = {}
    for f in result.findings:
        s = f.get("severity","Info")
        sev_counts[s] = sev_counts.get(s,0) + 1

    lines = [
        f"# Bounty Recon Report — {result.target}", "",
        "| | |", "|---|---|",
        f"| **Generated** | {result.timestamp} |",
        f"| **Tool** | bounty_recon.py v{VERSION} |", "",
        "---", "", "## Executive Summary", "",
        "| Severity | Count |", "|----------|-------|",
    ]
    for sev in ["Critical","High","Medium","Low","Info"]:
        c = sev_counts.get(sev,0)
        lines.append(f"| {SEV_EMOJI.get(sev,'')} **{sev}** | {c} |")
    lines += [f"| ✅ Passed | {len(result.passed)} |",""]

    if result.subdomains:
        lines += ["## Discovered Subdomains",""]
        for s in result.subdomains[:80]: lines.append(f"- `{s}`")
        lines += [""]

    if result.live_hosts:
        lines += ["## Live Hosts","", "| URL | Status | Server |", "|-----|--------|--------|"]
        for h in result.live_hosts:
            lines.append(f"| `{h['url']}` | {h['status']} | `{h.get('server','?')}` |")
        lines += [""]

    if result.endpoints:
        lines += ["## Discovered API Endpoints (JS & Dynamic)",""]
        for ep in result.endpoints[:80]: lines.append(f"- `{ep}`")
        lines += [""]

    if result.wayback_urls:
        lines += ["## Historical Wayback URLs (Parameterized / API)",""]
        for wu in result.wayback_urls[:60]: lines.append(f"- `{wu}`")
        lines += [""]

    lines += ["## Findings",""]
    sorted_f = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.get("severity","Info"),4))
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity","Info")
        title = f.get("title") or f.get("detail") or f.get("header","") or "Finding"
        url   = f.get("url") or f.get("host","")
        lines += [f"### {i}. {SEV_EMOJI.get(sev,'')} [{sev}] {title}", "", f"**Severity:** {sev}  "]
        if url: lines.append(f"**Target:** `{url}`  ")
        ev = f.get("evidence") or f.get("snippet") or f.get("detail","")
        if ev: lines += ["**Evidence:**","```",ev[:300],"```"]
        if f.get("command"): lines += ["**Reproduce:**","```bash",f["command"],"```"]
        if f.get("remediation"): lines.append(f"**Remediation:** {f['remediation']}")
        lines += [""]

    out_path.write_text("\n".join(lines), encoding="utf-8")

def generate_json(result: ScanResult, out_path: Path):
    out_path.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")

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
        print(f"  {em} [{sev}] {t} | {url}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=f"bounty_recon.py v{VERSION}")
    ap.add_argument("-t","--target",         required=True, help="Target domain (e.g. fluttercee.com)")
    ap.add_argument("--url",                 help="Override primary base URL for scanning")
    ap.add_argument("--threads",             type=int, default=15, help="Concurrent worker threads (default: 15)")
    ap.add_argument("--max-hosts",           type=int, default=30, help="Max live hosts to deep-scan (default: 30)")
    ap.add_argument("--cors-origin",         action="append", default=[], dest="cors_origins", help="Extra CORS origin")
    ap.add_argument("--nuclei",              action="store_true", help="Run nuclei")
    ap.add_argument("--js",                  action="store_true", help="Scan JS files, dynamic source maps & endpoints")
    ap.add_argument("--playwright",          action="store_true", help="Headless Playwright SPA crawl")
    ap.add_argument("--s3",                  action="store_true", help="Check AWS S3, Google GCS & Azure Blob buckets")
    ap.add_argument("--wayback",             action="store_true", help="Fetch historical URLs from Wayback Machine")
    ap.add_argument("--securitytrails-key",  default=os.environ.get("SECURITYTRAILS_API_KEY",""))
    ap.add_argument("--no-subdomains",       action="store_true", help="Skip subdomain enumeration")
    ap.add_argument("--out",                 default="", help="Output file stem")
    ap.add_argument("--out-dir",             default=".", help="Output directory")
    ap.add_argument("--json",                action="store_true", help="Write JSON report")
    args = ap.parse_args()

    domain   = args.target.replace("https://","").replace("http://","").split("/")[0]
    base_url = args.url.rstrip("/") if args.url else f"https://{domain}"
    out_dir  = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem     = args.out or f"{domain.replace('.','_')}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M')}"
    md_path  = out_dir / f"{stem}.md"
    jp       = out_dir / f"{stem}.json"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    if HAS_RICH:
        console.print(Panel(
            f"[bold cyan]bounty_recon.py[/bold cyan] v{VERSION} (Threads: {args.threads})\n"
            f"Target  : [bold]{domain}[/bold] | Base URL: {base_url}\n"
            f"js={args.js}  s3/cloud={args.s3}  wayback={args.wayback}  playwright={args.playwright}  nuclei={args.nuclei}",
            title="🔍 Bug Bounty Concurrent Recon"))

    # 1. Subdomains
    if not args.no_subdomains:
        console.print("\n[bold]1. Subdomain Enumeration[/bold]")
        result.subdomains = enum_subdomains(domain, args.securitytrails_key)
    else:
        result.subdomains = [domain]

    # 2. DNS + Takeover
    console.print("\n[bold]2. Concurrent DNS Resolution & Takeover Check[/bold]")
    dns_records = resolve_dns(result.subdomains, threads=args.threads)
    result.dns_records = dns_records
    for host, rec in dns_records.items():
        if rec["CNAME"]:
            to = check_dns_takeover(host, rec["CNAME"])
            if to:
                all_findings.append({
                    "severity":"Critical", "category":"dns-takeover",
                    "title":f"Subdomain Takeover — {to['service']}",
                    "url":f"https://{host}",
                    "evidence":f"CNAME {to['cname']} → Fingerprint: '{to['fingerprint']}'",
                    "command":to["command"],
                    "remediation":"Claim the external resource or remove the dangling CNAME record",
                })
    all_findings.extend(audit_dns_security(domain))

    # 3. Live Hosts + Tech
    console.print("\n[bold]3. Concurrent Live Host Detection & Fingerprinting[/bold]")
    candidate = [h for h, r in dns_records.items() if r["live"]] or [domain]
    if args.url:
        url_host = urlparse(base_url).hostname
        if url_host and url_host not in candidate:
            candidate.insert(0, url_host)

    live = check_live(candidate[:args.max_hosts], threads=args.threads)
    result.live_hosts = [{k: v for k, v in h.items() if k not in ("headers", "html")} for h in live]
    console.print(f"  {len(live)} live host(s) responded")
    for lh in live:
        techs = deep_fingerprint_tech(lh["url"], lh.get("headers", {}), lh.get("html", ""))
        if techs:
            result.technologies[lh["host"]] = techs

    scan_urls = [base_url] + [h["url"] for h in live if h["url"] != base_url]
    scan_urls = scan_urls[:args.max_hosts]

    # 4. Sensitive Endpoint Sweep + GraphQL Introspection
    console.print("\n[bold]4. Sensitive Endpoint Sweep (with Soft-404 Filter) & GraphQL Check[/bold]")
    for url in scan_urls:
        ep_f, ep_p = sweep_endpoints(url, threads=args.threads)
        for f in ep_f:
            all_findings.append({
                "severity":"High", "category":"exposure",
                "title":f"Sensitive endpoint exposed: {f['url'].split('/')[-1]}",
                "url":f["url"], "command":f["command"],
                "evidence":f"HTTP 200 | {f['content_type']} | {f['snippet'][:100]}",
                "remediation":"Restrict access or remove sensitive file from public webroot",
            })
        all_passed.extend(ep_p)
        all_findings.extend(check_graphql_introspection(url))

    # 5. Security Headers & Cookies
    console.print("\n[bold]5. Security Headers & Cookie Audit[/bold]")
    for url in scan_urls[:10]:
        hf, hp = check_headers(url)
        for f in hf:
            all_findings.append({
                "severity":f["severity"], "category":"headers",
                "title":f"Header issue: {f['header']}",
                "url":f.get("url", url), "command":f.get("command",""),
                "evidence":f.get("evidence") or f.get("detail",""),
                "remediation":f.get("remediation",""),
            })
        all_passed.extend(hp)
        try:
            _, resp_hdrs, _ = http_get(url, timeout=7)
            sc_raw = norm_headers(resp_hdrs).get("set-cookie", "")
            for sc in sc_raw.splitlines():
                if "=" in sc:
                    c_name = sc.split("=")[0].strip()
                    c_val = sc.split("=")[1].split(";")[0].strip()
                    all_findings.extend(audit_cookie(c_name, c_val, sc, url))
        except Exception: pass

    # 6. TLS Check
    console.print("\n[bold]6. TLS Check[/bold]")
    tls_hosts = list({urlparse(u).hostname for u in scan_urls if u.startswith("https") and urlparse(u).hostname})
    for host in tls_hosts[:10]:
        tf, tp = check_tls(host)
        for f in tf:
            all_findings.append({
                "severity":f["severity"], "category":"tls",
                "title":f"TLS: {f['detail']}", "url":f"https://{f['host']}",
                "command":f.get("command",""), "evidence":f["detail"],
            })
        all_passed.extend(tp)

    # 7. JS Secrets, Dynamic Source Maps & Endpoints
    all_endpoints, all_routes, all_oauth = set(), set(), set()
    if args.js:
        console.print("\n[bold]7. Concurrent JS Secrets, Source Maps & Endpoint Extraction[/bold]")
        js_urls, nxt_routes = collect_js_urls(base_url)
        all_routes.update(nxt_routes)
        console.print(f"  Scanning {len(js_urls)} JS bundle(s) across {args.threads} threads...")
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            for sec_list, ep_list, oa_list, map_list in ex.map(scan_js_secrets, js_urls):
                all_endpoints.update(ep_list)
                all_oauth.update(oa_list)
                all_findings.extend(map_list)
                for sf in sec_list:
                    sample_ev = f" | Sample: {sf['sample']}" if sf.get('sample') else ""
                    all_findings.append({
                        "severity":sf["severity"], "category":"js-secrets",
                        "title":f"Secret in JS: {sf['type']}",
                        "url":sf["url"], "command":sf["command"],
                        "evidence":f"{sf['detail']}{sample_ev}",
                        "remediation":sf["remediation"],
                    })
        result.oauth_params = sorted(list(all_oauth))
        console.print(f"  🔍 Extracted {len(all_endpoints)} API endpoint(s) & {len(all_oauth)} OAuth/Redirect param(s)")

    # 8. Playwright Dynamic Crawler
    if args.playwright:
        console.print("\n[bold]8. Playwright Dynamic SPA Crawl[/bold]")
        pw_res = crawl_with_playwright(base_url)
        if pw_res.get("error"):
            console.print(f"  ⚠️  {pw_res['error']}")
        else:
            all_endpoints.update(pw_res["api_calls"])
            console.print(f"  Captured {len(pw_res['api_calls'])} runtime API call(s)")

    result.routes = sorted(list(all_routes))
    result.endpoints = sorted(list(all_endpoints))

    # 9. Expanded CORS Check (includes discovered API endpoints)
    console.print("\n[bold]9. Expanded CORS Check (Base + Discovered API Endpoints)[/bold]")
    test_origins = list(set(args.cors_origins + [f"https://evil.example.com", "null", f"https://attacker.{domain}"]))
    cors_candidates = [base_url, f"{base_url}/api/v1/health", f"{base_url}/api/health"]
    for ep in list(all_endpoints)[:12]:
        cors_candidates.append(ep if ep.startswith("http") else f"{base_url}{ep}")
    for curl in dict.fromkeys(cors_candidates):
        for cf in check_cors(curl, test_origins):
            all_findings.append({
                "severity":cf["severity"], "category":"cors",
                "title":f"CORS misconfiguration — {cf['origin']}",
                "url":curl, "command":cf["command"],
                "evidence":cf["evidence"], "remediation":cf["remediation"],
            })

    # 10. Multi-Cloud Storage (S3, GCS, Azure)
    if args.s3:
        console.print("\n[bold]10. Multi-Cloud Storage Check (AWS S3, GCS, Azure Blob)[/bold]")
        for sf in check_cloud_buckets(domain, threads=args.threads):
            all_findings.append({
                "severity":sf["severity"], "category":"cloud-storage",
                "title":sf["detail"], "url":sf["url"],
                "command":sf["command"], "evidence":sf.get("snippet",""),
                "remediation":sf.get("remediation",""),
            })

    # 11. Wayback Machine
    if args.wayback:
        console.print("\n[bold]11. Wayback Machine Passive Recon[/bold]")
        wb_urls = fetch_wayback_urls(domain)
        result.wayback_urls = wb_urls
        console.print(f"  🕰️  Found {len(wb_urls)} historical parameterized/API URL(s)")

    # 12. nuclei
    if args.nuclei:
        console.print("\n[bold]12. nuclei Scan[/bold]")
        for url in scan_urls[:5]:
            for n in run_nuclei(url, out_dir):
                if "error" not in n:
                    all_findings.append(n)

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

    if HAS_RICH: console.rule("[bold red]FINDINGS")
    for f in sorted(all_findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4)):
        print_finding(f)

    s = result.summary
    if HAS_RICH:
        console.rule("[bold green]SUMMARY")
        console.print(f"  🔴 Critical:{s['critical']}  🟠 High:{s['high']}  "
                      f"🟡 Medium:{s['medium']}  🔵 Low:{s['low']}  ✅ Passed:{s['passed']}")

    generate_markdown(result, md_path)
    console.print(f"\n📄 Report: {md_path}")
    if args.json:
        generate_json(result, jp)
        console.print(f"📄 JSON  : {jp}")

if __name__ == "__main__":
    main()
