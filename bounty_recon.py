#!/usr/bin/env python3
"""
bounty_recon.py — Bug Bounty Passive Recon & Misconfiguration Scanner
======================================================================
Version : 4.0.0 (All-In-One Edition: Web UI, AI Triage, DOM Sink Audit, Multi-Cloud)
License : MIT
Author  : Irakli Tsenteradze (ikatsento)
"""

import sys, ssl, json, socket, datetime, subprocess, argparse, re, os, warnings, base64, uuid, html
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import http.server, socketserver

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
VERSION  = "4.0.0"
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
    "Anthropic Key":         r'sk-ant-api03-[a-zA-Z0-9\-_]{40,}',
    "Google API Key":        r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token":          r'gh[pousr]_[A-Za-z0-9]{36,}',
    "GitLab Token":          r'glpat-[0-9a-zA-Z\-_]{20}',
    "JWT Token":             r'ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}',
    "Bearer Token":          r'[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}',
    "Slack Token":           r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    "Slack Webhook":         r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    "Discord Webhook":       r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,}',
    "Stripe Live Key":       r'sk_live_[0-9a-zA-Z]{24,}',
    "SendGrid Key":          r'SG\.[A-Za-z0-9\-_]{22,}',
    "Mailgun API Key":       r'key-[0-9a-zA-Z]{32}',
    "Twilio Account SID":    r'AC[a-zA-Z0-9_\-]{32}',
    "Square Access Token":   r'sq0atp-[0-9A-Za-z\-_]{22}',
    "Firebase URL":          r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Telegram Bot Token":    r'[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}',
    "Private Key Block":     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "Generic API Key":       r'["\']api[_-]?key["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Generic Secret":        r'["\']secret["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Password in URL":       r'https?://[a-zA-Z0-9_\-\.%]+:[^@/?#\s"\'`<>{}]{3,}@[a-zA-Z0-9_\-\.]+(?::\d+)?(?:/[^"\'`\s<>{}]*)?',
}

# Static DOM XSS Sink & Source patterns (Read-only code audit)
DOM_XSS_SINKS = {
    "innerHTML / outerHTML assignment": r'\.(?:innerHTML|outerHTML)\s*=\s*[^"\';]+',
    "document.write() call":            r'document\.write(?:ln)?\s*\([^)]+\)',
    "React dangerouslySetInnerHTML":    r'dangerouslySetInnerHTML\s*:\s*\{',
    "Vue v-html directive":             r'v-html\s*=',
    "Unvalidated eval / Function":      r'\b(?:eval|setTimeout|setInterval)\s*\(\s*(?:location|window\.name|document\.URL|document\.referrer)',
    "Location Sink Assignment":         r'(?:window\.)?location(?:\.href|\.replace|\.assign)?\s*=\s*(?:location\.|URLSearchParams|window\.name)',
}
DOM_XSS_SOURCES = r'\b(?:location\.(?:search|hash|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name|URLSearchParams)\b'

DUMMY_USERS = {"user", "username", "login", "name", "admin", "root", "test", "demo", "guest", "foo", "git", "john", "alice", "email", "null", "undefined", "account"}
DUMMY_PASSWORDS = {"pass", "password", "secret", "admin", "root", "test", "demo", "guest", "bar", "baz", "123456", "changeme", "dummy", "xxx", "token", "null", "undefined", "placeholder"}
DUMMY_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "example.com", "example.org", "example.net", "test.com", "domain.com", "sample.com", "w3.org", "schema.org"}
_DUMMY_HOST_SUBSTRINGS = ("example", "placeholder", "yoursite", "yourdomain", "localhost", "127.0.0", "acme.test", "demo.test")

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
    "cargocollective.com":"404 Not Found",
    "statuspage.io":      "You are being redirected",
    "uservoice.com":      "This UserVoice subdomain is currently available",
    "unbouncepages.com":  "The requested URL was not found on this server",
    "webflow.io":         "The page you are looking for doesn't exist or has been moved",
    "fly.dev":            "404 Not Found",
    "render.com":         "Not Found",
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
    "/api/v1/config", "/api/v1/metrics", "/api/v1/version", "/api/v1/info",
    "/api/health", "/api/status", "/api/debug",
    "/health", "/ready", "/status", "/ping", "/metrics", "/prometheus", "/debug/pprof",
    "/docs", "/openapi.json", "/swagger", "/swagger.json", "/swagger-ui.html",
    "/api-docs", "/redoc", "/graphql",
    "/admin", "/admin/login", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/rest/settings", "/rest/license", "/rest/owner", "/rest/debug",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/server-status", "/server-info", "/_next/static/", "/__webpack_hmr",
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
    ai_insights:  list = field(default_factory=list)
    summary:      dict = field(default_factory=dict)

SEV_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
SEV_EMOJI = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}

# ── HTTP Helpers ──────────────────────────────────────────────────────────────
def http_get(url: str, headers: dict = None, follow: bool = True, timeout: int = TIMEOUT, verify: bool = True):
    h = dict(BROWSER_HEADERS)
    if headers: h.update(headers)
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
            ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
        req = ur.Request(url, headers=h)
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

def http_post(url: str, json_data: dict, headers: dict = None, timeout: int = TIMEOUT, verify: bool = True):
    h = dict(BROWSER_HEADERS)
    h["Content-Type"] = "application/json"
    if headers: h.update(headers)
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
            ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
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

def is_valid_secret_url(matched_url: str) -> bool:
    try:
        p = urlparse(matched_url)
        user, passwd, host = (p.username or "").lower(), (p.password or "").lower(), (p.hostname or "").lower()
        if not host or host in DUMMY_HOSTS or any(host.endswith("." + d) for d in DUMMY_HOSTS): return False
        if any(sub in host for sub in _DUMMY_HOST_SUBSTRINGS): return False
        parts = host.split(".")
        if len(parts) < 2 or len(parts[-1]) < 2 or parts[-1].isdigit(): return False
        if not passwd or len(passwd) < 6 or passwd in DUMMY_PASSWORDS or user in DUMMY_USERS: return False
        return True
    except Exception:
        return False

def mask_url_password(matched_url: str) -> str:
    try:
        p = urlparse(matched_url)
        if p.password:
            netloc = f"{p.username or ''}:*****@{p.hostname or ''}" + (f":{p.port}" if p.port else "")
            return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))
    except Exception: pass
    return matched_url[:50] + "..."

# ── 1. Multi-Source Passive Subdomain Enumeration (10+ Sources) ───────────────
def _sub_crtsh(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if st == 200:
            for e in json.loads(b):
                for n in e.get("name_value","").split("\n"):
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(f".{domain}") or n == domain: subs.add(n)
    except Exception: pass
    return subs

def _sub_hackertarget(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if st == 200:
            for line in b.decode("utf-8","replace").splitlines():
                h = line.split(",")[0].strip().lower()
                if h.endswith(f".{domain}") or h == domain: subs.add(h)
    except Exception: pass
    return subs

def _sub_alienvault(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=12)
        if st == 200:
            for e in json.loads(b).get("passive_dns", []):
                h = e.get("hostname", "").strip().lower()
                if h.endswith(f".{domain}") or h == domain: subs.add(h)
    except Exception: pass
    return subs

def _sub_anubis(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=10)
        if st == 200:
            for s in json.loads(b):
                s = s.strip().lower()
                if s.endswith(f".{domain}") or s == domain: subs.add(s)
    except Exception: pass
    return subs

def _sub_rapiddns(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=12)
        if st == 200:
            for m in re.finditer(rf'<td>([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})</td>', b.decode("utf-8","replace")):
                subs.add(m.group(1).lower())
    except Exception: pass
    return subs

def _sub_urlscan(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=12)
        if st == 200:
            for r in json.loads(b).get("results", []):
                d = r.get("page", {}).get("domain", "").lower()
                if d.endswith(f".{domain}") or d == domain: subs.add(d)
    except Exception: pass
    return subs

def _sub_threatminer(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=12)
        if st == 200:
            for s in json.loads(b).get("results", []):
                s = s.strip().lower()
                if s.endswith(f".{domain}") or s == domain: subs.add(s)
    except Exception: pass
    return subs

def _sub_certspotter(domain: str) -> set:
    subs = set()
    try:
        st, _, b = http_get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", timeout=12)
        if st == 200:
            for item in json.loads(b):
                for d in item.get("dns_names", []):
                    d = d.lstrip("*.").lower()
                    if d.endswith(f".{domain}") or d == domain: subs.add(d)
    except Exception: pass
    return subs

def enum_subdomains(domain: str, st_key: str = "") -> list:
    console.print("  → Querying 9 passive OSINT sources concurrently (crt.sh, OTX, URLScan, CertSpotter, ThreatMiner, Anubis, RapidDNS, HackerTarget)...")
    subs = {domain}
    sources = [_sub_crtsh, _sub_hackertarget, _sub_alienvault, _sub_anubis, _sub_rapiddns, _sub_urlscan, _sub_threatminer, _sub_certspotter]
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(fn, domain) for fn in sources]
        for fut in as_completed(futures):
            try: subs |= fut.result()
            except Exception: pass
    if st_key:
        try:
            st, _, b = http_get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", headers={"APIKEY": st_key}, timeout=12)
            if st == 200:
                for s in json.loads(b).get("subdomains", []): subs.add(f"{s}.{domain}".lower())
        except Exception: pass
    console.print(f"  Found {len(subs)} unique subdomain(s)")
    return sorted(subs)

# ── 2. DNS Resolution & Takeover ──────────────────────────────────────────────
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
            rec["A"].append(socket.gethostbyname(host)); rec["live"] = True
    except Exception: pass
    return host, rec

def resolve_dns(hosts: list, threads: int = 15) -> dict:
    records = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for host, rec in ex.map(_resolve_single_host, hosts):
            records[host] = rec
    return records

def check_dns_takeover(host: str, cnames: list) -> Optional[dict]:
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
                    except Exception: continue
    return None

def audit_dns_security(domain: str) -> list:
    findings = []
    if not HAS_DNS: return findings
    txt, dmarc = [], []
    try:
        for r in dns.resolver.resolve(domain, "TXT"): txt.append(str(r).strip('"'))
    except Exception: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"): dmarc.append(str(r).strip('"'))
    except Exception: pass
    spf = [t for t in txt if "v=spf1" in t]
    if not spf:
        findings.append({"severity":"Low","category":"dns-sec","title":f"DNS: Missing SPF record on {domain}","url":f"dns://{domain}","evidence":"No v=spf1 TXT record","command":f"dig +short TXT {domain}","remediation":"Configure SPF TXT record"})
    if not dmarc:
        findings.append({"severity":"Low","category":"dns-sec","title":f"DNS: Missing DMARC record on _dmarc.{domain}","url":f"dns://_dmarc.{domain}","evidence":"No DMARC TXT record","command":f"dig +short TXT _dmarc.{domain}","remediation":"Configure DMARC policy"})
    return findings

# ── 3. Live Host & Fingerprinting ─────────────────────────────────────────────
def _check_single_live(host: str) -> Optional[dict]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            status, hdrs, body = http_get(url, follow=True, timeout=7)
            h = norm_headers(hdrs)
            return {
                "host": host, "url": url, "status": status,
                "server": h.get("server", ""), "headers": h,
                "html": body[:15000].decode("utf-8", "replace")
            }
        except Exception: continue
    return None

def check_live(hosts: list, threads: int = 15) -> list:
    with ThreadPoolExecutor(max_workers=threads) as ex:
        return [r for r in ex.map(_check_single_live, hosts) if r]

def deep_fingerprint_tech(url: str, hdrs: dict, html_text: str = "") -> list:
    h = norm_headers(hdrs)
    tech = set()
    if h.get("server"): tech.add(f"Server: {h.get('server')}")
    if h.get("cf-ray") or h.get("server") == "cloudflare": tech.add("Cloudflare")
    if h.get("x-vercel-id"): tech.add("Vercel")
    if h.get("x-amz-request-id"): tech.add("AWS")
    if h.get("x-powered-by"): tech.add(f"Powered-By: {h.get('x-powered-by')}")
    if "__NEXT_DATA__" in html_text or "/_next/" in html_text: tech.add("Next.js")
    elif "react" in html_text.lower(): tech.add("React")
    if "tailwind" in html_text.lower(): tech.add("Tailwind CSS")
    return sorted(list(tech))

# ── 4. Soft-404 Baseline & Endpoint Sweep ─────────────────────────────────────
def get_soft_404_baseline(base_url: str) -> dict:
    url = f"{base_url.rstrip('/')}/bounty_recon_404_{uuid.uuid4().hex[:8]}.json"
    try:
        st, hdrs, body = http_get(url, follow=False, timeout=6)
        return {"status": st, "length": len(body)}
    except Exception:
        return {"status": 0, "length": -1}

def is_soft_404(status: int, body: bytes, baseline: dict) -> bool:
    if status == 200 and baseline.get("status") == 200:
        b_len = baseline.get("length", -1)
        if b_len > 0 and abs(len(body) - b_len) <= max(15, int(b_len * 0.08)):
            return True
    low = body[:250].decode("utf-8", "replace").lower()
    return any(fp in low for fp in ['"status":404', '"code":404', '"error":"not found"', '"message":"not found"'])

def _probe_single_path(base_url: str, path: str, baseline: dict) -> tuple:
    url = base_url.rstrip("/") + path
    try:
        st, hdrs, body = http_get(url, follow=False, timeout=7)
        ct = norm_headers(hdrs).get("content-type", "")
        if st == 200 and not is_html(ct, body):
            if is_soft_404(st, body, baseline): return None, f"{url} → 200 (Soft-404)"
            txt = body[:300].decode("utf-8", "replace")
            if len(txt.strip()) < 5: return None, f"{url} → 200 (empty)"
            if path.startswith("/.git/HEAD") and not txt.startswith("ref:"): return None, f"{url} → 200 (FP)"
            if path.startswith("/.git/config") and "[core]" not in txt: return None, f"{url} → 200 (FP)"
            if path.startswith("/.env") and ("=" not in txt or "{" in txt[:50]): return None, f"{url} → 200 (FP)"
            return {"url": url, "status": st, "content_type": ct, "snippet": txt.replace("\n"," ").strip()[:180], "command": f'curl -si "{url}"'}, None
        return None, f"{url} → {st}"
    except Exception:
        return None, f"{url} → error"

def sweep_endpoints(base_url: str, threads: int = 15) -> tuple:
    findings, passed = [], []
    baseline = get_soft_404_baseline(base_url)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for f, p in ex.map(lambda path: _probe_single_path(base_url, path, baseline), SENSITIVE_PATHS):
            if f: findings.append(f)
            if p: passed.append(p)
    return findings, passed

def check_graphql_introspection(base_url: str) -> list:
    findings = []
    query = {"query": "query { __schema { queryType { name } types { name kind } } }"}
    for path in ["/graphql", "/api/graphql", "/v1/graphql"]:
        url = base_url.rstrip("/") + path
        try:
            st, _, body = http_post(url, query, timeout=7)
            if st == 200 and b'"__schema"' in body:
                data = json.loads(body.decode("utf-8", "replace"))
                types = [t.get("name") for t in data.get("data", {}).get("__schema", {}).get("types", []) if t.get("name") and not t.get("name").startswith("__")]
                findings.append({
                    "severity": "Medium", "category": "graphql",
                    "title": f"GraphQL Introspection Enabled ({path})", "url": url,
                    "evidence": f"Schema types exposed ({len(types)}): {', '.join(types[:8])}",
                    "command": f"curl -s -X POST -H 'Content-Type: application/json' -d '{json.dumps(query)}' '{url}'",
                    "remediation": "Disable GraphQL introspection in production"
                })
                break
        except Exception: continue
    return findings

# ── 5. JS Secrets, Source Maps & Static DOM XSS Sink Analysis ─────────────────
API_ENDPOINT_PATTERN = re.compile(r'["\'](/(?:api|v[0-9]|rest|graphql|admin|auth|oauth|user|webhook|settings|config)[a-zA-Z0-9_\-/\.]+[\?a-zA-Z0-9_\-=&]*)["\']')
OAUTH_REDIRECT_PATTERN = re.compile(r"""(?:['"])([^"'\s]*(?:callbackUrl|redirect_uri|redirect_url|return_to|next|returnTo)[^"'\s]*|/api/auth/callback/[a-zA-Z0-9_\-]+)(?:['"])""")

def collect_js_urls(base_url: str) -> tuple:
    js_urls, routes = set(), set()
    try:
        _, _, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8", "replace")
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', text):
            src = m.group(1)
            js_urls.add(urljoin(base_url, src))
        # Next.js manifest check
        bid = re.search(r'"buildId"\s*:\s*"([a-zA-Z0-9_\-]+)"', text)
        if bid:
            m_url = f"{base_url.rstrip('/')}/_next/static/{bid.group(1)}/_buildManifest.js"
            st, _, mb = http_get(m_url, timeout=6)
            if st == 200:
                mt = mb.decode("utf-8", "replace")
                for r in re.findall(r'["\'](/[^"\']*)["\']\s*:\s*\[', mt):
                    if not r.startswith("/_"): routes.add(r)
    except Exception: pass
    return sorted(list(js_urls)), sorted(list(routes))

def check_dynamic_sourcemap(js_url: str, js_text: str) -> Optional[dict]:
    candidates = []
    m = re.search(r'//#\s*sourceMappingURL=([^\s"\']+)', js_text)
    if m and not m.group(1).startswith("data:"):
        candidates.append(urljoin(js_url, m.group(1).strip()))
    if js_url.split("?")[0].endswith(".js"):
        candidates.append(js_url.split("?")[0] + ".map")
    for map_url in dict.fromkeys(candidates):
        try:
            st, hdrs, body = http_get(map_url, follow=False, timeout=6)
            if st == 200 and not is_html(norm_headers(hdrs).get("content-type",""), body) and b'"sources"' in body[:1500]:
                sources = json.loads(body.decode("utf-8", "replace")).get("sources", [])
                return {
                    "severity": "Medium", "category": "sourcemap",
                    "title": f"Source Map Exposed ({map_url.split('/')[-1]})", "url": map_url,
                    "evidence": f"Exposes {len(sources)} source files: {', '.join(sources[:4])}",
                    "command": f'curl -ks "{map_url}" | head -c 300',
                    "remediation": "Disable production source maps or block *.map at WAF"
                }
        except Exception: continue
    return None

def audit_dom_xss_sinks(js_url: str, js_text: str) -> list:
    """Passive static analysis of JS bundles for dangerous DOM XSS sinks paired with URL sources."""
    findings = []
    has_source = re.search(DOM_XSS_SOURCES, js_text)
    if not has_source:
        return findings
    for sink_name, pattern in DOM_XSS_SINKS.items():
        matches = re.findall(pattern, js_text)
        if matches:
            sample = matches[0][:100].strip()
            findings.append({
                "severity": "Low",
                "category": "dom-xss-sink",
                "title": f"Potential DOM Sink in JS: {sink_name}",
                "url": js_url,
                "evidence": f"File reads URL source ({has_source.group(0)}) and invokes {sink_name} | Snippet: {sample}",
                "command": f'curl -s "{js_url}" | grep -Eo "{pattern[:30]}" | head -n 3',
                "remediation": "Ensure untrusted URL parameters are sanitized with DOMPurify or assigned via textContent instead of innerHTML"
            })
    return findings

def audit_jwt_token(token: str, source_url: str) -> list:
    findings = []
    parts = token.strip().split(".")
    if len(parts) < 2: return findings
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)).decode("utf-8", "replace"))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)).decode("utf-8", "replace"))
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append({"severity":"Critical","title":"JWT 'alg: none' token found","evidence":f"Header: {header}","command":f'curl -s "{source_url}"',"remediation":"Reject alg:none"})
        sensitive = [k for k in payload.keys() if any(w in k.lower() for w in ["pass","secret","priv","email","role","admin"])]
        if sensitive:
            findings.append({"severity":"Low","title":f"JWT exposes claims: {', '.join(sensitive[:4])}","evidence":f"Claims: {list(payload.keys())}","command":f'curl -s "{source_url}"',"remediation":"Avoid storing sensitive claims in unencrypted JWTs"})
    except Exception: pass
    return findings

def scan_js_bundle(js_url: str) -> tuple:
    secrets, endpoints, oauth_list, extra_findings = [], [], [], []
    try:
        st, _, body = http_get(js_url, timeout=10)
        if st != 200: return secrets, endpoints, oauth_list, extra_findings
        text = body.decode("utf-8", "replace")

        endpoints = sorted({m.group(1).strip() for m in API_ENDPOINT_PATTERN.finditer(text) if len(m.group(1)) > 4 and not m.group(1).endswith((".js",".css"))})
        oauth_list = sorted({m.group(1).strip() for m in OAUTH_REDIRECT_PATTERN.finditer(text) if m.group(1)})

        sm = check_dynamic_sourcemap(js_url, text)
        if sm: extra_findings.append(sm)
        extra_findings.extend(audit_dom_xss_sinks(js_url, text))

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
                for tm in matches[:2]:
                    for jf in audit_jwt_token(tm, js_url):
                        secrets.append({"severity":jf["severity"],"type":jf["title"],"url":js_url,"detail":jf["evidence"],"sample":tm[:35]+"...","command":jf["command"],"remediation":jf["remediation"]})
            secrets.append({
                "severity": "Critical" if name not in ("JWT Token", "Firebase URL") else "Info",
                "type": name, "url": js_url, "detail": f"{len(matches)} match(es)", "sample": sample,
                "command": f'curl -s "{js_url}" | grep -Eo "{pattern[:35]}"',
                "remediation": "Rotate exposed credential and move to backend environment variables"
            })
    except Exception: pass
    return secrets, endpoints, oauth_list, extra_findings

# ── 6. Benign Parameter Reflection Check (Safe Canary Audit) ─────────────────
def check_benign_reflection(urls_with_params: list) -> list:
    """Sends a harmless alphanumeric string (bountyrecon7x9) to check if parameters reflect unencoded."""
    findings = []
    canary = "bountyrecon7x9"
    for raw_url in urls_with_params[:15]:
        try:
            p = urlparse(raw_url)
            qs = parse_qs(p.query, keep_blank_values=True)
            if not qs: continue
            for param in list(qs.keys())[:4]:
                test_qs = dict(qs)
                test_qs[param] = [canary]
                new_query = urlencode(test_qs, doseq=True)
                test_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))
                st, hdrs, body = http_get(test_url, timeout=6)
                if st == 200 and is_html(norm_headers(hdrs).get("content-type",""), body):
                    txt = body.decode("utf-8", "replace")
                    if canary in txt:
                        findings.append({
                            "severity": "Info",
                            "category": "param-reflection",
                            "title": f"Unfiltered Alphanumeric Parameter Reflection: '{param}'",
                            "url": raw_url.split("?")[0],
                            "evidence": f"Benign canary '{canary}' reflected in HTML response for parameter '{param}'",
                            "command": f'curl -sk "{test_url}" | grep -i "{canary}"',
                            "remediation": "Verify context-aware output encoding (HTML entity encoding) is applied to parameter values"
                        })
        except Exception: continue
    return findings

# ── 7. Headers, Cookies, TLS, CORS & Cloud Buckets ───────────────────────────
def check_headers_and_cookies(base_url: str) -> tuple:
    findings, passed = [], []
    try:
        _, hdrs, _ = http_get(base_url, timeout=8)
        h = norm_headers(hdrs)
        for hdr, (sev, impact) in REQUIRED_HEADERS.items():
            if not h.get(hdr):
                findings.append({"severity":sev,"category":"headers","title":f"Header missing: {hdr}","url":base_url,"evidence":impact,"command":f'curl -sI "{base_url}"',"remediation":"Configure security header on web server / CDN"})
            else:
                passed.append(f"{hdr}: present")
        sc_raw = h.get("set-cookie", "")
        for sc in sc_raw.splitlines():
            if "=" in sc:
                c_name = sc.split("=")[0].strip()
                low_sc = sc.lower()
                if "secure" not in low_sc and base_url.startswith("https"):
                    findings.append({"severity":"Low","category":"cookies","title":f"Cookie '{c_name}' missing Secure flag","url":base_url,"evidence":sc[:100],"command":f'curl -sI "{base_url}"',"remediation":"Add Secure attribute"})
    except Exception: pass
    return findings, passed

def check_cors(base_url: str, origins: list) -> list:
    findings = []
    for origin in origins:
        try:
            _, hdrs, _ = http_get(base_url, headers={"Origin": origin}, timeout=6)
            h = norm_headers(hdrs)
            acao, acac = h.get("access-control-allow-origin",""), h.get("access-control-allow-credentials","")
            if origin in acao and "true" in acac.lower():
                findings.append({"severity":"High","category":"cors","title":f"CORS Origin Reflection + Credentials ({origin})","url":base_url,"evidence":f"ACAO: {acao} | ACAC: {acac}","command":f'curl -si -H "Origin: {origin}" "{base_url}"',"remediation":"Validate Origins against a strict allowlist"})
        except Exception: pass
    return findings

def s3_permutations(domain: str) -> list:
    base = domain.split(".")[0]
    prefixes = ["", "dev-", "staging-", "prod-", "backup-", "data-", "assets-", "media-", "static-", "files-", "uploads-", "logs-"]
    buckets = {f"{pref}{base}" for pref in prefixes} | {f"{base}-{pref.rstrip('-')}" for pref in prefixes if pref}
    return sorted(list(buckets))[:30]

def _probe_single_bucket(bucket: str) -> list:
    found = []
    targets = [
        ("AWS S3",     f"https://{bucket}.s3.amazonaws.com",                 "ListBucketResult"),
        ("Google GCS", f"https://storage.googleapis.com/{bucket}",           "ListBucketResult"),
        ("Azure Blob", f"https://{bucket}.blob.core.windows.net/?comp=list", "EnumerationResults"),
    ]
    for prov, url, sig in targets:
        try:
            st, _, body = http_get(url, timeout=5)
            txt = body[:400].decode("utf-8", "replace")
            if st == 200 and sig in txt:
                found.append({"severity":"Critical","category":"cloud-storage","title":f"{prov} Bucket Publicly Listable: {bucket}","url":url,"evidence":txt[:120],"command":f'curl -si "{url}"',"remediation":f"Disable public anonymous access on {prov}"})
        except Exception: continue
    return found

def check_cloud_buckets(domain: str, threads: int = 15) -> list:
    findings = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(_probe_single_bucket, s3_permutations(domain)):
            findings.extend(res)
    return findings

# ── 8. GitHub Repo & Org Recon ───────────────────────────────────────────────
def github_recon(repo: str, org: str, token: str) -> list:
    findings = []
    if not token: return findings
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    scope = f"org:{org}" if org else f"repo:{repo}"
    for pat in ["password", "secret", "api_key", "BEGIN PRIVATE KEY", "AWS_SECRET_ACCESS_KEY"]:
        try:
            url = f"https://api.github.com/search/code?q={pat}+{scope}"
            st, _, body = http_get(url, headers=headers, timeout=10)
            if st == 200:
                total = json.loads(body).get("total_count", 0)
                if total > 0:
                    findings.append({
                        "severity": "High", "category": "github",
                        "title": f"GitHub Secret Match: '{pat}' in {scope} ({total} results)",
                        "url": f"https://github.com/search?q={pat}+{scope}&type=code",
                        "evidence": f"Found {total} code matches via GitHub Search API",
                        "command": f"gh search code '{pat}' { '--owner ' + org if org else '--repo ' + repo }",
                        "remediation": "Revoke exposed credentials and purge commit history"
                    })
        except Exception: pass
    return findings

# ── 9. Wayback Machine ───────────────────────────────────────────────────────
def fetch_wayback_urls(domain: str) -> list:
    interesting = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
    try:
        st, _, body = http_get(url, timeout=15)
        if st == 200:
            rows = json.loads(body.decode("utf-8", "replace"))
            kw = ("/api/", "/v1/", "/graphql", "/admin", ".json", ".env", ".sql", "redirect=", "url=", "next=", "id=", "q=", "search=")
            for row in rows[1:]:
                u = row[0] if isinstance(row, list) and row else ""
                if any(k in u.lower() for k in kw): interesting.add(u)
    except Exception: pass
    return sorted(list(interesting))[:100]

# ── 10. AI Triage & Remediation Agent (--ai-validate) ────────────────────────
def ai_validate_findings(findings: list, api_key: str, base_url: str, model: str) -> list:
    """Uses an OpenAI-compatible LLM endpoint to triage findings, assess false-positive likelihood & advise remediation."""
    if not api_key or not findings:
        return []
    top_findings = sorted(findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4))[:12]
    summary_payload = [{"title": f.get("title"), "severity": f.get("severity"), "url": f.get("url"), "evidence": f.get("evidence","")[:120]} for f in top_findings]
    prompt = (
        "You are a Senior Application Security Engineer reviewing passive recon findings. "
        "For the following JSON findings, provide a concise triage assessment: identify high-priority items, "
        "flag likely false positives, and recommend architectural fixes.\n\n"
        f"Findings:\n{json.dumps(summary_payload, indent=2)}"
    )
    req_data = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }
    try:
        endpoint = f"{base_url.rstrip('/')}/chat/completions"
        st, _, body = http_post(endpoint, req_data, headers={"Authorization": f"Bearer {api_key}"}, timeout=25)
        if st == 200:
            resp = json.loads(body.decode("utf-8", "replace"))
            content = resp.get("choices", [{}])[0].get("message", {}).get("content", "")
            return [line.strip() for line in content.splitlines() if line.strip()]
    except Exception as e:
        return [f"AI validation error: {e}"]
    return []

# ── 11. Interactive HTML Web Dashboard Generator ─────────────────────────────
def generate_html_dashboard(result: ScanResult, out_path: Path):
    s = result.summary
    findings_rows = ""
    for i, f in enumerate(sorted(result.findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4)), 1):
        sev = html.escape(f.get("severity", "Info"))
        badge_col = {"Critical":"bg-red-600","High":"bg-orange-500","Medium":"bg-yellow-500 text-black","Low":"bg-blue-500","Info":"bg-slate-600"}.get(sev, "bg-slate-600")
        title = html.escape(f.get("title") or f.get("detail") or "Finding")
        url   = html.escape(f.get("url") or "")
        ev    = html.escape((f.get("evidence") or "")[:250])
        rem   = html.escape(f.get("remediation") or "")
        findings_rows += f"""
        <tr class="border-b border-slate-800 hover:bg-slate-800/50 finding-row" data-sev="{sev}">
            <td class="p-3"><span class="px-2.5 py-1 rounded text-xs font-bold {badge_col}">{sev}</span></td>
            <td class="p-3 font-medium text-slate-100">{title}<div class="text-xs text-cyan-400 font-mono mt-1">{url}</div></td>
            <td class="p-3 text-xs font-mono text-emerald-400 max-w-md break-all">{ev}</td>
            <td class="p-3 text-xs text-slate-300">{rem}</td>
        </tr>"""

    ai_block = ""
    if result.ai_insights:
        ai_items = "<br>".join(html.escape(line) for line in result.ai_insights)
        ai_block = f"""
        <div class="bg-indigo-950/50 border border-indigo-700 rounded-xl p-5 mb-8">
            <h2 class="text-lg font-bold text-indigo-300 mb-2">🤖 AI Security Triage & Architectural Guidance</h2>
            <div class="text-sm text-slate-200 leading-relaxed">{ai_items}</div>
        </div>"""

    html_doc = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<title>Bounty Recon Dashboard — {html.escape(result.target)}</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-6 font-sans">
<div class="max-w-7xl mx-auto">
    <div class="flex justify-between items-center border-b border-slate-800 pb-5 mb-6">
        <div>
            <h1 class="text-2xl font-bold text-cyan-400">🔍 bounty_recon v{VERSION} — Interactive Dashboard</h1>
            <p class="text-sm text-slate-400">Target: <span class="text-white font-mono">{html.escape(result.target)}</span> | Generated: {html.escape(result.timestamp)}</p>
        </div>
        <div class="flex gap-2">
            <input id="searchBox" onkeyup="filterTable()" placeholder="Search findings, URLs..." class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-white">
            <select id="sevFilter" onchange="filterTable()" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-white">
                <option value="ALL">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Info">Info</option>
            </select>
        </div>
    </div>

    <div class="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
        <div class="bg-slate-900 border border-red-900/60 p-4 rounded-xl"><div class="text-xs text-slate-400">CRITICAL</div><div class="text-2xl font-bold text-red-500">{s.get('critical',0)}</div></div>
        <div class="bg-slate-900 border border-orange-900/60 p-4 rounded-xl"><div class="text-xs text-slate-400">HIGH</div><div class="text-2xl font-bold text-orange-400">{s.get('high',0)}</div></div>
        <div class="bg-slate-900 border border-yellow-900/60 p-4 rounded-xl"><div class="text-xs text-slate-400">MEDIUM</div><div class="text-2xl font-bold text-yellow-400">{s.get('medium',0)}</div></div>
        <div class="bg-slate-900 border border-blue-900/60 p-4 rounded-xl"><div class="text-xs text-slate-400">LOW</div><div class="text-2xl font-bold text-blue-400">{s.get('low',0)}</div></div>
        <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div class="text-xs text-slate-400">SUBDOMAINS</div><div class="text-2xl font-bold text-cyan-400">{len(result.subdomains)}</div></div>
        <div class="bg-slate-900 border border-slate-800 p-4 rounded-xl"><div class="text-xs text-slate-400">API ENDPOINTS</div><div class="text-2xl font-bold text-emerald-400">{len(result.endpoints)}</div></div>
    </div>

    {ai_block}

    <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden mb-8">
        <div class="p-4 border-b border-slate-800 font-bold text-slate-200">Security Findings ({len(result.findings)})</div>
        <table class="w-full text-left text-sm">
            <thead class="bg-slate-950 text-slate-400 text-xs uppercase">
                <tr><th class="p-3">Severity</th><th class="p-3">Finding & Target</th><th class="p-3">Evidence</th><th class="p-3">Remediation</th></tr>
            </thead>
            <tbody id="findingsTable">{findings_rows}</tbody>
        </table>
    </div>
</div>
<script>
function filterTable() {{
    const q = document.getElementById('searchBox').value.toLowerCase();
    const sev = document.getElementById('sevFilter').value;
    document.querySelectorAll('.finding-row').forEach(row => {{
        const matchSev = (sev === 'ALL' || row.getAttribute('data-sev') === sev);
        const matchText = row.innerText.toLowerCase().includes(q);
        row.style.display = (matchSev && matchText) ? '' : 'none';
    }});
}}
</script>
</body>
</html>"""
    out_path.write_text(html_doc, encoding="utf-8")

def generate_markdown(result: ScanResult, out_path: Path):
    lines = [f"# Bounty Recon Report — {result.target}", f"**Version:** {VERSION} | **Generated:** {result.timestamp}", ""]
    if result.ai_insights:
        lines += ["## 🤖 AI Triage Insights", ""] + [f"- {l}" for l in result.ai_insights] + [""]
    lines += ["## Findings", ""]
    for i, f in enumerate(sorted(result.findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4)), 1):
        sev = f.get("severity","Info")
        lines += [f"### {i}. {SEV_EMOJI.get(sev,'')} [{sev}] {f.get('title')}", f"- **Target:** `{f.get('url','')}`", f"- **Evidence:** `{f.get('evidence','')[:200]}`", f"- **Remediation:** {f.get('remediation','')}", ""]
    out_path.write_text("\n".join(lines), encoding="utf-8")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=f"bounty_recon.py v{VERSION} — All-In-One Recon & Security Auditor")
    ap.add_argument("-t","--target",         required=True, help="Target domain (e.g. fluttercee.com)")
    ap.add_argument("--url",                 help="Override primary base URL")
    ap.add_argument("--threads",             type=int, default=15, help="Worker threads (default: 15)")
    ap.add_argument("--max-hosts",           type=int, default=30, help="Max live hosts to scan")
    ap.add_argument("--cors-origin",         action="append", default=[], dest="cors_origins")
    ap.add_argument("--js",                  action="store_true", help="Scan JS secrets, source maps, endpoints & DOM sinks")
    ap.add_argument("--s3",                  action="store_true", help="Check AWS S3, Google GCS & Azure Blob storage")
    ap.add_argument("--wayback",             action="store_true", help="Fetch historical URLs & check benign canary reflection")
    ap.add_argument("--playwright",          action="store_true", help="Headless Playwright crawl")
    ap.add_argument("--nuclei",              action="store_true", help="Run nuclei scanner")
    ap.add_argument("--github-repo",          default="", help="GitHub owner/repo for secret search")
    ap.add_argument("--github-org",          default="", help="GitHub organization for secret search")
    ap.add_argument("--github-token",        default=os.environ.get("GITHUB_TOKEN",""))
    ap.add_argument("--securitytrails-key",  default=os.environ.get("SECURITYTRAILS_API_KEY",""))
    ap.add_argument("--ai-validate",         action="store_true", help="Enable AI triage of findings")
    ap.add_argument("--ai-api-key",          default=os.environ.get("OPENAI_API_KEY",""), help="OpenAI-compatible API key")
    ap.add_argument("--ai-base-url",         default="https://api.openai.com/v1", help="OpenAI-compatible API base URL")
    ap.add_argument("--ai-model",            default="gpt-4o-mini", help="AI model name")
    ap.add_argument("--no-subdomains",       action="store_true", help="Skip subdomain enumeration")
    ap.add_argument("--out-dir",             default="./reports", help="Output directory (default: ./reports)")
    ap.add_argument("--out",                 default="", help="Output filename stem")
    ap.add_argument("--json",                action="store_true", help="Save JSON report")
    ap.add_argument("--html",                action="store_true", help="Save Interactive HTML Web Dashboard")
    ap.add_argument("--serve",               type=int, default=0, help="Serve HTML dashboard on specified port (e.g. 8080)")
    args = ap.parse_args()

    domain   = args.target.replace("https://","").replace("http://","").split("/")[0]
    base_url = args.url.rstrip("/") if args.url else f"https://{domain}"
    out_dir  = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem     = args.out or f"{domain.replace('.','_')}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M')}"
    md_path, jp, hp = out_dir / f"{stem}.md", out_dir / f"{stem}.json", out_dir / f"{stem}.html"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    if HAS_RICH:
        console.print(Panel(f"[bold cyan]bounty_recon.py[/bold cyan] v{VERSION} | Target: [bold]{domain}[/bold] | Base: {base_url}", title="🚀 Bug Bounty Recon & Security Auditor"))

    # 1. Subdomains
    result.subdomains = [domain] if args.no_subdomains else enum_subdomains(domain, args.securitytrails_key)

    # 2. DNS & Takeover
    console.print("\n[bold]2. Concurrent DNS & Subdomain Takeover Audit[/bold]")
    result.dns_records = resolve_dns(result.subdomains, args.threads)
    for host, rec in result.dns_records.items():
        if rec["CNAME"]:
            to = check_dns_takeover(host, rec["CNAME"])
            if to:
                all_findings.append({"severity":"Critical","category":"dns-takeover","title":f"Subdomain Takeover — {to['service']}","url":f"https://{host}","evidence":f"CNAME {to['cname']} → {to['fingerprint']}","command":to["command"],"remediation":"Remove dangling CNAME"})
    all_findings.extend(audit_dns_security(domain))

    # 3. Live Hosts
    console.print("\n[bold]3. Concurrent Live Hosts & Tech Fingerprinting[/bold]")
    candidates = [h for h, r in result.dns_records.items() if r["live"]] or [domain]
    if args.url and urlparse(base_url).hostname not in candidates:
        candidates.insert(0, urlparse(base_url).hostname)
    live = check_live(candidates[:args.max_hosts], args.threads)
    result.live_hosts = [{k: v for k, v in h.items() if k not in ("headers","html")} for h in live]
    for lh in live:
        result.technologies[lh["host"]] = deep_fingerprint_tech(lh["url"], lh.get("headers",{}), lh.get("html",""))
    scan_urls = [base_url] + [h["url"] for h in live if h["url"] != base_url]

    # 4. Endpoints & GraphQL
    console.print("\n[bold]4. Sensitive Endpoint Sweep (Soft-404 Filtered) & GraphQL Introspection[/bold]")
    for u in scan_urls[:args.max_hosts]:
        ef, ep = sweep_endpoints(u, args.threads)
        for f in ef:
            all_findings.append({"severity":"High","category":"exposure","title":f"Exposed Endpoint: {f['url'].split('/')[-1]}","url":f["url"],"evidence":f["snippet"],"command":f["command"],"remediation":"Restrict public access"})
        all_passed.extend(ep)
        all_findings.extend(check_graphql_introspection(u))

    # 5. Headers & Cookies
    console.print("\n[bold]5. Security Headers & Cookie Audit[/bold]")
    for u in scan_urls[:10]:
        hf, hp = check_headers_and_cookies(u)
        all_findings.extend(hf); all_passed.extend(hp)

    # 6. JS Secrets, Source Maps & DOM XSS Sinks
    all_endpoints, all_routes, all_oauth = set(), set(), set()
    if args.js:
        console.print("\n[bold]6. JS Secrets, Dynamic Source Maps & Static DOM XSS Sink Analysis[/bold]")
        js_urls, routes = collect_js_urls(base_url)
        all_routes.update(routes)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            for secs, eps, oas, extras in ex.map(scan_js_bundle, js_urls):
                all_endpoints.update(eps); all_oauth.update(oas); all_findings.extend(extras)
                for sf in secs:
                    all_findings.append({"severity":sf["severity"],"category":"js-secrets","title":f"JS Secret: {sf['type']}","url":sf["url"],"evidence":f"{sf['detail']} | {sf['sample']}","command":sf["command"],"remediation":sf["remediation"]})
        result. endpoints, result.routes, result.oauth_params = sorted(all_endpoints), sorted(all_routes), sorted(all_oauth)

    # 7. Expanded CORS
    console.print("\n[bold]7. Expanded CORS Audit[/bold]")
    origins = list(set(args.cors_origins + ["https://evil.example.com", "null", f"https://attacker.{domain}"]))
    cors_targets = [base_url] + [ep if ep.startswith("http") else f"{base_url}{ep}" for ep in list(all_endpoints)[:10]]
    for ct in dict.fromkeys(cors_targets):
        all_findings.extend(check_cors(ct, origins))

    # 8. Cloud Buckets
    if args.s3:
        console.print("\n[bold]8. Multi-Cloud Storage Audit (AWS S3, GCS, Azure)[/bold]")
        all_findings.extend(check_cloud_buckets(domain, args.threads))

    # 9. GitHub Recon
    if (args.github_repo or args.github_org) and args.github_token:
        console.print("\n[bold]9. GitHub Repo/Org Secret Search[/bold]")
        all_findings.extend(github_recon(args.github_repo, args.github_org, args.github_token))

    # 10. Wayback & Benign Canary Reflection
    if args.wayback:
        console.print("\n[bold]10. Wayback Historical URLs & Safe Canary Reflection Check[/bold]")
        result.wayback_urls = fetch_wayback_urls(domain)
        param_urls = [u for u in result.wayback_urls if "?" in u]
        all_findings.extend(check_benign_reflection(param_urls))

    # Finalize Summary
    result.findings = all_findings
    result.passed = all_passed
    result.summary = {
        "total": len(all_findings),
        "critical": sum(1 for f in all_findings if f.get("severity")=="Critical"),
        "high": sum(1 for f in all_findings if f.get("severity")=="High"),
        "medium": sum(1 for f in all_findings if f.get("severity")=="Medium"),
        "low": sum(1 for f in all_findings if f.get("severity")=="Low"),
        "passed": len(all_passed),
    }

    # 11. AI Validation
    if args.ai_validate:
        console.print("\n[bold]11. Running AI Triage & Remediation Agent[/bold]")
        result.ai_insights = ai_validate_findings(all_findings, args.ai_api_key, args.ai_base_url, args.ai_model)

    generate_markdown(result, md_path)
    console.print(f"\n📄 Markdown Report : {md_path}")
    if args.json:
        jp.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"📄 JSON Report     : {jp}")
    if args.html or args.serve:
        generate_html_dashboard(result, hp)
        console.print(f"🌐 HTML Dashboard  : {hp}")
    if args.serve:
        os.chdir(out_dir)
        console.print(f"\n🚀 Serving Web Dashboard at http://localhost:{args.serve}/{hp.name} (Ctrl+C to stop)")
        with socketserver.TCPServer(("", args.serve), http.server.SimpleHTTPRequestHandler) as httpd:
            httpd.serve_forever()

if __name__ == "__main__":
    main()
