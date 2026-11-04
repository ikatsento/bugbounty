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

import sys, ssl, json, socket, asyncio, datetime, subprocess, argparse, re, os
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

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION  = "2.0.0"
TIMEOUT  = 12
UA       = f"bounty-recon/{VERSION} (passive security scanner)"

# JS secret patterns (inspired by AutoAR regexes dir)
JS_SECRET_PATTERNS = {
    "AWS Access Key":        r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":        r'aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "OpenAI Key":            r'sk-[a-zA-Z0-9]{20,}',
    "Google API Key":        r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token":          r'gh[pousr]_[A-Za-z0-9]{36,}',
    "JWT Token":             r'ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "Bearer Token":          r'[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}',
    "Slack Token":           r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    "Stripe Key":            r'sk_live_[0-9a-zA-Z]{24,}',
    "SendGrid Key":          r'SG\.[A-Za-z0-9\-_]{22,}',
    "Generic API Key":       r'["\']api[_-]?key["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Generic Secret":        r'["\']secret["\']\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Password in URL":       r'https?://[^:]+:[^@]+@[^\s]+',
}

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
    timestamp:    str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat()+"Z")
    subdomains:   list = field(default_factory=list)
    dns_records:  dict = field(default_factory=dict)
    live_hosts:   list = field(default_factory=list)
    technologies: dict = field(default_factory=dict)
    findings:     list = field(default_factory=list)
    passed:       list = field(default_factory=list)
    summary:      dict = field(default_factory=dict)

SEV_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
SEV_EMOJI = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}

# ── HTTP helper ───────────────────────────────────────────────────────────────
def http_get(url: str, headers: dict = None, follow: bool = True, timeout: int = TIMEOUT):
    h = {"User-Agent": UA, "Accept": "*/*"}
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

# ── 1. Subdomain enumeration ──────────────────────────────────────────────────
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
    console.print("  → crt.sh certificate transparency")
    subs = enum_subdomains_crtsh(domain)
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
                snippet = body[:250].decode("utf-8","replace").replace("\n"," ").strip()
                findings.append({
                    "url": url, "status": status, "content_type": ct,
                    "snippet": snippet[:180],
                    "command": f'curl -si --noproxy "*" "{url}"',
                })
            elif status == 200:
                passed.append(f"{url} → 200 html/SPA (FP)")
            elif status in (401, 403):
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
                    "command": f'curl -sI --noproxy "*" "{base_url}"',
                    "remediation": "Add via Cloudflare Transform Rule or web server config",
                })
            else:
                passed.append(f"{hdr}: {val[:60]}")
        # Weak CSP
        csp = h.get("content-security-policy","")
        if csp:
            if "unsafe-inline" in csp:
                findings.append({"severity":"Medium","header":"CSP-unsafe-inline","url":base_url,
                    "detail":"CSP 'unsafe-inline' — inline XSS possible","command":"","remediation":"Use nonces instead"})
            if "unsafe-eval" in csp:
                findings.append({"severity":"Medium","header":"CSP-unsafe-eval","url":base_url,
                    "detail":"CSP 'unsafe-eval' — eval() XSS possible","command":"","remediation":"Remove unsafe-eval; use wasm-unsafe-eval if needed"})
            if re.search(r"default-src\s+\*", csp):
                findings.append({"severity":"High","header":"CSP-wildcard","url":base_url,
                    "detail":"CSP default-src is wildcard (*) — CSP defeated","command":"","remediation":"Lock to specific origins"})
        # Server version disclosure
        server = h.get("server","")
        if server and any(c.isdigit() for c in server):
            findings.append({"severity":"Low","header":"server-version","url":base_url,
                "detail":f"Server version disclosed: {server}","command":f'curl -sI "{base_url}"',
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
                    days = (exp - datetime.datetime.utcnow()).days
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
                findings.append({"origin":origin,"severity":"Medium","url":base_url,
                    "detail":"CORS wildcard (*) — broad but no credentials",
                    "evidence":f"ACAO: {acao}",
                    "command":f'curl -si -H "Origin: {origin}" "{base_url}"',
                    "remediation":"Restrict allowed origins explicitly"})
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
        ("/.well-known/jwks.json",           "High",     "JWKS endpoint exposed — RSA public key disclosed"),
        ("/.well-known/openid-configuration","Medium",   "OIDC config endpoint exposed"),
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
                snippet = body[:200].decode("utf-8","replace").replace("\n"," ").strip()
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
def collect_js_urls(base_url: str) -> list:
    js_urls = []
    try:
        _, _, body = http_get(base_url, timeout=10)
        text = body.decode("utf-8","replace")
        # Find all .js references
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', text):
            src = m.group(1)
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("//"):
                js_urls.append("https:" + src)
            elif src.startswith("/"):
                from urllib.parse import urlparse
                p = urlparse(base_url)
                js_urls.append(f"{p.scheme}://{p.netloc}{src}")
    except Exception: pass
    return list(set(js_urls))[:30]

def scan_js_secrets(js_url: str) -> list:
    secrets = []
    try:
        status, _, body = http_get(js_url, timeout=10)
        if status != 200: return secrets
        text = body.decode("utf-8","replace")
        for name, pattern in JS_SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                secrets.append({
                    "severity":"Critical","type":name,"url":js_url,
                    "detail":f"{len(matches)} match(es) of '{name}' pattern",
                    "sample":matches[0][:60],
                    "command":f'curl -s "{js_url}" | grep -Eo "{pattern[:40]}"',
                    "remediation":"Rotate secret immediately; remove from client-side code",
                })
    except Exception: pass
    return secrets

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
    ap.add_argument("--js",                  action="store_true", help="Scan JavaScript files for secrets")
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
    args = ap.parse_args()

    domain   = args.target.replace("https://","").replace("http://","").split("/")[0]
    base_url = args.url or f"https://{domain}"
    out_dir  = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem     = args.out or f"{domain.replace('.','_')}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M')}"
    md_path  = out_dir / f"{stem}.md"
    jp       = out_dir / f"{stem}.json"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    if HAS_RICH:
        console.print(Panel(
            f"[bold cyan]bounty_recon.py[/bold cyan] v{VERSION}\n"
            f"Target  : [bold]{domain}[/bold]\n"
            f"Base URL: {base_url}\n"
            f"nuclei={args.nuclei}  js={args.js}  s3={args.s3}",
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

    # ── 3. Live hosts + tech ──────────────────────────────────────────────────
    console.print("\n[bold]3. Live Host Detection + Tech[/bold]" if HAS_RICH else "\n3. Live Hosts")
    candidate = [h for h,r in dns_records.items() if r["live"]] or [domain]
    live = check_live(candidate[:20])
    result.live_hosts = live
    console.print(f"  {len(live)} live host(s)" if HAS_RICH else f"  {len(live)} live hosts")
    for lh in live:
        h_resp = {}
        try: _, h_resp, _ = http_get(lh["url"], timeout=6)
        except: pass
        techs = fingerprint_tech(lh["url"], h_resp)
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

    # ── 5. Security headers ───────────────────────────────────────────────────
    console.print("\n[bold]5. Security Headers[/bold]" if HAS_RICH else "\n5. Security Headers")
    for url in scan_urls[:5]:
        hf, hp = check_headers(url)
        for f in hf:
            all_findings.append({
                "severity":f["severity"],"category":"headers",
                "title":f"Header issue: {f['header']}",
                "url":f.get("url",url),"command":f.get("command",""),
                "evidence":f.get("detail",""),
                "remediation":f.get("remediation",""),
            })
        all_passed.extend(hp)

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

    # ── 9. JS secrets (optional) ──────────────────────────────────────────────
    if args.js:
        console.print("\n[bold]9. JS Secrets Scan[/bold]" if HAS_RICH else "\n9. JS Secrets")
        js_urls = collect_js_urls(primary)
        console.print(f"  Found {len(js_urls)} JS URLs")
        for ju in js_urls[:20]:
            for sf in scan_js_secrets(ju):
                all_findings.append({
                    "severity":sf["severity"],"category":"js-secrets",
                    "title":f"Secret in JS: {sf['type']}",
                    "url":sf["url"],"command":sf["command"],
                    "evidence":sf["detail"],
                    "remediation":sf["remediation"],
                })

    # ── 10. S3 (optional) ─────────────────────────────────────────────────────
    if args.s3:
        console.print("\n[bold]10. S3 Bucket Check[/bold]" if HAS_RICH else "\n10. S3 Buckets")
        for sf in check_s3_buckets(domain):
            all_findings.append({
                "severity":sf["severity"],"category":"s3",
                "title":f"S3: {sf['detail']}",
                "url":f"https://{sf['bucket']}.s3.amazonaws.com",
                "command":sf["command"],
                "evidence":sf.get("snippet",""),
                "remediation":sf.get("remediation",""),
            })

    # ── 11. GitHub (optional) ─────────────────────────────────────────────────
    if args.github_repo and args.github_token:
        console.print("\n[bold]11. GitHub Recon[/bold]" if HAS_RICH else "\n11. GitHub")
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

    # ── 12. nuclei (optional) ─────────────────────────────────────────────────
    if args.nuclei:
        console.print("\n[bold]12. nuclei Scan[/bold]" if HAS_RICH else "\n12. nuclei")
        for url in scan_urls[:3]:
            for n in run_nuclei(url, out_dir):
                if "error" in n:
                    all_passed.append(f"nuclei: {n['error']}")
                else:
                    all_findings.append(n)

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
