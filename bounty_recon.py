#!/usr/bin/env python3
"""
bounty_recon.py — Main Entrypoint
"""
import argparse, datetime, os, http.server, socketserver
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from core.models import ScanResult
from core.subdomains import enum_subdomains
from core.dns_audit import resolve_dns, check_dns_takeover, audit_dns_security
from core.http_scanner import check_live, deep_fingerprint_tech, sweep_endpoints, check_graphql_introspection
from core.js_analyzer import collect_js_urls, scan_js_bundle
from core.cloud_storage import check_cloud_buckets
from core.auditor import check_headers_and_cookies, check_cors, fetch_wayback_urls, check_benign_reflection
from core.reporter import generate_markdown, generate_json, generate_html_dashboard

try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class _C:
        def print(self, *a, **kw): print(*a)
    console = _C()

def main():
    ap = argparse.ArgumentParser(description="bounty_recon.py — Modular Security Auditor")
    ap.add_argument("-t", "--target", required=True, help="Target domain (e.g. fluttercee.com)")
    ap.add_argument("--url", help="Override primary base URL")
    ap.add_argument("--threads", type=int, default=15, help="Worker threads")
    ap.add_argument("--max-hosts", type=int, default=30, help="Max live hosts")
    ap.add_argument("--cors-origin", action="append", default=[], dest="cors_origins")
    ap.add_argument("--js", action="store_true", help="Scan JS secrets, source maps & DOM sinks")
    ap.add_argument("--s3", action="store_true", help="Check Cloud Storage buckets")
    ap.add_argument("--wayback", action="store_true", help="Wayback historical URLs & canary check")
    ap.add_argument("--securitytrails-key", default=os.environ.get("SECURITYTRAILS_API_KEY", ""))
    ap.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enum")
    ap.add_argument("--out-dir", default="./reports", help="Output directory")
    ap.add_argument("--out", default="", help="Output filename stem")
    ap.add_argument("--json", action="store_true", help="Save JSON report")
    ap.add_argument("--html", action="store_true", help="Save Interactive HTML Dashboard")
    ap.add_argument("--serve", type=int, default=0, help="Serve HTML dashboard on port")
    args = ap.parse_args()

    domain = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    base_url = args.url.rstrip("/") if args.url else f"https://{domain}"
    
    # უსაფრთხო დირექტორიების მართვა (არ ავურევთ ტიპებს)
    out_dir_path = Path(args.out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    
    stem = args.out or f"{domain.replace('.','_')}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M')}"
    md_path, jp, hp = out_dir_path / f"{stem}.md", out_dir_path / f"{stem}.json", out_dir_path / f"{stem}.html"

    result = ScanResult(target=domain)
    all_findings, all_passed = [], []

    if HAS_RICH:
        console.print(Panel(f"[bold cyan]bounty_recon.py[/bold cyan] | Target: [bold]{domain}[/bold] | Base: {base_url}", title="🚀 Modular Recon & Auditor"))

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
    live = check_live(candidates[:args.max_hosts], args.threads)
    result.live_hosts = [{k: v for k, v in h.items() if k not in ("headers","html")} for h in live]
    for lh in live:
        result.technologies[lh["host"]] = deep_fingerprint_tech(lh["url"], lh.get("headers",{}), lh.get("html",""))
    scan_urls = [base_url] + [h["url"] for h in live if h["url"] != base_url]

    # 4. Endpoints & GraphQL
    console.print("\n[bold]4. Sensitive Endpoint Sweep & GraphQL Introspection[/bold]")
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

    # 6. JS Secrets & DOM Sinks
    all_endpoints, all_routes, all_oauth = set(), set(), set()
    if args.js:
        console.print("\n[bold]6. JS Secrets, Source Maps & Static DOM XSS Sinks[/bold]")
        js_urls, routes = collect_js_urls(base_url)
        all_routes.update(routes)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            for secs, eps, oas, extras in ex.map(scan_js_bundle, js_urls):
                all_endpoints.update(eps); all_oauth.update(oas); all_findings.extend(extras)
                for sf in secs:
                    all_findings.append({"severity":sf["severity"],"category":"js-secrets","title":f"JS Secret: {sf['type']}","url":sf["url"],"evidence":f"{sf['detail']} | {sf['sample']}","command":sf["command"],"remediation":sf["remediation"]})
        result.endpoints, result.routes, result.oauth_params = sorted(all_endpoints), sorted(all_routes), sorted(all_oauth)

    # 7. CORS
    console.print("\n[bold]7. Expanded CORS Audit[/bold]")
    origins = list(set(args.cors_origins + ["https://evil.example.com", "null", f"https://attacker.{domain}"]))
    for ct in dict.fromkeys([base_url] + [ep if ep.startswith("http") else f"{base_url}{ep}" for ep in list(all_endpoints)[:10]]):
        all_findings.extend(check_cors(ct, origins))

    # 8. Cloud Buckets
    if args.s3:
        console.print("\n[bold]8. Multi-Cloud Storage Audit (AWS S3, GCS, Azure)[/bold]")
        all_findings.extend(check_cloud_buckets(domain, args.threads))

    # 9. Wayback & Canary
    if args.wayback:
        console.print("\n[bold]9. Wayback Historical URLs & Safe Canary Check[/bold]")
        result.wayback_urls = fetch_wayback_urls(domain)
        all_findings.extend(check_benign_reflection([u for u in result.wayback_urls if "?" in u]))

    # Finalize
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

    # Reports
    generate_markdown(result, md_path)
    console.print(f"\n📄 Markdown Report : {md_path}")
    if args.json:
        generate_json(result, jp)
        console.print(f"📄 JSON Report     : {jp}")
    if args.html or args.serve:
        generate_html_dashboard(result, hp)
        console.print(f"🌐 HTML Dashboard  : {hp}")
    
    if args.serve:
        os.chdir(out_dir_path)
        console.print(f"\n🚀 Serving Web Dashboard at http://localhost:{args.serve}/{hp.name} (Ctrl+C to stop)")
        with socketserver.TCPServer(("", args.serve), http.server.SimpleHTTPRequestHandler) as httpd:
            httpd.serve_forever()

if __name__ == "__main__":
    main()
