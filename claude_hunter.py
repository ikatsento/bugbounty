#!/usr/bin/env python3
"""
claude_hunter.py — AI-assisted bug bounty recon loop
=====================================================
Feeds subfinder/amass output to Claude API for intelligent
triage, attack angle selection, and next-step generation.

Inspired by: awarexone/Agentic-Bug-Hunter + secengai.com
             Claude-BugHunter (elementalsouls)

Usage:
  python3 claude_hunter.py -t example.com
  python3 claude_hunter.py -t example.com --recon-only
  python3 claude_hunter.py -t example.com --findings-file report.md
  echo "admin.example.com" | python3 claude_hunter.py -t example.com --stdin

Requirements:
  pip install anthropic httpx
  subfinder (optional): go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  amass (optional):     go install -v github.com/owasp-amass/amass/v4/...@master
"""

import sys, os, json, subprocess, argparse, re, datetime
from pathlib import Path

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False
    print("[!] anthropic not installed: pip install anthropic")

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

MODEL   = "claude-sonnet-4-6"
TIMEOUT = 30

# ── Tool wrappers ─────────────────────────────────────────────────────────────
def run_subfinder(domain: str) -> list[str]:
    """Run subfinder if installed, return list of subdomains."""
    path = subprocess.run(["which","subfinder"], capture_output=True, text=True).stdout.strip()
    if not path:
        print("  [!] subfinder not found — skipping (install: go install ...projectdiscovery/subfinder...)")
        return []
    try:
        result = subprocess.run(
            [path, "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=120
        )
        subs = [s.strip() for s in result.stdout.splitlines() if s.strip()]
        print(f"  [+] subfinder: {len(subs)} subdomains")
        return subs
    except subprocess.TimeoutExpired:
        print("  [!] subfinder timed out")
        return []

def run_amass(domain: str) -> list[str]:
    """Run amass passive if installed."""
    path = subprocess.run(["which","amass"], capture_output=True, text=True).stdout.strip()
    if not path:
        return []
    try:
        result = subprocess.run(
            [path, "enum", "-passive", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=180
        )
        subs = [s.strip() for s in result.stdout.splitlines() if s.strip()]
        print(f"  [+] amass: {len(subs)} subdomains")
        return subs
    except subprocess.TimeoutExpired:
        return []

def run_httpx_probe(subdomains: list[str]) -> list[dict]:
    """Run httpx for live host detection if installed."""
    path = subprocess.run(["which","httpx"], capture_output=True, text=True).stdout.strip()
    if not path or not subdomains:
        return []
    input_str = "\n".join(subdomains)
    try:
        result = subprocess.run(
            [path, "-silent", "-json", "-title", "-tech-detect", "-status-code"],
            input=input_str, capture_output=True, text=True, timeout=120
        )
        live = []
        for line in result.stdout.splitlines():
            try: live.append(json.loads(line))
            except: pass
        print(f"  [+] httpx: {len(live)} live hosts")
        return live
    except subprocess.TimeoutExpired:
        return []

# ── Claude API calls ──────────────────────────────────────────────────────────
def ask_claude(prompt: str, system: str = "") -> str:
    if not HAS_ANTHROPIC:
        return "[ERROR] anthropic not installed"
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": prompt}]
    kwargs = {"model": MODEL, "max_tokens": 1500, "messages": messages}
    if system:
        kwargs["system"] = system
    try:
        msg = client.messages.create(**kwargs)
        return msg.content[0].text
    except Exception as e:
        return f"[ERROR] Claude API: {e}"

def triage_subdomains(domain: str, subdomains: list[str]) -> dict:
    """
    Ask Claude to triage subdomains: flag interesting ones, 
    group by risk, suggest attack angles.
    Returns parsed JSON.
    """
    system = (
        "You are a senior bug bounty hunter. You receive subdomain lists and "
        "output structured JSON triage with no markdown, no preamble. "
        "Output ONLY valid JSON, nothing else."
    )
    sample = subdomains[:80]  # limit context
    prompt = f"""Triage these subdomains for {domain}. 
Subdomains ({len(sample)} of {len(subdomains)} total):
{chr(10).join(sample)}

Return JSON:
{{
  "interesting": ["list of high-value subdomains: admin, dev, staging, api, internal, legacy, vpn, etc"],
  "attack_angles": ["3-5 specific attack vectors based on subdomain names"],
  "takeover_check": ["subdomains using services like heroku, github, vercel, azure, etc"],
  "recon_next": ["3 specific tools/commands to run next"],
  "risk_summary": "one sentence"
}}"""

    response = ask_claude(prompt, system)
    try:
        # Strip any markdown fences if Claude adds them
        clean = re.sub(r'^```(?:json)?\n?', '', response.strip())
        clean = re.sub(r'\n?```$', '', clean.strip())
        return json.loads(clean)
    except Exception:
        return {"raw_response": response, "parse_error": True}

def analyze_tech_stack(domain: str, live_hosts: list[dict]) -> str:
    """Ask Claude to analyze detected tech stack and recommend tests."""
    if not live_hosts:
        return ""
    system = "You are a bug bounty expert. Be concise and specific. Use bullet points."
    tech_summary = []
    for h in live_hosts[:20]:
        entry = f"{h.get('url','?')} [{h.get('status-code','?')}] tech={h.get('tech',[])} title={h.get('title','')}"
        tech_summary.append(entry)

    prompt = f"""Tech stack detected on {domain}:
{chr(10).join(tech_summary)}

For each tech, give:
1. The most impactful vulnerability class to test
2. One specific tool or payload to use
3. One nuclei template tag that covers it

Format: short bullet list per host, max 300 words total."""

    return ask_claude(prompt, system)

def generate_attack_plan(domain: str, findings_text: str) -> str:
    """Given a recon report, generate a prioritized attack plan."""
    system = (
        "You are a senior penetration tester. Generate a practical, "
        "step-by-step attack plan based on the recon findings. "
        "Prioritize by severity and exploitability. Be specific."
    )
    prompt = f"""Target: {domain}

Recon findings summary:
{findings_text[:3000]}

Generate:
1. Top 3 attack chains to pursue first (with specific steps)
2. Tools and commands to use for each
3. What to look for in responses
4. Estimated effort per chain (low/medium/high)
Keep total response under 500 words."""

    return ask_claude(prompt, system)

def suggest_payloads(tech: str, vuln_type: str) -> str:
    """Get Claude to recommend specific payloads for a tech/vuln combination."""
    system = "You are a bug bounty payload specialist. Output only the payloads and minimal explanation."
    prompt = f"""Tech: {tech}
Vulnerability type: {vuln_type}

Give me:
- 5 specific payloads optimized for this tech stack
- Any detection canary first (safe to test)
- WAF bypass variants if relevant
- One curl command to test the most likely vector

Max 200 words."""
    return ask_claude(prompt, system)

# ── Report ────────────────────────────────────────────────────────────────────
def save_report(domain: str, data: dict, out_dir: Path):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    path = out_dir / f"claude_hunt_{domain.replace('.','_')}_{ts}.md"
    lines = [
        f"# Claude Hunter Report — {domain}",
        f"Generated: {datetime.datetime.now().isoformat()}",
        "",
    ]
    if data.get("triage"):
        t = data["triage"]
        lines += ["## Subdomain Triage", ""]
        if t.get("risk_summary"):
            lines.append(f"**Risk Summary:** {t['risk_summary']}")
            lines += [""]
        if t.get("interesting"):
            lines += ["### High-Value Subdomains",""]
            for s in t["interesting"]: lines.append(f"- `{s}`")
            lines += [""]
        if t.get("attack_angles"):
            lines += ["### Attack Angles",""]
            for a in t["attack_angles"]: lines.append(f"- {a}")
            lines += [""]
        if t.get("takeover_check"):
            lines += ["### Takeover Candidates",""]
            for s in t["takeover_check"]: lines.append(f"- `{s}`")
            lines += [""]
        if t.get("recon_next"):
            lines += ["### Next Steps",""]
            for step in t["recon_next"]: lines.append(f"- {step}")
            lines += [""]

    if data.get("tech_analysis"):
        lines += ["## Tech Stack Analysis","", data["tech_analysis"], ""]

    if data.get("attack_plan"):
        lines += ["## AI Attack Plan","", data["attack_plan"], ""]

    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n📄 Claude Hunter report saved: {path}")
    return path

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="claude_hunter.py — AI-assisted bug bounty recon")
    ap.add_argument("-t","--target",         required=True, help="Target domain")
    ap.add_argument("--recon-only",          action="store_true", help="Only run tools, skip Claude AI")
    ap.add_argument("--findings-file",       default="", help="Existing bounty_recon.py report .md file to analyze")
    ap.add_argument("--stdin",               action="store_true", help="Read subdomains from stdin")
    ap.add_argument("--tech",                default="", help="Tech stack for payload suggestion (e.g. 'Next.js React')")
    ap.add_argument("--vuln",                default="", help="Vuln type for payload suggestion (e.g. 'XSS')")
    ap.add_argument("--out-dir",             default=".", help="Output directory")
    args = ap.parse_args()

    domain  = args.target.replace("https://","").replace("http://","").split("/")[0]
    out_dir = Path(args.out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    data    = {}

    print(f"\n🤖 Claude Hunter — {domain}")
    print(f"   Model: {MODEL}")

    # ── Payload suggestion mode ───────────────────────────────────────────────
    if args.tech and args.vuln:
        print(f"\n[*] Payload suggestion: {args.tech} × {args.vuln}")
        result = suggest_payloads(args.tech, args.vuln)
        print(result)
        return

    # ── Findings analysis mode ────────────────────────────────────────────────
    if args.findings_file:
        f = Path(args.findings_file)
        if not f.exists():
            print(f"[!] File not found: {f}")
            sys.exit(1)
        print(f"\n[*] Analyzing findings from: {f.name}")
        plan = generate_attack_plan(domain, f.read_text(encoding="utf-8"))
        data["attack_plan"] = plan
        save_report(domain, data, out_dir)
        print("\n" + plan)
        return

    # ── Full recon mode ───────────────────────────────────────────────────────
    # Collect subdomains
    subdomains = []
    if args.stdin:
        subdomains = [l.strip() for l in sys.stdin if l.strip()]
        print(f"  Read {len(subdomains)} subdomains from stdin")
    else:
        print("\n[1] Subdomain enumeration")
        s1 = run_subfinder(domain)
        s2 = run_amass(domain)
        subdomains = sorted(set(s1 + s2 + [domain]))
        print(f"  Total unique: {len(subdomains)}")

    # Live host detection
    print("\n[2] Live host probe (httpx)")
    live_hosts = run_httpx_probe(subdomains)

    if args.recon_only:
        print("\n[*] --recon-only: skipping Claude analysis")
        for h in live_hosts[:20]:
            print(f"  {h.get('url','')} [{h.get('status-code','')}] {h.get('title','')}")
        return

    # Claude triage
    print("\n[3] Claude subdomain triage")
    triage = triage_subdomains(domain, subdomains)
    data["triage"] = triage

    if not triage.get("parse_error"):
        print(f"\n  🎯 Interesting: {', '.join(triage.get('interesting',[])[:5])}")
        print(f"  ⚡ Attack angles:")
        for a in triage.get("attack_angles",[]):
            print(f"     • {a}")
        if triage.get("takeover_check"):
            print(f"  ⚠️  Takeover candidates: {', '.join(triage.get('takeover_check',[]))}")
    else:
        print(f"  Raw response: {triage.get('raw_response','')[:200]}")

    # Tech analysis
    if live_hosts:
        print("\n[4] Claude tech stack analysis")
        tech_analysis = analyze_tech_stack(domain, live_hosts)
        data["tech_analysis"] = tech_analysis
        print(tech_analysis[:400])

    save_report(domain, data, out_dir)

if __name__ == "__main__":
    main()
