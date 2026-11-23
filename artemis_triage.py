#!/usr/bin/env python3
"""
artemis_triage.py — ARTEMIS-inspired 3-Phase Vulnerability Triage
==================================================================
Version : 1.0.0
Source  : Adapted from Stanford-Trinity/ARTEMIS (MIT License)

The best part of ARTEMIS for bug bounty: the 3-phase triage system.
Works with Ollama (free) or any OpenAI-compatible API.

Phase 1: Initial Review   — is this finding worth pursuing?
Phase 2: Validation       — reproduce it with a sub-agent
Phase 3: Severity         — CVSS scoring + final report

Usage:
  # Triage a single finding interactively
  python3 artemis_triage.py --finding "SQLi in /api/login param 'email'" --target https://example.com

  # Triage a full scanner.py report
  python3 artemis_triage.py --report reports/example_com_*/summary.md

  # Triage with specific provider
  python3 artemis_triage.py --report summary.md --provider ollama
  python3 artemis_triage.py --report summary.md --provider groq

Requirements:
  pip install httpx rich --break-system-packages
  Ollama: brew install ollama && ollama pull llama3.2 && ollama serve
  Groq:   export GROQ_API_KEY="gsk_..."
"""

import sys, os, re, json, argparse, datetime, urllib.request, hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    HAS_RICH = True
except ImportError:
    class _C:
        def print(self, *a, **kw): print(*a)
        def rule(self, t=""): print(f"\n{'─'*55} {t}")
    console = _C()
    HAS_RICH = False

VERSION = "1.0.0"

# ── AI Provider (same as ai_hunter.py) ───────────────────────────────────────

def ask_ollama(prompt: str, model: str, system: str = "") -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = json.dumps({
        "model": model, "messages": messages,
        "stream": False, "options": {"temperature": 0.2, "num_predict": 2000}
    }).encode()
    req = urllib.request.Request(
        "http://localhost:11434/api/chat", data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read()).get("message", {}).get("content", "")
    except Exception as e:
        return f"[ERROR] Ollama: {e}"

def ask_groq_http(prompt: str, model: str, system: str = "") -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = json.dumps({
        "model": model, "messages": messages,
        "max_tokens": 2000, "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions", data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ.get('GROQ_API_KEY', '')}"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[ERROR] Groq: {e}"

def detect_provider() -> tuple:
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=3) as r:
            models = [m["name"] for m in json.loads(r.read()).get("models", [])]
            if models:
                for pref in ["llama3.2","llama3.1","mistral","qwen2.5","gemma2"]:
                    for m in models:
                        if pref in m.lower():
                            return "ollama", m
                return "ollama", models[0]
    except Exception:
        pass
    if os.environ.get("GROQ_API_KEY"):
        return "groq", "llama-3.3-70b-versatile"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", "claude-sonnet-4-6"
    return "none", ""

def ask_ai(prompt: str, provider: str, model: str, system: str = "") -> str:
    if provider == "ollama":
        return ask_ollama(prompt, model, system)
    elif provider == "groq":
        return ask_groq_http(prompt, model, system)
    elif provider == "anthropic":
        try:
            import anthropic as ant
            client = ant.Anthropic()
            msg = client.messages.create(
                model=model, max_tokens=2000,
                system=system,
                messages=[{"role": "user", "content": prompt}]
            )
            return msg.content[0].text
        except Exception as e:
            return f"[ERROR] Anthropic: {e}"
    return "[ERROR] No provider"

# ── ARTEMIS Triage Prompts (adapted) ─────────────────────────────────────────

TRIAGE_SYSTEM = (
    "You are a senior security triage analyst. Be concise, specific, and decisive. "
    "Focus on exploitability and real-world impact. No theoretical findings. "
    "Output structured responses as requested."
)

def phase1_prompt(finding: dict) -> str:
    """ARTEMIS Phase 1: Initial Review — is this worth pursuing?"""
    return f"""## PHASE 1: INITIAL REVIEW

Vulnerability report to review:
- **Title**: {finding.get('title', 'N/A')}
- **URL/Asset**: {finding.get('url', 'N/A')}
- **Severity**: {finding.get('severity', 'N/A')}
- **Category**: {finding.get('category', 'N/A')}
- **Tool**: {finding.get('tool', 'N/A')}
- **Confidence**: {finding.get('confidence', '?')}%
- **Evidence**: {finding.get('evidence', 'N/A')[:300]}

## Review Checklist:
1. Is the evidence specific and actionable (not generic)?
2. Does this look like a real vulnerability (not a false positive)?
3. Is the impact realistic and significant?
4. Is it worth spending time to validate?

## Decision:
Answer in this exact JSON format:
{{
  "decision": "PROCEED" or "REJECT",
  "reasoning": "2-3 sentences explaining why",
  "risk_assessment": "what an attacker could actually do",
  "validation_plan": "specific steps to confirm this is real (if PROCEED)",
  "fp_indicators": "what makes this look like a false positive (if REJECT)"
}}"""

def phase2_prompt(finding: dict, phase1_result: dict) -> str:
    """ARTEMIS Phase 2: Validation — reproduce it."""
    return f"""## PHASE 2: VALIDATION

You approved this finding. Now write a step-by-step reproduction plan.

**Finding**: {finding.get('title', 'N/A')}
**URL**: {finding.get('url', 'N/A')}
**Category**: {finding.get('category', 'N/A')}
**Evidence**: {finding.get('evidence', 'N/A')[:300]}
**Validation plan from Phase 1**: {phase1_result.get('validation_plan', 'N/A')}

## Your Task:
Write the EXACT commands to reproduce and confirm this vulnerability.
Include:
1. Exact curl/tool commands (copy-paste ready)
2. What response/behavior confirms it's exploitable
3. PoC that demonstrates real impact
4. Any bypasses needed (WAF, auth, etc.)

Answer in this exact JSON format:
{{
  "reproduced": true or false (your assessment based on evidence),
  "confidence": 0-100,
  "repro_steps": ["step 1", "step 2", "step 3"],
  "exact_commands": ["curl -si ...", "sqlmap -u ..."],
  "proof_of_concept": "what output/behavior confirms exploitation",
  "additional_impact": "can this be chained or escalated?",
  "burp_steps": "how to test this in Burp Suite"
}}"""

def phase3_prompt(finding: dict, phase1: dict, phase2: dict) -> str:
    """ARTEMIS Phase 3: Severity — CVSS scoring + final report."""
    return f"""## PHASE 3: SEVERITY ASSESSMENT & FINAL REPORT

**Finding**: {finding.get('title', 'N/A')}
**Category**: {finding.get('category', 'N/A')}
**Original Severity**: {finding.get('severity', 'N/A')}
**Phase 1 Risk Assessment**: {phase1.get('risk_assessment', 'N/A')}
**Phase 2 Reproduced**: {phase2.get('reproduced', '?')} (confidence: {phase2.get('confidence', '?')}%)
**Additional Impact Found**: {phase2.get('additional_impact', 'none')}

## CVSS v3.1 Severity Guide:
- **Critical (9.0-10.0)**: Complete system compromise, no auth needed, remote
- **High (7.0-8.9)**: Significant data access, privilege escalation
- **Medium (4.0-6.9)**: Limited access, requires interaction or auth
- **Low (0.1-3.9)**: Minimal impact, hard to exploit

## Your Task:
Assess final severity and write a bug bounty report.

Answer in this exact JSON format:
{{
  "severity": "Critical|High|Medium|Low",
  "cvss_score": 0.0-10.0,
  "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "severity_reasoning": "why this severity based on CVSS factors",
  "report_title": "clear, specific title for bug bounty submission",
  "report_summary": "2-3 sentence executive summary",
  "business_impact": "what an attacker gains + real-world consequences",
  "remediation": "specific fix recommendation",
  "bounty_estimate": "$XXX-$YYYY (based on typical HackerOne/Bugcrowd payouts)"
}}"""

# ── Parsing helpers ───────────────────────────────────────────────────────────

def parse_json_response(text: str) -> dict:
    """Robustly extract JSON from AI response."""
    # Strip markdown fences
    text = re.sub(r'^```(?:json)?\s*\n?', '', text.strip())
    text = re.sub(r'\n?```\s*$', '', text.strip())
    try:
        return json.loads(text.strip())
    except Exception:
        pass
    # Find outermost {...}
    start = text.find('{')
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i+1])
                    except Exception:
                        break
    # Fallback: extract key values manually
    result = {}
    for key in ["decision","severity","cvss_score","reproduced","confidence"]:
        m = re.search(rf'"{key}"\s*:\s*"?([^",\n}}]+)"?', text)
        if m:
            val = m.group(1).strip().strip('"')
            result[key] = val
    result["_raw"] = text[:500]
    return result

def parse_findings_from_report(report_path: Path) -> list:
    """Extract findings from scanner.py summary.md report."""
    findings = []
    text = report_path.read_text(encoding="utf-8")

    # Match finding blocks: ### N. 🟠 [High] Title
    blocks = re.split(r'\n### \d+\.', text)
    for block in blocks[1:]:  # skip header
        lines = block.strip().splitlines()
        if not lines:
            continue

        title_line = lines[0].strip()
        # Extract severity from emoji or [Severity] pattern
        sev_m = re.search(r'\[(Critical|High|Medium|Low|Info)\]', title_line)
        severity = sev_m.group(1) if sev_m else "Info"

        # Clean title
        title = re.sub(r'^[🔴🟠🟡🔵⚪]\s*\[(?:Critical|High|Medium|Low|Info)\]\s*', '', title_line).strip()

        # Extract URL
        url_m = re.search(r'\*\*URL:\*\*\s*`([^`]+)`', block)
        url = url_m.group(1) if url_m else ""

        # Extract category
        cat_m = re.search(r'\*\*Category:\*\*\s*`([^`]+)`', block)
        category = cat_m.group(1) if cat_m else ""

        # Extract tool
        tool_m = re.search(r'\*\*Tool:\*\*\s*`([^`]+)`', block)
        tool = tool_m.group(1) if tool_m else ""

        # Extract confidence
        conf_m = re.search(r'\*\*Confidence:\*\*\s*(\d+)%', block)
        confidence = int(conf_m.group(1)) if conf_m else 50

        # Extract evidence
        ev_m = re.search(r'```\n(.*?)\n```', block, re.DOTALL)
        evidence = ev_m.group(1).strip() if ev_m else ""

        if severity in ["Critical","High","Medium"] and title:
            findings.append({
                "title": title,
                "severity": severity,
                "url": url,
                "category": category,
                "tool": tool,
                "confidence": confidence,
                "evidence": evidence,
            })

    return findings

# ── 3-Phase Triage ────────────────────────────────────────────────────────────

@dataclass
class TriageResult:
    finding:    dict
    phase1:     dict = field(default_factory=dict)
    phase2:     dict = field(default_factory=dict)
    phase3:     dict = field(default_factory=dict)
    decision:   str  = "PENDING"
    final_severity: str = ""
    cvss_score: float = 0.0
    report_ready: bool = False

def run_triage(finding: dict, provider: str, model: str, verbose: bool = False) -> TriageResult:
    result = TriageResult(finding=finding)
    title = finding.get("title","?")[:60]

    console.print(f"\n  📋 Triaging: [bold]{title}[/bold]" if HAS_RICH
                  else f"\n  Triaging: {title}")

    # ── Phase 1 ───────────────────────────────────────────────────────────────
    console.print("    Phase 1: Initial Review..." if HAS_RICH
                  else "    Phase 1: Initial Review...")
    p1_response = ask_ai(phase1_prompt(finding), provider, model, TRIAGE_SYSTEM)
    result.phase1 = parse_json_response(p1_response)

    if verbose:
        console.print(f"    → {result.phase1.get('decision','?')}: {result.phase1.get('reasoning','')[:100]}")

    if result.phase1.get("decision") == "REJECT":
        result.decision = "REJECTED"
        console.print(f"    ❌ REJECTED: {result.phase1.get('reasoning','')[:80]}")
        return result

    # ── Phase 2 ───────────────────────────────────────────────────────────────
    console.print("    Phase 2: Validation..." if HAS_RICH
                  else "    Phase 2: Validation...")
    p2_response = ask_ai(phase2_prompt(finding, result.phase1), provider, model, TRIAGE_SYSTEM)
    result.phase2 = parse_json_response(p2_response)

    conf = result.phase2.get("confidence", 0)
    try: conf = int(str(conf).replace("%",""))
    except: conf = 0

    if verbose:
        console.print(f"    → Reproduced: {result.phase2.get('reproduced','?')} | Confidence: {conf}%")

    if not result.phase2.get("reproduced", False) and conf < 40:
        result.decision = "LIKELY_FP"
        console.print(f"    ⚠️  Likely false positive (confidence {conf}%)")
        # Still run phase 3 for completeness but mark low confidence
    else:
        result.decision = "CONFIRMED"

    # ── Phase 3 ───────────────────────────────────────────────────────────────
    console.print("    Phase 3: Severity Assessment...")
    p3_response = ask_ai(phase3_prompt(finding, result.phase1, result.phase2),
                         provider, model, TRIAGE_SYSTEM)
    result.phase3 = parse_json_response(p3_response)

    result.final_severity = result.phase3.get("severity", finding.get("severity","?"))
    try:
        result.cvss_score = float(str(result.phase3.get("cvss_score", 0)).split()[0])
    except:
        result.cvss_score = 0.0

    result.report_ready = result.decision == "CONFIRMED"

    sev_emoji = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵"}.get(result.final_severity,"⚪")
    console.print(f"    {sev_emoji} Final: {result.final_severity} (CVSS {result.cvss_score:.1f}) | "
                  f"Bounty: {result.phase3.get('bounty_estimate','unknown')}")

    return result

# ── Report generation ─────────────────────────────────────────────────────────

def generate_triage_report(results: list, out_dir: Path) -> Path:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    path = out_dir / f"triage_report_{ts}.md"

    confirmed = [r for r in results if r.decision == "CONFIRMED"]
    rejected  = [r for r in results if r.decision == "REJECTED"]
    fps       = [r for r in results if r.decision == "LIKELY_FP"]

    sev_emoji = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}

    lines = [
        "# ARTEMIS-Style Triage Report",
        f"Generated: {datetime.datetime.now().isoformat()}",
        f"Tool: artemis_triage.py v{VERSION}",
        "",
        "## Summary",
        "",
        f"| | Count |","|---|---|",
        f"| ✅ Confirmed Real | {len(confirmed)} |",
        f"| ❌ Rejected | {len(rejected)} |",
        f"| ⚠️ Likely FP | {len(fps)} |",
        f"| Total Triaged | {len(results)} |",
        "",
    ]

    if confirmed:
        lines += ["## ✅ Confirmed Vulnerabilities (Submit These)", ""]
        for i, r in enumerate(sorted(confirmed, key=lambda x: -x.cvss_score), 1):
            p3 = r.phase3
            p1 = r.phase1
            p2 = r.phase2
            sev = r.final_severity
            em = sev_emoji.get(sev,"⚪")

            lines += [
                f"### {i}. {em} {p3.get('report_title', r.finding.get('title','?'))}",
                "",
                f"**Severity:** {sev} | **CVSS:** {r.cvss_score:.1f} | "
                f"**Vector:** `{p3.get('cvss_vector','?')}`",
                f"**Bounty Estimate:** {p3.get('bounty_estimate','?')}",
                "",
                f"**Summary:**  \n{p3.get('report_summary', '')}",
                "",
                f"**Business Impact:**  \n{p3.get('business_impact', '')}",
                "",
                "**Reproduction Steps:**",
                "```bash",
            ]
            for step in p2.get("repro_steps", []):
                lines.append(step)
            lines += ["```", ""]

            cmds = p2.get("exact_commands", [])
            if cmds:
                lines += ["**Exact Commands:**","```bash"]
                lines.extend(cmds[:5])
                lines += ["```",""]

            burp = p2.get("burp_steps","")
            if burp:
                lines += [f"**Burp Suite:** {burp}", ""]

            lines += [
                f"**Remediation:** {p3.get('remediation','')}",
                "",
                "---","",
            ]

    if rejected:
        lines += ["## ❌ Rejected (False Positives)", ""]
        for r in rejected:
            lines.append(f"- **{r.finding.get('title','?')}** — {r.phase1.get('reasoning','')[:100]}")
        lines += [""]

    if fps:
        lines += ["## ⚠️ Likely False Positives (Low Confidence)", ""]
        for r in fps:
            lines.append(
                f"- **{r.finding.get('title','?')}** "
                f"(conf {r.phase2.get('confidence','?')}%) — "
                f"{r.phase1.get('reasoning','')[:80]}"
            )
        lines += [""]

    lines += ["---", f"*artemis_triage.py v{VERSION} — Stanford ARTEMIS-inspired triage system*"]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path

# ── Terminal summary ──────────────────────────────────────────────────────────

def print_triage_summary(results: list):
    confirmed = [r for r in results if r.decision == "CONFIRMED"]
    rejected  = [r for r in results if r.decision == "REJECTED"]
    fps       = [r for r in results if r.decision == "LIKELY_FP"]

    if HAS_RICH:
        console.rule("[bold green]TRIAGE RESULTS")
        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("Severity", width=10)
        t.add_column("Title", width=50)
        t.add_column("CVSS", width=6)
        t.add_column("Bounty", width=15)
        t.add_column("Status", width=10)
        for r in sorted(confirmed, key=lambda x: -x.cvss_score):
            em = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵"}.get(r.final_severity,"⚪")
            t.add_row(
                f"{em} {r.final_severity}",
                r.phase3.get("report_title", r.finding.get("title","?"))[:48],
                f"{r.cvss_score:.1f}",
                r.phase3.get("bounty_estimate","?")[:14],
                "✅ Real"
            )
        for r in rejected:
            t.add_row("—", r.finding.get("title","?")[:48], "—", "—", "❌ FP")
        console.print(t)
    else:
        print(f"\n{'─'*60}")
        print(f"Confirmed: {len(confirmed)} | Rejected: {len(rejected)} | FP: {len(fps)}")
        for r in confirmed:
            print(f"  ✅ [{r.final_severity}] CVSS {r.cvss_score:.1f} — {r.phase3.get('report_title',r.finding.get('title','?'))[:60]}")
        for r in rejected:
            print(f"  ❌ REJECTED — {r.finding.get('title','?')[:60]}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description=f"artemis_triage.py v{VERSION} — ARTEMIS-inspired 3-phase vulnerability triage"
    )
    ap.add_argument("--report",    default="", help="scanner.py summary.md report to triage")
    ap.add_argument("--finding",   default="", help="Single finding description to triage")
    ap.add_argument("--url",       default="", help="Target URL for the finding")
    ap.add_argument("--severity",  default="High", help="Reported severity for --finding mode")
    ap.add_argument("--provider",  default="auto",
                    choices=["auto","ollama","groq","anthropic"],
                    help="AI provider")
    ap.add_argument("--model",     default="", help="Override model name")
    ap.add_argument("--out-dir",   default=".", help="Output directory")
    ap.add_argument("--min-sev",   default="Medium",
                    choices=["Critical","High","Medium","Low","Info"],
                    dest="min_sev",
                    help="Only triage findings at or above this severity")
    ap.add_argument("--verbose",   action="store_true")
    args = ap.parse_args()

    # Provider
    if args.provider == "auto":
        provider, model = detect_provider()
    else:
        provider = args.provider
        model = args.model or {
            "ollama": "llama3.2", "groq": "llama-3.3-70b-versatile",
            "anthropic": "claude-sonnet-4-6",
        }.get(provider, "llama3.2")
    if args.model:
        model = args.model

    if provider == "none":
        print("❌ No AI provider found.")
        print("  🦙 Ollama: brew install ollama && ollama pull llama3.2 && ollama serve")
        print("  ⚡ Groq:   export GROQ_API_KEY='gsk_...'")
        sys.exit(1)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    provider_icons = {"ollama":"🦙","groq":"⚡","anthropic":"🤖"}
    console.print(f"\n{provider_icons.get(provider,'?')} ARTEMIS Triage | {provider}/{model}")

    # Collect findings to triage
    findings = []
    SEV_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
    min_sev_level = SEV_ORDER.get(args.min_sev, 2)

    if args.report:
        report_path = Path(args.report)
        if not report_path.exists():
            print(f"❌ Report not found: {report_path}")
            sys.exit(1)
        all_findings = parse_findings_from_report(report_path)
        # Filter by min severity
        findings = [f for f in all_findings
                    if SEV_ORDER.get(f.get("severity","Info"), 4) <= min_sev_level]
        console.print(f"  Loaded {len(all_findings)} findings from report, "
                      f"triaging {len(findings)} (≥ {args.min_sev})")

    elif args.finding:
        findings = [{
            "title":    args.finding,
            "severity": args.severity,
            "url":      args.url,
            "category": "manual",
            "tool":     "manual",
            "confidence": 50,
            "evidence": f"Manually specified: {args.finding}",
        }]
    else:
        ap.print_help()
        sys.exit(1)

    if not findings:
        console.print("No findings to triage.")
        sys.exit(0)

    # Run triage on each finding
    results = []
    for finding in findings:
        result = run_triage(finding, provider, model, args.verbose)
        results.append(result)

    # Summary
    print_triage_summary(results)

    # Save report
    report_path = generate_triage_report(results, out_dir)
    console.print(f"\n📄 Triage report: {report_path}")

    # Quick win summary
    confirmed = [r for r in results if r.decision == "CONFIRMED"]
    if confirmed:
        console.print(f"\n🎯 Submit these {len(confirmed)} findings:")
        for r in sorted(confirmed, key=lambda x: -x.cvss_score)[:5]:
            console.print(f"  CVSS {r.cvss_score:.1f} — {r.phase3.get('report_title', r.finding.get('title','?'))[:60]}")

if __name__ == "__main__":
    main()
