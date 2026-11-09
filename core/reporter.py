import json
import html
from pathlib import Path
from dataclasses import asdict
from core.models import ScanResult, SEV_ORDER, SEV_EMOJI, VERSION

def generate_html_dashboard(result: ScanResult, out_path: Path):
    s = result.summary
    findings_rows = ""
    sorted_findings = sorted(result.findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"), 4))
    
    for f in sorted_findings:
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
    </div>
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
</body>
</html>"""
    out_path.write_text(html_doc, encoding="utf-8")

def generate_markdown(result: ScanResult, out_path: Path):
    lines = [f"# Bounty Recon Report — {result.target}", f"**Version:** {VERSION} | **Generated:** {result.timestamp}", ""]
    for i, f in enumerate(sorted(result.findings, key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4)), 1):
        sev = f.get("severity","Info")
        lines += [f"### {i}. {SEV_EMOJI.get(sev,'')} [{sev}] {f.get('title')}", f"- **Target:** `{f.get('url','')}`", f"- **Evidence:** `{f.get('evidence','')[:200]}`", f"- **Remediation:** {f.get('remediation','')}", ""]
    out_path.write_text("\n".join(lines), encoding="utf-8")

def generate_json(result: ScanResult, out_path: Path):
    out_path.write_text(json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8")
