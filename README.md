# 🔍 Bounty Recon & Security Auditor

**Modular Bug Bounty Passive Recon, Misconfiguration & Vulnerability Scanner**  
A powerful, multi-threaded single/multi-module Python & Docker tool designed for reconnaissance, asset discovery, and automated security auditing.

---

## 🚀 Features & Modules

| Module | Description |
|--------|-------------|
| **Subdomain Enum** | Passive OSINT via 9+ sources (crt.sh, AlienVault OTX, URLScan, CertSpotter, ThreatMiner, Anubis, RapidDNS, HackerTarget, SecurityTrails) |
| **DNS Audit & Takeover** | A/CNAME/MX resolution + Dangling CNAME takeover detection (22+ services with HTTP/HTTPS fallback) |
| **Live Host & Tech** | Concurrent HTTP/host reachability + deep passive technology fingerprinting |
| **Endpoint Sweep** | Sensitive path discovery (60+ paths) equipped with a **Soft-404 Baseline Filter** to eliminate false positives |
| **GraphQL Introspection** | Automated schema introspection check on `/graphql` and `/api/graphql` |
| **JS Secrets & SourceMaps** | Scans JS bundles for 22+ secret patterns, extracts endpoints, OAuth params, and parses Webpack/Vite source maps |
| **Static DOM Sinks** | Static analysis of JavaScript code to detect unvalidated URL sources flowing into dangerous sinks (`innerHTML`, `document.write`, `eval`) |
| **Multi-Cloud Storage** | Audits public container/bucket listings across **AWS S3**, **Google Cloud Storage (GCS)**, and **Azure Blob Storage** |
| **Wayback & Canary** | Fetches historical parameterized endpoints from Archive.org and runs a safe parameter reflection check |
| **0day & CVE Fingerprinting** | Detects vulnerable versions of N-central, ScreenConnect, Novalink, MOVEit, Citrix, etc. (passive, non-exploitative) |
| **Interactive HTML UI** | Generates a modern Dark-Mode Tailwind CSS web dashboard with search and severity filters (`--html` / `--serve`) |
| **AI Triage (Optional)** | Integrates with OpenAI-compatible LLMs to triage findings and provide architectural remediation advice (`--ai-validate`) |

---

## 🛡️ 0day & CVE Passive Detection

This tool includes dedicated modules to fingerprint systems known to have critical vulnerabilities (inspired by the `Oracle-Security/CVEs` repository). **These modules are strictly passive and non-intrusive.** They do not exploit the vulnerabilities; they only check for public indicators of exposure.

The following systems are currently fingerprinted:
- **N-able N-central** (Able2Shell 0days & CVE-2026-86218) - *Checks for version disclosure.*
- **IBM PowerVM Novalink** (CVE-2026-12943 / CVE-2026-14971) - *Checks if TCP port 1657 is exposed.*
- **ConnectWise ScreenConnect** (CVE-2024-1709) - *Checks if `/SetupWizard.aspx/` is exposed.*
- **DotNetNuke** (CVE-2018-14486) - *Fingerprints DNN version.*
- **Parallels RAS** (CVE-2023-45894) - *Fingerprints RAS version.*
- **QStar Archive** (CVE-2023-51062 to 51070) - *Checks for specific vulnerable endpoints.*
- **MOVEit Transfer** (CVE-2023-34362) - *Detects exposed `/human.aspx` login page.*
- **Citrix NetScaler** (CVE-2023-4966 - Citrix Bleed) - *Checks OIDC endpoint behavior.*
- **Apache OFBiz** (CVE-2023-51467) - *Checks for exposed `/webtools/control/ProgramExport`.*
- **WordPress** - *Checks if the REST API allows user enumeration.*

---

## 🛠️ Installation & Setup

### Option 1: Local Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ikatsento/bounty_recon.git
   cd bounty_recon
