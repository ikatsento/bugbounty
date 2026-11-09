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
| **Interactive HTML UI** | Generates a modern Dark-Mode Tailwind CSS web dashboard with search and severity filters (`--html` / `--serve`) |
| **AI Triage (Optional)** | Integrates with OpenAI-compatible LLMs to triage findings and provide architectural remediation advice (`--ai-validate`) |

---

## 🛠️ Installation & Setup

### Option 1: Local Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ikatsento/bounty_recon.git](https://github.com/ikatsento/bounty_recon.git)
   cd bounty_recon
