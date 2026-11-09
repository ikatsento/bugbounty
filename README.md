## Comparison with AutoAR

| Feature | bounty_recon v4.0 | AutoAR |
|---------|-------------------|--------|
| Language | Python 3 (Async/Threaded) | Go |
| Install | `pip install` / Docker | Go build / Docker |
| Single file | ✅ (Zero-compile portability) | ❌ (multi-module) |
| Subdomain enum | ✅ 10+ OSINT sources | 15+ sources |
| DNS takeover | ✅ 22 services (HTTP/HTTPS) | ✅ full suite |
| JS secrets & DOM Audit | ✅ 22 patterns + Static DOM Sinks + SourceMaps | ✅ |
| nuclei | ✅ wrapper | ✅ native |
| Cloud buckets | ✅ AWS S3 + Google GCS + Azure Blob | ✅ S3 |
| GitHub recon | ✅ Repo + Org Code Search | ✅ full + org |
| Web dashboard | ✅ Interactive Dark-Mode HTML (`--html` / `--serve`) | ✅ v4.1+ |
| AI agent | ✅ OpenAI / Ollama Triage (`--ai-validate`) | ✅ |
| Docker | ✅ Official `Dockerfile` | ✅ |
