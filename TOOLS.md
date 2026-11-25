# 🧰 The Tool Catalog

Every tool worth knowing, grouped by phase, de-duplicated, and tagged.
This is the *breadth* reference — `ARSENAL.md` is the *depth* (payloads, oneliners,
submission rules), and `bounty_recon.py` automates a large slice of it.

**Legend** &nbsp; ⭐ = modern default / most-used &nbsp; 🧩 = Burp/browser extension &nbsp; 💤 = useful but low maintenance (verify before relying)

> Install the whole modern stack in one go: see [§ One-shot install](#-one-shot-install) at the bottom.

---

## 📑 Index

| Phase | Jump |
|---|---|
| 0 · Scope & program data | [link](#0--scope--program-data) |
| 1 · Subdomain enumeration | [link](#1--subdomain-enumeration) |
| 2 · DNS, permutation & resolving | [link](#2--dns-permutation--resolving) |
| 3 · Port scanning & network | [link](#3--port-scanning--network) |
| 4 · Live hosts, tech & TLS fingerprint | [link](#4--live-hosts-tech--tls-fingerprint) |
| 5 · Screenshots / visual triage | [link](#5--screenshots--visual-triage) |
| 6 · URL & JS harvesting | [link](#6--url--js-harvesting) |
| 7 · Content & API discovery | [link](#7--content--api-discovery) |
| 8 · Parameter discovery | [link](#8--parameter-discovery) |
| 9 · URL list wrangling (tomnomnom stack) | [link](#9--url-list-wrangling-the-tomnomnom-stack) |
| 10 · Secrets, JS & git exposure | [link](#10--secrets-js--git-exposure) |
| 11 · Vulnerability scanners | [link](#11--vulnerability-scanners) |
| 12 · Per-class exploitation | [link](#12--per-class-exploitation) |
| 13 · Cloud, buckets & origin-IP | [link](#13--cloud-buckets--origin-ip) |
| 14 · Subdomain takeover | [link](#14--subdomain-takeover) |
| 15 · Auth: JWT / OAuth / SSO | [link](#15--auth-jwt--oauth--sso) |
| 16 · Proxies & interception | [link](#16--proxies--interception) |
| 17 · Monitoring & continuous recon | [link](#17--monitoring--continuous-recon) |
| 18 · Mobile & thick client | [link](#18--mobile--thick-client) |
| 19 · Automation frameworks | [link](#19--automation-frameworks) |
| 20 · AI-assisted | [link](#20--ai-assisted) |
| 21 · Wordlists & payloads | [link](#21--wordlists--payloads) |

---

## 0 · Scope & program data
| Tool | Repo | What it does |
|---|---|---|
| ⭐ bbscope | `sw33tLie/bbscope` | Pull in-scope targets from H1/Bugcrowd/Intigriti/YesWeHack/Immunefi |
| bounty-targets-data | `arkadiyt/bounty-targets-data` | Hourly dumps of all public program scopes |
| Hacker-Scoper | `ItsIgnacioPortal/Hacker-Scoper` | Filter a URL/IP list down to in-scope only |
| BigBountyRecon | `Viralmaniar/BigBountyRecon` | 58 Google-dork launchers for initial recon |

## 1 · Subdomain enumeration
**Passive first, then resolve + brute. Run several, `anew` into one list.**

| Tool | Repo | Notes |
|---|---|---|
| ⭐ subfinder | `projectdiscovery/subfinder` | Passive, ~58 sources; add API keys for depth |
| ⭐ amass | `owasp-amass/amass` | Passive + active, CT logs, ASN mapping (the heavy one) |
| ⭐ bbot | `blacklanternsecurity/bbot` | Recursive multi-stage scanner (recon → modules) |
| assetfinder | `tomnomnom/assetfinder` | Quick first-pass |
| Findomain | `Findomain/Findomain` | Fast cross-platform enumerator |
| chaos-client | `projectdiscovery/chaos-client` | ProjectDiscovery's free CT/subdomain dataset |
| github-subdomains | `gwen001/github-subdomains` | Subdomains mined from GitHub code search |
| gitlab-subdomains | `gwen001/gitlab-subdomains` | Same, for GitLab |
| csprecon | `edoardottt/csprecon` | Pull domains out of `Content-Security-Policy` headers |
| cero | `glebarez/cero` | Scrape hostnames from TLS certs on an IP range |
| shosubgo | `incogbyte/shosubgo` | Subdomains via Shodan API |
| subdominator | `RevoltSecurities/Subdominator` | Fast passive enum |
| Sublist3r 💤 | `aboul3la/Sublist3r` | Classic; slower, fewer sources now |
| Knockpy 💤 | `guelfoweb/knock` | Wordlist DNS enum |

## 2 · DNS, permutation & resolving
| Tool | Repo | Notes |
|---|---|---|
| ⭐ dnsx | `projectdiscovery/dnsx` | Fast multi-type DNS toolkit (resolve, CNAME, probe) |
| ⭐ puredns | `d3mondev/puredns` | Resolve + brute with wildcard filtering (massdns wrapper) |
| ⭐ alterx | `projectdiscovery/alterx` | DSL-driven permutation wordlists |
| massdns | `blechschmidt/massdns` | High-perf stub resolver (bulk) |
| shuffledns | `projectdiscovery/shuffledns` | massdns wrapper, wildcard-aware brute |
| gotator | `Josue87/gotator` | Permutation generator |
| dnsgen | `AlephNullSK/dnsgen` | Name permutations from a seed list |
| ripgen | `resyncgg/ripgen` | Fast Rust permutations |
| hakrevdns | `hakluke/hakrevdns` | Mass reverse DNS |

## 3 · Port scanning & network
| Tool | Repo | Notes |
|---|---|---|
| ⭐ naabu | `projectdiscovery/naabu` | Fast Go SYN/CONNECT scanner, feeds httpx |
| ⭐ nmap | `nmap/nmap` | Deep service/version + NSE scripts |
| masscan | `robertdavidgraham/masscan` | Internet-scale async SYN |
| RustScan | `RustScan/RustScan` | Fast front-end, hands ports to nmap |
| naabu→nmap | — | Common combo: naabu for speed, nmap `-sV` on the hits |
| nrich | `shodan-public/nrich` (GitLab) | Annotate IPs with open ports/CVEs via Shodan |
| asnmap | `projectdiscovery/asnmap` | ASN → CIDR ranges |
| mapcidr | `projectdiscovery/mapcidr` | CIDR/subnet math on lists |
| cut-cdn | `ImAyrix/cut-cdn` | Strip CDN IPs before scanning origins |

## 4 · Live hosts, tech & TLS fingerprint
| Tool | Repo | Notes |
|---|---|---|
| ⭐ httpx | `projectdiscovery/httpx` | Probe live hosts, status/title/tech/hash — the hub |
| ⭐ tlsx | `projectdiscovery/tlsx` | TLS grabber (SANs, issuer, expiry) |
| whatweb | `urbanadventurer/whatweb` | Tech fingerprinting |
| webanalyze | `rverton/webanalyze` | Mass Wappalyzer-style detection |
| wafw00f | `EnableSecurity/wafw00f` | Identify the WAF vendor |
| cdncheck | `projectdiscovery/cdncheck` | Flag CDN/WAF/cloud behind an IP |
| graphw00f | `dolevf/graphw00f` | Fingerprint the GraphQL engine |
| fingerprintx | `praetorian-inc/fingerprintx` | Service ID on arbitrary open ports |
| MurMurHash | `Viralmaniar/MurMurHash` | Favicon hash → pivot to sibling hosts |

## 5 · Screenshots / visual triage
| Tool | Repo | Notes |
|---|---|---|
| ⭐ gowitness | `sensepost/gowitness` | Chrome-headless screenshots at scale |
| aquatone 💤 | `michenriksen/aquatone` | Classic visual attack-surface grid |
| EyeWitness | `FortyNorthSecurity/EyeWitness` | Screens + headers + default-cred hints |
| eyeballer | `BishopFox/eyeballer` | ML triage of "which screenshot matters" |
| Depix | `beurtschipper/Depix` | Recover text from pixelated redactions |

## 6 · URL & JS harvesting
| Tool | Repo | Notes |
|---|---|---|
| ⭐ katana | `projectdiscovery/katana` | Active crawler, JS-aware, headless mode |
| ⭐ gau | `lc/gau` | Known URLs from Wayback + OTX + CommonCrawl |
| ⭐ waymore | `xnl-h4ck3r/waymore` | gau on steroids — more archives, downloads responses |
| waybackurls | `tomnomnom/waybackurls` | Minimal Wayback fetcher |
| hakrawler | `hakluke/hakrawler` | Fast lightweight crawler |
| gospider | `jaeles-project/gospider` | Go spider, forms + sitemaps |
| urlfinder | `projectdiscovery/urlfinder` | Passive URL gathering |
| getJS | `003random/getJS` | Pull every `<script src>` |
| ⭐ jsluice | `BishopFox/jsluice` | Extract URLs/paths/secrets from JS *by AST usage* (low-FP) |
| LinkFinder | `GerbenJavado/LinkFinder` | Regex endpoints in JS |
| xnLinkFinder | `xnl-h4ck3r/xnLinkFinder` | Endpoints + params + target wordlist |
| wakaru | `pionxzh/wakaru` | Un-bundle/decompile webpack JS for reading |
| jsmon | `robre/jsmon` | Diff JS files over time (new endpoints appear here) |

## 7 · Content & API discovery
| Tool | Repo | Notes |
|---|---|---|
| ⭐ ffuf | `ffuf/ffuf` | The fuzzer — dirs, vhosts, params, with `-ac` |
| ⭐ feroxbuster | `epi052/feroxbuster` | Recursive content discovery (Rust) |
| ⭐ kiterunner | `assetnote/kiterunner` | API route brute using real request schemas |
| dirsearch | `maurosoria/dirsearch` | Python path scanner |
| gobuster | `OJ/gobuster` | dir/dns/vhost/s3 modes |
| wfuzz 💤 | `xmendez/wfuzz` | Flexible classic fuzzer |
| uncover | `projectdiscovery/uncover` | Query Shodan/Censys/Fofa for exposed hosts |
| cariddi | `edoardottt/cariddi` | Crawl + flag endpoints/secrets/keys in one pass |

## 8 · Parameter discovery
| Tool | Repo | Notes |
|---|---|---|
| ⭐ Arjun | `s0md3v/Arjun` | HTTP param discovery per endpoint |
| ⭐ x8 | `Sh1Yo/x8` | Hidden param brute (Rust, fast) |
| ParamSpider | `devanshbatham/ParamSpider` | Params from web archives |
| 🧩 param-miner | `PortSwigger/param-miner` | Burp — unlinked params & cache-key probing |
| qsfuzz | `ameenmaali/qsfuzz` | Rule-based query-string fuzzing |

## 9 · URL list wrangling (the tomnomnom stack)
*The glue that keeps pipelines clean and false-positive-free.*

| Tool | Repo | Notes |
|---|---|---|
| ⭐ anew | `tomnomnom/anew` | Append only new lines (idempotent pipelines) |
| ⭐ gf | `tomnomnom/gf` | Named grep patterns (`gf xss`, `gf ssrf`, `gf redirect`) |
| ⭐ qsreplace | `tomnomnom/qsreplace` | Swap every param value for a payload |
| ⭐ uro | `s0md3v/uro` | De-dup near-identical URLs (kills noise) |
| unfurl | `tomnomnom/unfurl` | Explode URLs into parts (domains, paths, params) |
| gf-patterns | `1ndianl33t/Gf-Patterns` | Big community pattern pack for `gf` |
| interactsh | `projectdiscovery/interactsh` | Self-hostable OOB callback server |
| notify | `projectdiscovery/notify` | Pipe results to Slack/Discord/Telegram |
| CyberChef | `gchq/CyberChef` | Encode/decode/crypto swiss-army (browser) |

## 10 · Secrets, JS & git exposure
| Tool | Repo | Notes |
|---|---|---|
| ⭐ trufflehog | `trufflesecurity/trufflehog` | Secret scan with **verification** (low-FP) — git, S3, filesystem |
| ⭐ noseyparker | `praetorian-inc/noseyparker` | Very fast secret scan over text + git history |
| gitleaks | `gitleaks/gitleaks` | Regex+entropy secret scanner / pre-commit |
| SecretFinder | `m4ll0k/SecretFinder` | Keys/tokens/JWTs in JS |
| keyhacks | `streaak/keyhacks` | *How to validate* a leaked key (prove impact) |
| gitGraber | `hisxo/gitGraber` | Real-time GitHub monitoring for your keywords |
| GitHound | `tillson/git-hound` | GitHub code search for exposed keys via dorks |
| GitTools | `internetwache/GitTools` | Dump + rebuild an exposed `.git/` |
| git-dumper | `arthaud/git-dumper` | Pull a `.git` from a website |
| gato | `praetorian-inc/gato` | GitHub Actions / self-hosted-runner attack |
| zizmor | `zizmorcore/zizmor` | Static analysis of GitHub Actions workflows |

## 11 · Vulnerability scanners
| Tool | Repo | Notes |
|---|---|---|
| ⭐ nuclei | `projectdiscovery/nuclei` | Template engine — CVEs, misconfigs, takeovers, **DAST mode** |
| ⭐ nuclei-templates | `projectdiscovery/nuclei-templates` | The community template library |
| 🧩 backslash-powered-scanner | `PortSwigger/backslash-powered-scanner` | Finds *unknown* injection classes in Burp |
| jaeles | `jaeles-project/jaeles` | Signature-based web scanner |
| nikto 💤 | `sullo/nikto` | Old-school server scanner |
| wpscan | `wpscanteam/wpscan` | WordPress black-box scanner |
| joomscan / CMSmap | `OWASP/joomscan`, `Dionach/CMSmap` | CMS-specific |
| retire.js | `RetireJS/retire.js` | Flag vulnerable JS libs (this repo ships a lite clone) |
| cvemap | `projectdiscovery/cvemap` | CLI over CVE data |
| nomore403 | `devploit/nomore403` | 403/40X bypass automation |

## 12 · Per-class exploitation
| Class | Tools |
|---|---|
| **XSS** | ⭐ `hahwul/dalfox` · `s0md3v/XSStrike` · `ssl/ezXSS` (blind) · `mandatoryprogrammer/xsshunter` · `LewisArdern/bXSS` · `fcavallarin/domdig` (DOM/SPA) |
| **SQLi** | ⭐ `sqlmapproject/sqlmap` · ⭐ `r0oth3x49/ghauri` · `Charlie-belmer/nosqli` · `codingo/NoSQLMap` |
| **SSRF** | ⭐ `swisskyrepo/SSRFmap` · `tarunkant/Gopherus` (gopher→RCE) · `assetnote/surf` (cloud SSRF filter) · `teknogeek/ssrf-sheriff` · DNS-rebind: `nccgroup/singularity` |
| **SSTI** | `vladko312/SSTImap` · `epinna/tplmap` |
| **XXE** | `enjoiz/XXEinjector` · `luisfontes19/xxexploiter` · `BuffaloWill/oxml_xxe` · `GoSecure/dtd-finder` |
| **Cmd injection** | `commixproject/commix` |
| **CORS** | `s0md3v/Corsy` · `Shivangx01b/CorsMe` |
| **CRLF** | `Nefcore/CRLFsuite` · `dwisiswant0/crlfuzz` |
| **Open redirect** | `r0075h3ll/Oralyzer` · `devanshbatham/OpenRedireX` |
| **Deserialization** | `frohoff/ysoserial` (Java) · `pwntester/ysoserial.net` · `ambionics/phpggc` (PHP) · `BishopFox/GadgetProbe` |
| **Request smuggling** | 🧩 `PortSwigger/http-request-smuggler` · `defparam/smuggler` · `BishopFox/h2csmuggler` |
| **Race condition** | 🧩 `PortSwigger/turbo-intruder` (single-packet) · `nccgroup/requests-racer` |
| **Cache poisoning** | `xhzeem/toxicache` · 🧩 param-miner |
| **IDOR/authZ** | 🧩 `Quitten/Autorize` (Burp — the standard) |
| **GraphQL** | 🧩 `doyensec/inql` · `nikitastupin/clairvoyance` (recover schema) · `dolevf/graphql-cop` · `swisskyrepo/GraphQLmap` |
| **Directory traversal** | `wireghoul/dotdotpwn` · 🧩 `bayotop/off-by-slash` (NGINX alias) |
| **postMessage** | 🧩 `fransr/postMessage-tracker` |
| **CSP bypass** | `renniepak/CSPBypass` · `zigoo0/JSONBee` |

## 13 · Cloud, buckets & origin-IP
| Tool | Repo | Notes |
|---|---|---|
| ⭐ S3Scanner | `sa7mon/S3Scanner` | Find + dump open S3 buckets |
| CloudScraper | `jordanpotti/CloudScraper` | Enumerate S3 / Azure Blob / DO Spaces |
| CloudBrute | `0xsha/CloudBrute` | Multi-cloud asset brute |
| s3dns | `olizimmermann/s3dns` | Passive bucket discovery via DNS |
| festin | `cr0hn/festin` | S3 weakness discovery |
| dufflebag | `BishopFox/dufflebag` | Search exposed EBS volumes for secrets |
| ⭐ hakoriginfinder | `hakluke/hakoriginfinder` | Find origin host behind a reverse proxy |
| CloudRip | `staxsum/CloudRip` | Origin IP behind Cloudflare |

## 14 · Subdomain takeover
| Tool | Repo | Notes |
|---|---|---|
| ⭐ dnsReaper | `punk-security/dnsReaper` | ~50 takeover signatures, fast |
| ⭐ subzy | `PentestPad/subzy` | Fingerprint-based takeover check |
| nuclei takeovers | `-t http/takeovers/` | Template set, folds into existing pipeline |
| can-i-take-over-xyz | `EdOverflow/can-i-take-over-xyz` | The reference: which services are claimable |
| subjack 💤 | `haccer/subjack` | Classic Go checker |

## 15 · Auth: JWT / OAuth / SSO
| Tool | Repo | Notes |
|---|---|---|
| ⭐ jwt_tool | `ticarpi/jwt_tool` | Test/tamper/crack JWTs (alg:none, key confusion, kid) |
| jwt-hack | `hahwul/jwt-hack` | JWT attack helper |
| 🧩 jwt-heartbreaker | `wallarm/jwt-heartbreaker` | Burp — detect known/public signing keys |
| c-jwt-cracker | `brendan-rius/c-jwt-cracker` | Brute weak HS256 secrets |
| hashcat `-m 16500` | — | GPU-crack JWT HMAC secrets |

## 16 · Proxies & interception
| Tool | Repo | Notes |
|---|---|---|
| ⭐ Burp Suite | portswigger.net | The manual-testing standard (Pro for scanner/extensions) |
| ⭐ Caido | caido.io | Fast modern Burp alternative, Rust |
| mitmproxy | `mitmproxy/mitmproxy` | Scriptable intercepting proxy |
| proxify | `projectdiscovery/proxify` | Capture/replay HTTP(S), MITM for pipelines |
| mitmproxy2swagger | `alufers/mitmproxy2swagger` | Build an OpenAPI spec from captured traffic |
| hetty | `dstotijn/hetty` | Open-source Burp-lite |
| **Essential Burp extensions** | — | Autorize · param-miner · turbo-intruder · HTTP Request Smuggler · inql · Backslash Powered Scanner · JS Link Finder · nowafpls |

## 17 · Monitoring & continuous recon
| Tool | Repo | Notes |
|---|---|---|
| ⭐ notify | `projectdiscovery/notify` | Alert pipelines to chat |
| jsmon | `robre/jsmon` | Watch JS files for new endpoints |
| Substr3am | `nexxai/Substr3am` | Watch new TLS certs for a target |
| gitGraber | `hisxo/gitGraber` | Watch GitHub for leaked keywords |
| reconFTW | `six2dez/reconftw` | Cron it for recurring full recon |

## 18 · Mobile & thick client
| Tool | Repo | Notes |
|---|---|---|
| ⭐ MobSF | `MobSF/Mobile-Security-Framework-MobSF` | Static+dynamic APK/IPA analysis |
| ⭐ frida | `frida/frida` | Runtime hooking (cert pinning bypass, etc.) |
| objection | `sensepost/objection` | Frida-powered runtime toolkit |
| jadx | `skylot/jadx` | Decompile APK → readable Java |
| apktool | `iBotPeaches/Apktool` | Unpack/repack APK resources |
| awesome-mobile-security | `vaib25vicky/awesome-mobile-security` | The reference list |

## 19 · Automation frameworks
| Tool | Repo | Notes |
|---|---|---|
| ⭐ reconftw | `six2dez/reconftw` | Full automated recon pipeline (opinionated, maintained) |
| Osmedeus | `j3ssie/Osmedeus` | Recon + scan workflow engine |
| nuclei + notify + anew | — | The DIY pipeline most pros actually run |
| Sn1per | `1N3/Sn1per` | All-in-one pentest framework |
| **`bounty_recon.py`** | *this repo* | Recon + scan + AI triage + visual report in one file |

## 20 · AI-assisted
| Tool | Repo | Notes |
|---|---|---|
| nuclei-ai / cvemap | ProjectDiscovery | AI template gen + CVE lookup |
| PentestGPT | `GreyDGL/PentestGPT` | LLM pentest assistant |
| `--ai-triage` | *this repo* | 3-phase triage (worth it? → reproduce → CVSS) on findings |
| **Note** | — | AI *proposes*, OOB *confirms*. Never submit an AI-asserted bug unverified. |

## 21 · Wordlists & payloads
| Resource | Repo | Notes |
|---|---|---|
| ⭐ SecLists | `danielmiessler/SecLists` | The wordlist monorepo (Discovery, fuzzing, creds) |
| ⭐ PayloadsAllTheThings | `swisskyrepo/PayloadsAllTheThings` | Payloads + bypasses per class |
| assetnote wordlists | wordlists.assetnote.io | Huge, data-driven content/param lists |
| fuzzdb | `fuzzdb-project/fuzzdb` | Attack patterns + resource discovery |
| OneListForAll | `six2dez/OneListForAll` | Merged resolver/content wordlist |
| this repo `Payloads/` | *this repo* | Curated per-class starter payloads |

---

## 🚀 One-shot install

### Go stack (ProjectDiscovery + tomnomnom + friends)
```bash
# ProjectDiscovery core
for t in subfinder/v2/cmd/subfinder httpx/cmd/httpx nuclei/v3/cmd/nuclei \
         naabu/v2/cmd/naabu katana/cmd/katana dnsx/cmd/dnsx tlsx/cmd/tlsx \
         interactsh/cmd/interactsh-client notify/cmd/notify \
         asnmap/cmd/asnmap mapcidr/cmd/mapcidr uncover/cmd/uncover \
         alterx/cmd/alterx cvemap/cmd/cvemap urlfinder/cmd/urlfinder; do
  go install -v "github.com/projectdiscovery/${t}@latest"
done

# tomnomnom glue
for t in anew gf qsreplace unfurl assetfinder waybackurls; do
  go install -v "github.com/tomnomnom/${t}@latest"
done

# fuzz / crawl / xss / urls / takeover
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/PentestPad/subzy@latest
go install -v github.com/ticarpi/jwt_tool@latest   # (pipx also works)

# gf pattern packs
mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf-tmp \
  && cp ~/.gf-tmp/*.json ~/.gf/ && rm -rf ~/.gf-tmp
```

### pipx / pip tools
```bash
pipx install arjun && pipx install uro && pipx install git+https://github.com/xnl-h4ck3r/waymore.git
pipx install dirsearch
pip install sqlmap-cli 2>/dev/null || pipx install git+https://github.com/sqlmapproject/sqlmap.git
```

### Rust / brew
```bash
brew install trufflehog gitleaks ffuf rustscan feroxbuster gowitness amass || true
cargo install --git https://github.com/sa7mon/S3Scanner 2>/dev/null || true
```

### Wordlists
```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists ~/wordlists/SecLists
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings ~/wordlists/PayloadsAllTheThings
```

### Then: feed it all into this repo's scanner
```bash
python3 bounty_recon.py -t target.com --profile safe --ai-triage --html --out-dir ./reports
```

---

*All tools are for authorized testing only. Maintenance status (💤) is a hint —
check each repo's recent commits before depending on it. When a tool and a Burp
extension overlap, prefer the one you can validate by hand.*
