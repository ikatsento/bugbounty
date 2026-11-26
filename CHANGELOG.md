# Changelog

## 4.7.0 — reflected-XSS surface + richer SSRF (2026)

Attack-surface techniques from XSSRush (N45HT) and SSRFmap (swisskyrepo),
re-implemented for the unauthenticated / no-browser design. Exploitation stays
manual; detections are FP-honest leads.

Added
- `--xss`: reflect a unique canary + special-char matrix (`<>"'`(){};=/`) through
  query params; report breakout chars that survive UNESCAPED and classify the
  context (html-tag / attribute / javascript). HTTP-only — a lead to confirm in a
  browser, never a claim of execution. In the safe/full profiles.
- SSRF enrichment: more cloud-metadata targets (Alibaba 100.100.100.200, Oracle
  OCI, Packet) and a SSRF_BYPASS_PAYLOADS list (decimal/hex/IPv6 loopback,
  gopher/dict/file schemes) wired into the manual SSRF recipe.
- Tests for the XSS reflection analyser (tag/attribute/javascript/encoded/absent)
  and the enriched SSRF data. Suite: 32 tests, green.
- ARSENAL.md: XSS reflection-matrix + SSRF localhost/scheme bypass recipes.

## 4.6.0 — unauthenticated-only (login replay removed) (2026)

The v4.5 login machinery was removed by request: this tool now finds everything
**without login**. No cookies, session or auth headers are ever sent.

Removed
- `--cookie`, `--auth-state` (Playwright storageState) and `--header` flags.
- `build_auth_headers`, `cookies_from_storage_state`, `parse_header_args` and the
  `HTTP_CFG["extra_headers"]` / `configure_http(extra_headers=...)` plumbing.

Kept (all unauthenticated)
- `--access-bypass`: 401/403 path-normalisation + trusted-proxy header spoofs.
- `--tls-downgrade`: https → cleartext http:// redirect detection.
- The unauthenticated sensitive/internal endpoint sweep (/rest/settings,
  /api/v1/stream/demo, /actuator, /metrics, …) — unchanged.

Tests
- Dropped the auth-helper tests; added a regression guard that the login
  machinery stays gone. Suite: 24 tests, green.

## 4.5.0 — authenticated scanning + access-control bypass (2026)

Generalised (no target-specific code) from an authorised n8n/Next.js engagement.

Added
- **Authenticated scanning**: `--cookie`, `--auth-state` (Playwright
  storageState JSON), and repeatable `--header` are merged into the shared HTTP
  layer and sent on every request, so all modules run behind a login.
- **`--access-bypass`**: on 401/403 endpoints, retry with path-normalisation
  (`/%2e/`, `..;/`, `//`, `%2f`, `%00`) and trusted-proxy header spoofs
  (`X-Forwarded-For/Host`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, …);
  report High if a variant returns 200 (confirm manually).
- **`--tls-downgrade`**: flag https endpoints that 3xx-redirect to cleartext
  `http://`. Both new modules join the `safe` and `full` profiles.
- Tests for the new pure logic (cookie/storageState/header parsing, path
  variants, downgrade detection). Suite: 25 tests, green.

ARSENAL
- The target-specific n8n webhook / SSRF-flow techniques stay as recipes in
  ARSENAL.md rather than FP-prone auto-probes.

## 4.4.0 — curated upgrade (2026)

Added
- **Test suite** (`tests/`, pytest): JWT audit, secret library + severity
  coverage, SARIF builder, cookie audit, Shannon entropy, dedup, severity order.
  `pip install -r requirements-dev.txt && pytest -q`.
- **SARIF 2.1.0 output** (`--sarif`) for CI / code-scanning ingestion.
- **JWT audit extended**: alg-confusion (RS/ES/PS→HS downgrade), `kid` path/SQLi
  injection, `jku`/`x5u` remote-key/SSRF injection (CVE-2018-0114 class).
- **Secret library +20 patterns** (2020-2026): GitHub fine-grained PAT, GitLab
  PAT, npm, PyPI, Anthropic `sk-ant-`, OpenAI project key, Telegram, Discord bot
  token + webhook, DigitalOcean, HashiCorp Vault, Square, Postman, New Relic,
  Datadog, Google OAuth refresh, private-key blocks — all with severities.
- **ARSENAL.md modern recipes**: HTTP request smuggling / H2 desync, web cache
  deception, OAuth/OIDC + SAML, client-side gadgets (as verified recipes).

Changed / fixed
- Version is single-sourced from the `VERSION` constant (docstring de-drifted).
- `requirements.txt` de-staled (dropped the retired `claude_hunter.py` note);
  added `requirements-dev.txt`.
- Tightened 3 bare `except:` clauses to specific exception types.

## 4.3.0 and earlier
See the version history block at the top of `bounty_recon.py`.
