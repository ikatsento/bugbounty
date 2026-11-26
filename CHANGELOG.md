# Changelog

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
