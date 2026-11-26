"""v4.6: unauthenticated access-control-bypass + TLS-downgrade pure logic.

No login / cookie / session helpers exist any more — these checks are all
unauthenticated black-box probes.
"""

import bounty_recon as b


# ── path-normalisation variants ─────────────────────────────────────────────
def test_path_bypass_variants_are_distinct_and_rooted():
    variants = b.path_bypass_variants("/admin")
    assert len(variants) == len(set(variants))        # deduped
    assert all(v.startswith("/") for v in variants)   # rooted
    assert any("%2e" in v for v in variants)          # dot-encoding present
    assert any("..;" in v for v in variants)          # path-param trick present


def test_path_bypass_variants_normalises_missing_slash():
    assert b.path_bypass_variants("admin") == b.path_bypass_variants("/admin")


# ── TLS downgrade detection ─────────────────────────────────────────────────
def test_is_cleartext_downgrade():
    assert b.is_cleartext_downgrade("https://t/x", "http://t/x") is True
    assert b.is_cleartext_downgrade("https://t/x", "https://t/x") is False
    assert b.is_cleartext_downgrade("https://t/x", "//t/x") is False     # protocol-relative
    assert b.is_cleartext_downgrade("http://t/x", "http://t/x") is False  # not https to begin with
    assert b.is_cleartext_downgrade("https://t/x", "") is False


# ── header bypass set sanity ────────────────────────────────────────────────
def test_header_bypass_sets_are_single_header_dicts():
    assert len(b.HEADER_BYPASS_SETS) >= 5
    for h in b.HEADER_BYPASS_SETS:
        assert isinstance(h, dict) and len(h) == 1
    names = {list(h)[0] for h in b.HEADER_BYPASS_SETS}
    assert "X-Forwarded-For" in names and "X-Original-URL" in names


# ── v4.8: access-bypass false-positive guards ───────────────────────────────
def test_looks_like_access_denied():
    assert b.looks_like_access_denied("<title>403 Forbidden</title>") is True
    assert b.looks_like_access_denied("Attention Required! | Cloudflare") is True
    assert b.looks_like_access_denied("<h1>Welcome to your dashboard</h1>") is False
    # F5/BIG-IP WAF block page served with HTTP 200 (the live bmsstatic FP)
    assert b.looks_like_access_denied(
        "<title>Request Rejected</title>The requested URL was rejected. "
        "Please consult with your administrator.") is True


def test_candidate_bypass_rejects_fp_shapes():
    base = b"<html><title>403 Forbidden</title></html>"
    # identical to the denied baseline -> not a bypass (the /%2e/ live FP)
    assert b._candidate_bypass(200, base, base) is False
    # a 200 that is itself a forbidden page -> not a bypass
    assert b._candidate_bypass(200, b"<title>403 Forbidden</title>" + b"x" * 200, base) is False
    # tiny body -> not real access
    assert b._candidate_bypass(200, b"ok", base) is False
    # non-2xx -> not a bypass
    assert b._candidate_bypass(403, b"x" * 500, base) is False
    # distinct, substantial, non-error 200 -> genuine candidate
    assert b._candidate_bypass(200, b"<h1>Admin panel</h1>" + b"y" * 300, base) is True


# ── regression guard: the login machinery must stay gone ─────────────────────
def test_no_login_machinery_remains():
    for removed in ("build_auth_headers", "cookies_from_storage_state",
                    "parse_header_args"):
        assert not hasattr(b, removed), f"{removed} should have been removed (no-login tool)"
    assert "extra_headers" not in b.HTTP_CFG
