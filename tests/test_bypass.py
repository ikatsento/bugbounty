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


# ── regression guard: the login machinery must stay gone ─────────────────────
def test_no_login_machinery_remains():
    for removed in ("build_auth_headers", "cookies_from_storage_state",
                    "parse_header_args"):
        assert not hasattr(b, removed), f"{removed} should have been removed (no-login tool)"
    assert "extra_headers" not in b.HTTP_CFG
