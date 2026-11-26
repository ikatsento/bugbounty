"""v4.5: authenticated-scan helpers + access-bypass / TLS-downgrade pure logic."""

import json

import pytest

import bounty_recon as b


# ── cookie / storageState / header parsing ──────────────────────────────────
def test_cookies_from_storage_state():
    data = {"cookies": [{"name": "sid", "value": "abc"},
                        {"name": "csrf", "value": "x"}],
            "origins": []}
    assert b.cookies_from_storage_state(data) == "sid=abc; csrf=x"


def test_cookies_from_storage_state_empty():
    assert b.cookies_from_storage_state({"cookies": []}) == ""
    assert b.cookies_from_storage_state({}) == ""
    assert b.cookies_from_storage_state(None) == ""


def test_parse_header_args_ok_and_bad():
    assert b.parse_header_args(["X-A: 1", "Authorization: Bearer z"]) == \
        {"X-A": "1", "Authorization": "Bearer z"}
    with pytest.raises(ValueError):
        b.parse_header_args(["no-colon"])
    with pytest.raises(ValueError):
        b.parse_header_args([": empty-name"])


def test_build_auth_headers_from_state_file(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"cookies": [{"name": "s", "value": "1"}]}))
    hdrs = b.build_auth_headers(cookie="extra=9", auth_state_path=str(state),
                                header_items=["X-Api-Version: 2024-01"])
    assert "extra=9" in hdrs["Cookie"] and "s=1" in hdrs["Cookie"]
    assert hdrs["X-Api-Version"] == "2024-01"


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
    assert b.is_cleartext_downgrade("https://t/x", "//t/x") is False   # protocol-relative
    assert b.is_cleartext_downgrade("http://t/x", "http://t/x") is False  # not https to begin with
    assert b.is_cleartext_downgrade("https://t/x", "") is False


# ── header bypass set sanity ────────────────────────────────────────────────
def test_header_bypass_sets_are_single_header_dicts():
    assert len(b.HEADER_BYPASS_SETS) >= 5
    for h in b.HEADER_BYPASS_SETS:
        assert isinstance(h, dict) and len(h) == 1
    names = {list(h)[0] for h in b.HEADER_BYPASS_SETS}
    assert "X-Forwarded-For" in names and "X-Original-URL" in names
