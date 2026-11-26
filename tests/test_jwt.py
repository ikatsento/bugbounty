"""JWT audit: alg:none, HMAC, alg-confusion, kid, jku/x5u, sensitive claims."""

import base64
import json

import bounty_recon as b


def _seg(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _jwt(header, payload, sig="sig"):
    return f"{_seg(header)}.{_seg(payload)}.{sig}"


def _titles(findings):
    return " || ".join(f["title"] for f in findings)


def test_alg_none_is_critical():
    f = b.audit_jwt_token(_jwt({"alg": "none"}, {"sub": "1"}), "https://t/")
    assert any(x["severity"] == "Critical" and "alg:none" in x["title"] for x in f)


def test_hmac_is_flagged_info():
    f = b.audit_jwt_token(_jwt({"alg": "HS256"}, {"sub": "1"}), "https://t/")
    assert any(x["severity"] == "Info" and "HMAC" in x["title"] for x in f)


def test_asymmetric_flags_alg_confusion():
    f = b.audit_jwt_token(_jwt({"alg": "RS256"}, {"sub": "1"}), "https://t/")
    assert any(x["severity"] == "Medium" and "alg-confusion" in x["title"] for x in f)


def test_kid_header_flagged():
    f = b.audit_jwt_token(_jwt({"alg": "RS256", "kid": "key-1"}, {"sub": "1"}), "https://t/")
    assert any("kid" in x["title"].lower() for x in f)


def test_jku_and_x5u_are_high():
    f_jku = b.audit_jwt_token(_jwt({"alg": "RS256", "jku": "https://e/j"}, {"s": 1}), "https://t/")
    f_x5u = b.audit_jwt_token(_jwt({"alg": "RS256", "x5u": "https://e/x"}, {"s": 1}), "https://t/")
    assert any(x["severity"] == "High" and "jku" in x["title"] for x in f_jku)
    assert any(x["severity"] == "High" and "x5u" in x["title"] for x in f_x5u)


def test_sensitive_claims_flagged():
    f = b.audit_jwt_token(_jwt({"alg": "HS256"}, {"role": "admin", "email": "a@b"}), "https://t/")
    assert any("sensitive claims" in x["title"] for x in f)


def test_malformed_token_is_safe():
    assert b.audit_jwt_token("not-a-jwt", "https://t/") == []
    assert b.audit_jwt_token("a.b", "https://t/") == []  # <2 usable parts handled
