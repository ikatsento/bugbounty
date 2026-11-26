"""SARIF output, dedup, cookie audit, severity ordering."""

import json

import bounty_recon as b


def _result_with_findings():
    r = b.ScanResult(target="example.com")
    r.findings = [
        {"severity": "Critical", "category": "jwt", "title": "JWT alg:none",
         "url": "https://example.com/api", "detail": "alg:none accepted",
         "remediation": "Reject alg:none"},
        {"severity": "Medium", "category": "headers", "title": "Missing CSP",
         "url": "https://example.com/", "remediation": "Add CSP"},
        {"severity": "Info", "category": "jwt", "title": "JWT HMAC"},
    ]
    return r


def test_build_sarif_structure_and_levels():
    sarif = b.build_sarif(_result_with_findings())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "bounty_recon.py"
    assert driver["version"] == b.VERSION
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    levels = [r["level"] for r in results]
    assert levels == ["error", "warning", "note"]  # Critical, Medium, Info
    # Two distinct rule categories (jwt, headers) → 2 rules, reused by ruleIndex.
    assert len(driver["rules"]) == 2
    jwt_results = [r for r in results if r["ruleId"] == "jwt"]
    assert len(jwt_results) == 2


def test_generate_sarif_roundtrips(tmp_path):
    out = tmp_path / "r.sarif"
    b.generate_sarif(_result_with_findings(), out)
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["message"]["text"].startswith("JWT alg:none")


def test_dedup_findings_collapses_exact_duplicates():
    dupes = [
        {"severity": "High", "category": "x", "title": "t", "url": "u"},
        {"severity": "High", "category": "x", "title": "t", "url": "u"},
        {"severity": "High", "category": "x", "title": "t2", "url": "u"},
    ]
    assert len(b.dedup_findings(dupes)) == 2


def test_cookie_audit_flags_missing_flags():
    f = b.audit_cookie("sessionid", "abc", "sessionid=abc", "https://x/")
    titles = " ".join(x["title"] for x in f)
    assert "Secure" in titles and "HttpOnly" in titles


def test_severity_order_sorts_critical_first():
    findings = [{"severity": s} for s in ["Low", "Critical", "Info", "High", "Medium"]]
    ordered = sorted(findings, key=lambda f: b.SEV_ORDER.get(f["severity"], 4))
    assert [f["severity"] for f in ordered] == ["Critical", "High", "Medium", "Low", "Info"]
