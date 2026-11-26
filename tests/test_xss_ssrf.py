"""v4.7: reflected-XSS reflection analysis + enriched SSRF data (pure logic)."""

import bounty_recon as b

C = "xsrAB12CD"  # a stand-in canary


def _probe_window(raw_after: str) -> str:
    return f"prefix {C}{raw_after} suffix"


def test_matrix_probe_shape():
    p = b.xss_matrix_probe(C)
    assert p.startswith(C) and set("<>\"'") <= set(p)


def test_tag_injection_is_high():
    r = b.analyze_xss_reflection(C, _probe_window("<>\"'` rest"))
    assert r["reflected"] and r["severity"] == "High" and r["context"] == "html-tag"
    assert "<" in r["unescaped"] and ">" in r["unescaped"]


def test_javascript_context_quote_is_high():
    # quote survives inside a <script> block; no '<'/'>' within the window
    body = "<script>var x='" + C + '"' + " " * 30 + "</script>"
    r = b.analyze_xss_reflection(C, body)
    assert r["severity"] == "High" and r["context"] == "javascript"
    assert "<" not in r["unescaped"]  # proves it's the JS branch, not html-tag


def test_attribute_quote_is_medium():
    body = f'<input value="{C}"other">'
    r = b.analyze_xss_reflection(C, body)
    assert r["severity"] == "Medium" and r["context"] == "attribute"


def test_encoded_reflection_is_low_and_clean():
    r = b.analyze_xss_reflection(C, f"x {C}&lt;&gt;&quot;&#39; y")
    assert r["reflected"] is True
    assert r["severity"] == "Low" and r["context"] == "encoded"
    assert r["unescaped"] == []          # entity ';' must NOT be flagged


def test_not_reflected():
    r = b.analyze_xss_reflection(C, "nothing here")
    assert r["reflected"] is False and r["severity"] is None


# ── SSRF data enrichment (from SSRFmap) ─────────────────────────────────────
def test_metadata_targets_broadened():
    vals = " ".join(b.CLOUD_METADATA_TARGETS.values())
    assert "100.100.100.200" in vals          # Alibaba
    assert "metadata.google.internal" in vals  # GCP
    assert any("opc/v2" in v for v in b.CLOUD_METADATA_TARGETS.values())  # Oracle


def test_ssrf_bypass_payloads_cover_encodings_and_schemes():
    joined = " ".join(b.SSRF_BYPASS_PAYLOADS)
    assert "2130706433" in joined        # decimal 127.0.0.1
    assert "gopher://" in joined
    assert "[::1]" in joined             # IPv6 loopback
    assert "169.254.169.254" in joined   # IMDS
