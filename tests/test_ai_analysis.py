"""v4.9: AI deep-analysis context builder (pure; no network / no provider)."""

import bounty_recon as b


def _result():
    r = b.ScanResult(target="example.com")
    r.subdomains = [f"h{i}.example.com" for i in range(60)]
    r.live_hosts = [{"url": f"https://h{i}.example.com", "host": f"h{i}.example.com"}
                    for i in range(50)]
    r.technologies = {"h1.example.com": ["nginx", "next.js"] + [f"x{i}" for i in range(20)]}
    r.endpoints = [f"/api/{i}" for i in range(200)]
    r.parameters = [f"p{i}" for i in range(200)]
    r.waf_detected = {"h1.example.com": "Cloudflare"}
    r.findings = [{"severity": "High", "title": f"t{i}", "url": f"/u{i}"} for i in range(80)]
    r.summary = {"critical": 0, "high": 80, "medium": 0, "low": 0}
    return r


def test_context_is_capped_and_serialisable():
    import json
    ctx = b.build_ai_analysis_context(_result())
    # caps applied
    assert len(ctx["endpoints"]) == 60
    assert len(ctx["parameters"]) == 60
    assert len(ctx["findings"]) == 40
    assert len(ctx["subdomains"]) <= 40
    assert len(ctx["live_hosts"]) <= 40
    assert len(ctx["technologies"]["h1.example.com"]) <= 8
    # live_hosts flattened to URLs (strings), findings normalised
    assert all(isinstance(h, str) for h in ctx["live_hosts"])
    assert set(ctx["findings"][0]) == {"severity", "title", "url"}
    # fully JSON-serialisable (it gets embedded in the prompt)
    json.dumps(ctx)


def test_context_handles_empty_result():
    ctx = b.build_ai_analysis_context(b.ScanResult(target="x.com"))
    assert ctx["target"] == "x.com"
    assert ctx["endpoints"] == [] and ctx["findings"] == []


def test_ai_analysis_fields_and_fns_exist():
    assert hasattr(b.ScanResult(target="x"), "ai_analysis")
    assert callable(b.ai_deep_analysis) and callable(b.build_ai_analysis_context)
    assert "UNAUTHENTICATED" in b.AI_ANALYSIS_SYSTEM
