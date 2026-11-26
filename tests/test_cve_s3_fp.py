"""v4.10: CVE-fingerprint 3xx/path-echo FP + S3 private-bucket mislabel."""

import bounty_recon as b


# ── S3 exploit verdict: private bucket must NOT be labelled exploitable ──────
def test_s3_private_bucket_is_not_exploitable():
    f = {"category": "s3", "severity": "Info",
         "detail": "Bucket exists but private: cody-prod", "url": "https://cody-prod.s3.amazonaws.com"}
    exp = b.exploitation_for(f, "cody.fluttercee.com")
    assert exp["verdict"] == "no"


def test_s3_public_bucket_is_exploitable():
    f = {"category": "s3", "severity": "Critical",
         "detail": "Cloud storage publicly readable: cody-open", "url": "https://cody-open.s3.amazonaws.com"}
    exp = b.exploitation_for(f, "cody.fluttercee.com")
    assert exp["verdict"] == "yes"


# ── CVE fingerprint: a 308 that echoes the path must NOT fingerprint ─────────
def _patch_http_get(monkeypatch, responder):
    monkeypatch.setattr(b, "http_get", lambda url, *a, **k: responder(url))


def test_cve_fp_308_path_echo_is_suppressed(monkeypatch):
    # Every product path 308-redirects to itself with the path in Location + body
    # (the exact cody.fluttercee.com v4.8 false positive).
    def responder(url):
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        return (308, {"location": url.rstrip("/") + "/"}, path.encode())
    _patch_http_get(monkeypatch, responder)
    findings = b.check_cve_fingerprints("https://cody.fluttercee.com")
    assert [f for f in findings if f["category"] == "cve-fingerprint"] == []


def test_cve_fp_real_200_product_still_detected(monkeypatch):
    # A genuine 200 MOVEit page (not a redirect, not the baseline) still fires.
    def responder(url):
        if "zz" in url:                      # random baseline path
            return (404, {}, b"not found")
        if "/moveit" in url.lower():
            return (200, {"server": "nginx"},
                    b"<html><title>MOVEit Transfer</title>Progress MOVEit sign in</html>")
        return (404, {}, b"not found")
    _patch_http_get(monkeypatch, responder)
    findings = b.check_cve_fingerprints("https://target.example")
    moveit = [f for f in findings if "MOVEit" in f.get("title", "")]
    assert len(moveit) >= 1
    assert "200" in moveit[0]["evidence"]
