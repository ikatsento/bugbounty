"""Secret-pattern library: coverage, severity mapping, sample matches, entropy."""

import re

import bounty_recon as b


def test_every_pattern_has_a_severity():
    missing = [k for k in b.JS_SECRET_PATTERNS if k not in b.SECRET_SEVERITY]
    assert missing == [], f"patterns without a severity: {missing}"


def test_all_patterns_compile():
    for name, pat in b.JS_SECRET_PATTERNS.items():
        re.compile(pat)  # raises re.error on failure


# Samples are ASSEMBLED from fragments (prefix + body) so no token-shaped
# literal ever appears contiguously in this source file — otherwise GitHub
# (and any secret scanner) would flag this test fixture as a real leaked token.
# At runtime each value still matches its regex.
def _mk(prefix: str, body: str) -> str:
    return prefix + body

SAMPLES = {
    "GitLab PAT":              _mk("glpat" "-", "x" * 20),
    "npm Token":               _mk("npm" "_", "x" * 36),
    "Anthropic API Key":       _mk("sk-" "ant-", "api03-" + "x" * 20),
    "Telegram Bot Token":      _mk("123456789" ":", "x" * 35),
    "DigitalOcean Token":      _mk("dop_" "v1_", "a" * 64),
    "Private Key Block":       _mk("-----BEGIN ", "OPENSSH PRIVATE KEY-----"),
    "AWS Access Key":          _mk("AKIA", "X" * 16),
    "GitHub Fine-grained PAT": _mk("github_" "pat_", "X" * 30),
}


def test_sample_tokens_match_their_patterns():
    for name, sample in SAMPLES.items():
        assert name in b.JS_SECRET_PATTERNS, f"unknown pattern {name}"
        assert re.search(b.JS_SECRET_PATTERNS[name], sample), f"{name} did not match its sample"


def test_new_high_signal_patterns_are_critical_or_high():
    for name in ["GitLab PAT", "npm Token", "Anthropic API Key",
                 "DigitalOcean Token", "Private Key Block"]:
        assert b.SECRET_SEVERITY[name] in ("Critical", "High")


def test_shannon_entropy_ranges():
    assert b.shannon_entropy("") == 0.0
    assert b.shannon_entropy("aaaa") == 0.0            # no randomness
    assert b.shannon_entropy("abcd") == 2.0            # 4 equal symbols -> 2 bits
    assert b.shannon_entropy("Tr0ub4dour&3xplo") > 3.0  # high-entropy secret
