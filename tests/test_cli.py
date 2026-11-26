"""CLI smoke tests — the argument parser must build and --help must work.

These run bounty_recon.py as a subprocess (so argparse's add_argument validation
and help formatting actually execute — unit imports do not reach main()).
Python 3.12+ validates help strings at add_argument time, so a stray '%' in a
help string crashes every invocation; this test guards against that.
"""

import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
SCRIPT = os.path.join(ROOT, "bounty_recon.py")


def _run(*args):
    return subprocess.run([sys.executable, SCRIPT, *args],
                          capture_output=True, text=True, timeout=60)


def test_help_exits_zero_and_lists_new_flags():
    proc = _run("--help")
    assert proc.returncode == 0, proc.stderr[-800:]
    out = proc.stdout
    for flag in ("--access-bypass", "--tls-downgrade", "--sarif"):
        assert flag in out, f"{flag} missing from --help"
    # login flags were removed in v4.6 (unauthenticated-only tool)
    for gone in ("--cookie", "--auth-state"):
        assert gone not in out, f"{gone} should have been removed"


def test_no_target_errors_cleanly():
    """Missing required -t should be a clean argparse error (exit 2), not a crash."""
    proc = _run()
    assert proc.returncode == 2
    assert "usage" in (proc.stderr + proc.stdout).lower()
