"""Make the single-file tool importable as a module for tests.

bounty_recon.py guards main() behind __main__, so importing it only defines
functions/constants — no scan runs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bounty_recon  # noqa: E402,F401
