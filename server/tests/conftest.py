"""Top-level conftest — environment setup for all test suites.

Sets required environment variables *before* any module-level code runs so
that early-init guards (e.g. OSEYE_SECRET_KEY validation in api_keys.py) do
not raise RuntimeError during collection.
"""

from __future__ import annotations

import os

# SEC-001 fix: api_keys.py validates OSEYE_SECRET_KEY at import time.
# Provide a deterministic 32-char test secret so that all test suites can
# import the module without triggering the RuntimeError guard.
os.environ.setdefault(
    "OSEYE_SECRET_KEY",
    "test-secret-key-for-pytest-32chars",
)
