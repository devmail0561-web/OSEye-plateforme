"""Top-level conftest — environment setup for all test suites.

Sets required environment variables *before* any module-level code runs so
that early-init guards (e.g. OSEYE_SECRET_KEY validation in api_keys.py) do
not raise RuntimeError during collection.
"""

from __future__ import annotations

import os

import pytest

# Enable the full management API in tests regardless of OSEYE_UI_DIR.
os.environ.setdefault("OSEYE_MANAGEMENT_API_ENABLED", "true")

# SEC-001 fix: api_keys.py validates OSEYE_SECRET_KEY at import time.
# Provide a deterministic 32-char test secret so that all test suites can
# import the module without triggering the RuntimeError guard.
os.environ.setdefault(
    "OSEYE_SECRET_KEY",
    "test-secret-key-for-pytest-32chars",
)

# ML-R-03: MLEngine validates OSEYE_CHECKPOINT_HMAC_KEY at construction time
# (fix ML-03 removed the non-hex fallback).  Ensure the key is always a valid
# hex string — if the CI/env value is not hex (e.g. a base64 secret), replace
# it with a deterministic test key so tests can instantiate MLEngine() freely.
_hmac_raw = os.environ.get("OSEYE_CHECKPOINT_HMAC_KEY", "")
try:
    bytes.fromhex(_hmac_raw)
except ValueError:
    os.environ["OSEYE_CHECKPOINT_HMAC_KEY"] = (
        "74657374636865636b706f696e74686d61636b657966727079746573743132333435"
    )


@pytest.fixture(autouse=True)
def _reset_auth_rate_limiter() -> None:
    """Reset the module-level slowapi rate-limiter storage before every test.

    The Limiter object in oseye.api.routers.auth is a module-level singleton
    backed by limits.storage.MemoryStorage.  Without this reset, consecutive
    test functions that all call POST /api/v1/auth/token from 127.0.0.1 share
    the same counter and trip the 5-per-minute limit mid-suite.
    """
    from oseye.api.routers.auth import limiter  # noqa: PLC0415

    storage = getattr(limiter, "_storage", None)
    if storage is not None and hasattr(storage, "reset"):
        storage.reset()
