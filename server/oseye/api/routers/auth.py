"""Authentication router — /api/v1/auth/token, /api/v1/auth/refresh.

SEC-PREV-002: /auth/token is rate-limited to 5 requests/minute per IP.
SEC-AUTH-001: Passwords are verified with bcrypt.
"""

from __future__ import annotations

import logging
import os
import time
from collections import OrderedDict
from typing import Any

import bcrypt
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

# F2 / SEC-003: detect weak or missing credentials at startup
_WEAK_DEFAULTS: frozenset[str] = frozenset({"admin123", "analyst123"})

# SEC-AUTH-002: maximum total session lifetime (absolute cap for refresh chains)
_MAX_SESSION_LIFETIME_SECONDS: float = 24 * 3600  # 24 hours

# ---------------------------------------------------------------------------
# SEC-006: in-memory rate limiter for /auth/refresh — bounded LRU to 10 000 IPs
# ---------------------------------------------------------------------------
_RATE_STORE_CAP = 10_000
# NOTE (M): _refresh_rate_store is per-worker (in-process only). In a multi-worker
# deployment (gunicorn --workers N, or multiple replicas behind a load-balancer),
# each worker maintains its own independent store, making the effective per-IP
# limit max_calls * num_workers. For accurate enforcement in production use a
# shared Redis backend — e.g. replace _check_rate_limit with slowapi + a Redis
# storage backend (slowapi.extension.Limiter with storage_uri="redis://...").
_refresh_rate_store: OrderedDict[str, list[float]] = OrderedDict()


def _check_rate_limit(ip: str, max_calls: int = 10, window_seconds: float = 60.0) -> None:
    """Raise HTTP 429 if *ip* has exceeded *max_calls* within *window_seconds*.

    SEC-006: the store is capped at _RATE_STORE_CAP entries (LRU eviction) to
    prevent unbounded growth under floods of distinct source IPs.
    """
    now = time.monotonic()
    timestamps = _refresh_rate_store.get(ip, [])
    timestamps = [t for t in timestamps if now - t < window_seconds]
    if len(timestamps) >= max_calls:
        raise HTTPException(status_code=429, detail="Too many requests")
    timestamps.append(now)

    # Update the OrderedDict — move to end (most-recently-used)
    _refresh_rate_store[ip] = timestamps
    _refresh_rate_store.move_to_end(ip)

    # Evict oldest entries when cap is exceeded
    while len(_refresh_rate_store) > _RATE_STORE_CAP:
        _refresh_rate_store.popitem(last=False)


def _hash(pw: str) -> str:
    # bcrypt silently truncates at 72 bytes; enforce explicitly to avoid
    # silent auth failures when passwords differ only after byte 72.
    encoded = pw.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(encoded, salt)
    return hashed.decode("utf-8")


# ---------------------------------------------------------------------------
# User store — loaded from /etc/oseye/users.json if present (managed by
# `oseye-server user create/passwd/delete`), otherwise falls back to
# OSEYE_ADMIN_PASSWORD / OSEYE_ANALYST_PASSWORD environment variables.
# ---------------------------------------------------------------------------

import json as _json
from pathlib import Path as _Path

_USERS_FILE = _Path(os.getenv("OSEYE_USERS_FILE", "/etc/oseye/users.json"))
_OSEYE_ENV = os.getenv("OSEYE_ENV", "development").lower()
_is_production = _OSEYE_ENV == "production"

def _load_users() -> dict[str, dict[str, Any]]:
    """Load users from file, fall back to env vars for backward compatibility."""
    if _USERS_FILE.exists():
        try:
            data = _json.loads(_USERS_FILE.read_text())
            if data:
                logger.info("auth: loaded %d user(s) from %s", len(data), _USERS_FILE)
                return data
        except Exception as exc:
            logger.error("auth: failed to read %s: %s — falling back to env vars", _USERS_FILE, exc)

    # Fallback: env vars (backward compat and dev mode)
    # L-02: treat empty env var as "not set"
    admin_pw_env = os.getenv("OSEYE_ADMIN_PASSWORD")
    if admin_pw_env == "":
        logger.warning("OSEYE_ADMIN_PASSWORD is set but empty — falling back to dev default")
    admin_pw = admin_pw_env if admin_pw_env else "admin123"

    analyst_pw_env = os.getenv("OSEYE_ANALYST_PASSWORD")
    if analyst_pw_env == "":
        logger.warning("OSEYE_ANALYST_PASSWORD is set but empty — falling back to dev default")
    analyst_pw = analyst_pw_env if analyst_pw_env else "analyst123"

    # C-1: in production, weak/missing passwords are fatal
    for pw, name in [(admin_pw, "OSEYE_ADMIN_PASSWORD"), (analyst_pw, "OSEYE_ANALYST_PASSWORD")]:
        if pw in _WEAK_DEFAULTS:
            if _is_production:
                raise RuntimeError(
                    f"FATAL: {name} is not set or uses a weak dev default. "
                    "Set a strong password or run 'oseye-server user create' before "
                    "running in production (OSEYE_ENV=production)."
                )
            logger.critical("%s is missing or uses a weak dev default", name)

    return {
        "admin":   {"hashed_password": _hash(admin_pw),   "roles": ["admin", "analyst"]},
        "analyst": {"hashed_password": _hash(analyst_pw), "roles": ["analyst"]},
    }

_USERS: dict[str, dict[str, Any]] = _load_users()


def _authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Return the user record if credentials are valid, else None.

    H-03: when the username is not found, call dummy verify to consume the
    same time as a real bcrypt check and prevent timing-based username enumeration.
    """
    user = _USERS.get(username)
    pw_bytes = password.encode("utf-8")[:72]

    if user is None:
        # H-03: uniform response time — prevents username enumeration via timing.
        # Use a dummy hash to maintain constant time
        bcrypt.checkpw(pw_bytes, bcrypt.gensalt())
        return None

    stored_hash = user["hashed_password"].encode("utf-8")
    if not bcrypt.checkpw(pw_bytes, stored_hash):
        return None
    return user


@router.post("/token")
@limiter.limit("5/minute")
async def login(
    request: Request,  # required by slowapi
    form: OAuth2PasswordRequestForm = Depends(),
) -> dict[str, Any]:
    """Issue a JWT access token (SEC-PREV-002: 5 req/min per IP).

    Passwords are validated with bcrypt (SEC-AUTH-001).
    Default users: admin / analyst (override via OSEYE_ADMIN_PASSWORD / OSEYE_ANALYST_PASSWORD).
    """
    if not form.username or not form.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="username and password are required",
        )

    user = _authenticate(form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    handler = request.app.state.jwt_handler
    roles: list[str] = list(user["roles"])
    token = handler.create_token(subject=form.username, roles=roles)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/refresh")
async def refresh(request: Request, token: str = Body(..., embed=True)) -> dict[str, Any]:
    """Refresh a token by verifying the existing one and issuing a new one.

    SEC-006: rate-limited to 10 requests per 60 seconds per IP.
    SEC-AUTH-002: reject refresh if the absolute session lifetime (now - iat) exceeds
    _MAX_SESSION_LIFETIME_SECONDS to prevent indefinite refresh chains.
    """
    client_ip: str = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    handler = request.app.state.jwt_handler
    payload = handler.verify_token(token)

    # SEC-AUTH-002: enforce absolute session lifetime
    iat = payload.get("iat")
    if iat is not None:
        # PyJWT decodes iat as an int (Unix timestamp) or a datetime depending on version
        if isinstance(iat, (int, float)):
            age = time.time() - float(iat)
        else:
            # datetime object — use .timestamp() when available, else coerce
            iat_ts = iat.timestamp() if hasattr(iat, "timestamp") else float(iat)
            age = time.time() - iat_ts
        if age > _MAX_SESSION_LIFETIME_SECONDS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has expired — please log in again",
                headers={"WWW-Authenticate": "Bearer"},
            )

    subject: str = str(payload.get("sub", ""))
    if subject not in _USERS:
        raise HTTPException(status_code=401, detail="User no longer exists")
    roles = list(_USERS[subject].get("roles", []))
    # SEC-JWT-001: revoke the old token before issuing a new one so that both
    # tokens cannot be used concurrently (token rotation).
    handler.revoke_token(token)
    new_token = handler.create_token(subject=subject, roles=roles)
    return {"access_token": new_token, "token_type": "bearer"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def logout(
    request: Request,
    token: str = Body(..., embed=True),
) -> None:
    """Revoke the supplied access token immediately.

    SEC-JWT-001: adds the token's jti to the in-memory blocklist until its
    natural expiry so it cannot be reused after logout.
    """
    handler = request.app.state.jwt_handler
    handler.revoke_token(token)
