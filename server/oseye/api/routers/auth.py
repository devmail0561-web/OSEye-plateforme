"""Authentication router — /api/v1/auth/token, /api/v1/auth/refresh.

SEC-PREV-002: /auth/token is rate-limited to 5 requests/minute per IP.
SEC-AUTH-001: Passwords are verified with bcrypt via passlib.
"""

from __future__ import annotations

import logging
import os
import time
from collections import OrderedDict
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
    return str(_pwd_ctx.hash(encoded))


# ---------------------------------------------------------------------------
# In-process user store — configurable via environment variables.
# Override OSEYE_ADMIN_PASSWORD / OSEYE_ANALYST_PASSWORD in production.
# ---------------------------------------------------------------------------

# L-02: treat an empty env var the same as "not set" and log an explicit warning
# so that a misconfigured container (OSEYE_ADMIN_PASSWORD=) doesn't silently
# activate the weak dev default without any trace in the logs.
_ADMIN_PW_ENV = os.getenv("OSEYE_ADMIN_PASSWORD")
if _ADMIN_PW_ENV == "":
    logger.warning(
        "OSEYE_ADMIN_PASSWORD is set but empty — "
        "falling back to dev default 'admin123'"
    )
_ADMIN_PW_RAW: str = _ADMIN_PW_ENV if _ADMIN_PW_ENV else "admin123"

_ANALYST_PW_ENV = os.getenv("OSEYE_ANALYST_PASSWORD")
if _ANALYST_PW_ENV == "":
    logger.warning(
        "OSEYE_ANALYST_PASSWORD is set but empty — "
        "falling back to dev default 'analyst123'"
    )
_ANALYST_PW_RAW: str = _ANALYST_PW_ENV if _ANALYST_PW_ENV else "analyst123"

# C-1: in production, weak/missing passwords are a fatal misconfiguration.
_OSEYE_ENV = os.getenv("OSEYE_ENV", "development").lower()
_is_production = _OSEYE_ENV == "production"

if _ADMIN_PW_RAW in _WEAK_DEFAULTS:
    if _is_production:
        raise RuntimeError(
            "FATAL: OSEYE_ADMIN_PASSWORD is not set or uses the dev default 'admin123'. "
            "Set a strong password via the OSEYE_ADMIN_PASSWORD environment variable before "
            "running in production (OSEYE_ENV=production)."
        )
    logger.critical(
        "OSEYE_ADMIN_PASSWORD is missing or uses a weak dev default — "
        "set a strong password before deploying to production"
    )
if _ANALYST_PW_RAW in _WEAK_DEFAULTS:
    if _is_production:
        raise RuntimeError(
            "FATAL: OSEYE_ANALYST_PASSWORD is not set or uses the dev default 'analyst123'. "
            "Set a strong password via the OSEYE_ANALYST_PASSWORD environment variable before "
            "running in production (OSEYE_ENV=production)."
        )
    logger.critical(
        "OSEYE_ANALYST_PASSWORD is missing or uses a weak dev default — "
        "set a strong password before deploying to production"
    )

# Pre-hashed at startup; also accept the dev default "password" for tests.
_USERS: dict[str, dict[str, Any]] = {
    "admin": {
        "hashed_password": _hash(_ADMIN_PW_RAW),
        "roles": ["admin", "analyst"],
    },
    "analyst": {
        "hashed_password": _hash(_ANALYST_PW_RAW),
        "roles": ["analyst"],
    },
}


def _authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Return the user record if credentials are valid, else None.

    H-03: when the username is not found, call dummy_verify() to consume the
    same time as a real bcrypt check and prevent timing-based username enumeration.
    """
    user = _USERS.get(username)
    if user is None:
        # H-03: uniform response time — prevents username enumeration via timing.
        _pwd_ctx.dummy_verify()
        return None
    if not _pwd_ctx.verify(password, user["hashed_password"]):
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
