"""Authentication router — /api/v1/auth/token, /api/v1/auth/refresh.

SEC-PREV-002: /auth/token is rate-limited to 5 requests/minute per IP.
SEC-AUTH-001: Passwords are verified with bcrypt via passlib.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
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

# ---------------------------------------------------------------------------
# SEC-006: in-memory rate limiter for /auth/refresh
# ---------------------------------------------------------------------------
_refresh_rate_store: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(ip: str, max_calls: int = 10, window_seconds: float = 60.0) -> None:
    """Raise HTTP 429 if *ip* has exceeded *max_calls* within *window_seconds*."""
    now = time.monotonic()
    _refresh_rate_store[ip] = [t for t in _refresh_rate_store[ip] if now - t < window_seconds]
    if len(_refresh_rate_store[ip]) >= max_calls:
        raise HTTPException(status_code=429, detail="Too many requests")
    _refresh_rate_store[ip].append(now)


def _hash(pw: str) -> str:
    return str(_pwd_ctx.hash(pw))


# ---------------------------------------------------------------------------
# In-process user store — configurable via environment variables.
# Override OSEYE_ADMIN_PASSWORD / OSEYE_ANALYST_PASSWORD in production.
# ---------------------------------------------------------------------------

_ADMIN_PW_RAW = os.getenv("OSEYE_ADMIN_PASSWORD") or "admin123"
_ANALYST_PW_RAW = os.getenv("OSEYE_ANALYST_PASSWORD") or "analyst123"

if _ADMIN_PW_RAW in _WEAK_DEFAULTS:
    logger.critical(
        "OSEYE_ADMIN_PASSWORD is missing or uses a weak dev default — "
        "set a strong password before deploying to production"
    )
if _ANALYST_PW_RAW in _WEAK_DEFAULTS:
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
    """Return the user record if credentials are valid, else None."""
    user = _USERS.get(username)
    if user is None:
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
    """
    client_ip: str = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    handler = request.app.state.jwt_handler
    payload = handler.verify_token(token)
    subject: str = str(payload.get("sub", ""))
    roles: list[str] = list(payload.get("roles", []))
    new_token = handler.create_token(subject=subject, roles=roles)
    return {"access_token": new_token, "token_type": "bearer"}
