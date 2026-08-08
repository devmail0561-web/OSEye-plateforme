"""Authentication router — /api/v1/auth/token, /api/v1/auth/refresh.

SEC-PREV-002: /auth/token is rate-limited to 5 requests/minute per IP.
SEC-AUTH-001: Passwords are verified with bcrypt via passlib.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash(pw: str) -> str:
    return str(_pwd_ctx.hash(pw))


# ---------------------------------------------------------------------------
# In-process user store — configurable via environment variables.
# Defaults are dev-only; override OSEYE_ADMIN_PASSWORD / OSEYE_ANALYST_PASSWORD
# in production.
# ---------------------------------------------------------------------------

_ADMIN_PW_RAW = os.getenv("OSEYE_ADMIN_PASSWORD", "admin123")
_ANALYST_PW_RAW = os.getenv("OSEYE_ANALYST_PASSWORD", "analyst123")

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
    """Refresh a token by verifying the existing one and issuing a new one."""
    handler = request.app.state.jwt_handler
    payload = handler.verify_token(token)
    subject: str = str(payload.get("sub", ""))
    roles: list[str] = list(payload.get("roles", []))
    new_token = handler.create_token(subject=subject, roles=roles)
    return {"access_token": new_token, "token_type": "bearer"}
