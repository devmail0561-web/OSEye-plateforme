"""Authentication router — /api/v1/auth/token, /api/v1/auth/refresh.

SEC-PREV-002: /auth/token is rate-limited to 5 requests/minute per IP.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


@router.post("/token")
@limiter.limit("5/minute")
async def login(
    request: Request,  # required by slowapi
    form: OAuth2PasswordRequestForm = Depends(),
) -> dict[str, Any]:
    """Issue a JWT access token (SEC-PREV-002: 5 req/min per IP).

    For development, any username/password combination is accepted.
    In production this should validate against a user store.
    """
    handler = request.app.state.jwt_handler

    # Development stub — replace with real user lookup in production
    if not form.username or not form.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="username and password are required",
        )

    # Default role: analyst; 'admin' username gets admin role
    roles = ["admin"] if form.username == "admin" else ["analyst"]
    token = handler.create_token(subject=form.username, roles=roles)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/refresh")
async def refresh(request: Request, token: str) -> dict[str, Any]:
    """Refresh a token by verifying the existing one and issuing a new one."""
    handler = request.app.state.jwt_handler
    payload = handler.verify_token(token)
    subject: str = str(payload.get("sub", ""))
    roles: list[str] = list(payload.get("roles", []))
    new_token = handler.create_token(subject=subject, roles=roles)
    return {"access_token": new_token, "token_type": "bearer"}
