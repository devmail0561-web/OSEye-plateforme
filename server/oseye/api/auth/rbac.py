"""Role-Based Access Control FastAPI dependencies.

Supports two auth methods (P3.12 + P3.13):
- Bearer JWT:  Authorization: Bearer <token>
- API Key:     X-API-Key: osk_<token>

Both are checked transparently by require_role().
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer(auto_error=False)


async def _resolve_identity(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any]:
    """Resolve caller identity from Bearer JWT or X-API-Key header."""
    # Try X-API-Key first
    api_key_raw = request.headers.get("X-API-Key")
    if api_key_raw:
        repo = getattr(request.app.state, "api_key_repo", None)
        if repo is not None:
            info = await repo.verify(api_key_raw)
            if info is not None:
                return {"sub": info["name"], "roles": info["roles"], "auth_method": "api_key"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fall back to JWT Bearer
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    handler = request.app.state.jwt_handler
    payload: dict[str, Any] = handler.verify_token(credentials.credentials)
    return payload


def require_role(*roles: str) -> Any:
    """Return a FastAPI dependency that checks the caller has one of *roles*."""

    async def _dependency(
        identity: dict[str, Any] = Depends(_resolve_identity),
    ) -> dict[str, Any]:
        token_roles: list[str] = identity.get("roles", [])
        if not any(r in token_roles for r in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return identity

    return _dependency


# Ready-made dependency instances
require_analyst = require_role("analyst", "admin")
require_admin = require_role("admin")
