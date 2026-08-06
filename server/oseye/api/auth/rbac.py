"""Role-Based Access Control FastAPI dependencies."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer()


def require_role(*roles: str) -> Any:
    """Return a FastAPI dependency that checks the token contains one of *roles*.

    The request must carry ``Authorization: Bearer <token>``.  The JWT handler
    must have been attached to ``request.app.state.jwt_handler`` by the
    application factory.
    """

    async def _dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> dict[str, Any]:
        handler = request.app.state.jwt_handler
        payload = handler.verify_token(credentials.credentials)
        token_roles: list[str] = payload.get("roles", [])
        if not any(r in token_roles for r in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return payload  # type: ignore[no-any-return]

    return _dependency


# Ready-made dependency instances
require_analyst = require_role("analyst", "admin")
require_admin = require_role("admin")
