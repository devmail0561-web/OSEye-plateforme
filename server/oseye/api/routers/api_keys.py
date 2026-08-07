"""API keys router — /api/v1/api-keys.

Only admins can create and revoke keys.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, StringConstraints

from oseye.api.auth.rbac import require_admin

router = APIRouter(prefix="/api/v1", tags=["api-keys"])


class ApiKeyCreate(BaseModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    roles: list[str] = ["analyst"]
    expires_at: datetime | None = None


class ApiKeyResponse(BaseModel):
    key_id: str
    name: str
    roles: list[str]
    created_at: str
    expires_at: str | None
    revoked: bool
    created_by: str


class ApiKeyCreated(BaseModel):
    key: str
    key_id: str
    name: str
    roles: list[str]


def _get_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "api_key_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API key repository not initialised",
        )
    return repo


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: ApiKeyCreate,
    request: Request,
    auth: dict[str, Any] = Depends(require_admin),
) -> ApiKeyCreated:
    """Generate a new API key (admin only). The raw key is shown once."""
    repo = _get_repo(request)
    raw, key_id = await repo.create(
        name=body.name,
        roles=body.roles,
        created_by=str(auth.get("sub", "unknown")),
        expires_at=body.expires_at,
    )
    return ApiKeyCreated(key=raw, key_id=key_id, name=body.name, roles=body.roles)


@router.get("/api-keys")
async def list_api_keys(
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List all API keys (admin only). Raw keys are never returned."""
    repo = _get_repo(request)
    items = await repo.list()
    return {"items": items, "total": len(items)}


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> None:
    """Revoke an API key by ID (admin only)."""
    repo = _get_repo(request)
    found = await repo.revoke(key_id)
    if not found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
