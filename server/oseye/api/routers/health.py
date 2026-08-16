"""Health-check router."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import Any

from fastapi import APIRouter, Depends

from oseye.api.auth.rbac import require_analyst

router = APIRouter(prefix="/api/v1")


@router.get("/health")
async def health() -> dict[str, str]:
    """Public health check — returns minimal status only.

    API-11: version and technology details are omitted from this unauthenticated
    endpoint to avoid information disclosure. Use /health/detailed (requires auth)
    for full diagnostics.
    """
    return {"status": "ok"}


@router.get("/health/detailed")
async def health_detailed(
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """Authenticated health check — includes service name and version.

    Requires at least 'analyst' role.
    """
    try:
        ver = _pkg_version("oseye-server")
    except PackageNotFoundError:
        ver = "dev"
    return {
        "status": "ok",
        "service": "oseye-server",
        "version": ver,
    }
