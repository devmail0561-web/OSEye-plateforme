"""Agents router — /api/v1/agents (admin-only).

Endpoints:
    GET    /api/v1/agents/blocked        — list revoked agent CNs
    DELETE /api/v1/agents/{cn}           — revoke agent (immediate + persisted)
    POST   /api/v1/agents/{cn}/unblock   — restore access (immediate + persisted)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from oseye.api.auth.rbac import require_admin
from oseye.core.observability import get_logger

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

_require_admin = require_admin


def _get_servicer(request: Request) -> Any:
    servicer = getattr(request.app.state, "grpc_servicer", None)
    if servicer is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="gRPC servicer not initialised",
        )
    return servicer


def _get_blocked_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "blocked_agents_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blocked agents repository not initialised",
        )
    return repo


@router.get("/blocked")
async def list_blocked(
    request: Request,
    _auth: dict[str, Any] = Depends(_require_admin),
) -> list[str]:
    """Return the list of revoked agent CNs."""
    repo = _get_blocked_repo(request)
    return await repo.list_blocked()


@router.delete("/{cn}", status_code=status.HTTP_204_NO_CONTENT)
async def block_agent(
    cn: str,
    request: Request,
    _auth: dict[str, Any] = Depends(_require_admin),
) -> None:
    """Revoke an agent by CN. Takes effect immediately on active gRPC streams."""
    servicer = _get_servicer(request)
    repo = _get_blocked_repo(request)
    servicer.block_agent(cn)
    await repo.block(cn)
    _logger.info("agent_blocked", cn=cn)


@router.post("/{cn}/unblock", status_code=status.HTTP_204_NO_CONTENT)
async def unblock_agent(
    cn: str,
    request: Request,
    _auth: dict[str, Any] = Depends(_require_admin),
) -> None:
    """Restore access for a previously revoked agent."""
    servicer = _get_servicer(request)
    repo = _get_blocked_repo(request)
    servicer.unblock_agent(cn)
    await repo.unblock(cn)
    _logger.info("agent_unblocked", cn=cn)
