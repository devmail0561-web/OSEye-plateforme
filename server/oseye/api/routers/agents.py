"""Agents router — /api/v1/agents.

Endpoints:
    GET    /api/v1/agents               — list all known agents (analyst+)
    GET    /api/v1/agents/{cn}          — get agent detail (analyst+)
    GET    /api/v1/agents/blocked       — list revoked agent CNs (admin)
    DELETE /api/v1/agents/{cn}          — revoke agent (admin)
    POST   /api/v1/agents/{cn}/unblock  — restore access (admin)
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status

from oseye.api.auth.rbac import require_admin, require_analyst
from oseye.core.observability import get_logger

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


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


def _get_agent_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "agent_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent repository not initialised",
        )
    return repo


def _row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "cn":             row.cn,
        "online":         row.online,
        "first_seen":     row.first_seen.isoformat() if row.first_seen else None,
        "last_seen":      row.last_seen.isoformat() if row.last_seen else None,
        "version":        row.version,
        "active_profile": row.active_profile,
        "ip_address":     row.ip_address,
    }


@router.get("")
async def list_agents(
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> list[dict[str, Any]]:
    """List all known agents ordered by last_seen."""
    repo = _get_agent_repo(request)
    rows = await repo.list()
    return [_row_to_dict(r) for r in rows]


@router.get("/blocked")
async def list_blocked(
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> list[str]:
    """Return the list of revoked agent CNs."""
    repo = _get_blocked_repo(request)
    return await repo.list_blocked()


@router.get("/{cn}")
async def get_agent(
    cn: Annotated[str, Path(max_length=253)],
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """Get a single agent by CN."""
    repo = _get_agent_repo(request)
    row = await repo.get(cn)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return _row_to_dict(row)


@router.delete("/{cn}", status_code=status.HTTP_204_NO_CONTENT)
async def block_agent(
    cn: Annotated[str, Path(max_length=253)],
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> None:
    """Revoke an agent by CN. Takes effect immediately on active gRPC streams."""
    servicer = _get_servicer(request)
    repo = _get_blocked_repo(request)
    servicer.block_agent(cn)
    await repo.block(cn)
    _logger.info("agent_blocked", cn=cn)


@router.post("/{cn}/unblock", status_code=status.HTTP_204_NO_CONTENT)
async def unblock_agent(
    cn: Annotated[str, Path(max_length=253)],
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> None:
    """Restore access for a previously revoked agent."""
    servicer = _get_servicer(request)
    repo = _get_blocked_repo(request)
    servicer.unblock_agent(cn)
    await repo.unblock(cn)
    _logger.info("agent_unblocked", cn=cn)
