"""Snapshots router — /api/v1/snapshots.

Endpoints:
    POST /api/v1/snapshots              — store a snapshot (submitted by agent or manually)
    GET  /api/v1/snapshots/{id}         — get single snapshot
    GET  /api/v1/snapshots/agent/{id}   — list snapshots for an agent
    POST /api/v1/snapshots/diff         — diff two snapshots by ID
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger
from oseye.core.schema import AgentSnapshot

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/snapshots", tags=["snapshots"])

_require_reader = require_role("analyst", "admin")
_require_writer = require_role("analyst", "admin")

# SEC-RATELIMIT-001: snapshot creation and diff are expensive operations.
_limiter = Limiter(key_func=get_remote_address)


def _get_snapshot_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "snapshot_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Snapshot repository not initialised",
        )
    return repo


@router.post("", status_code=status.HTTP_201_CREATED)
@_limiter.limit("30/minute")
async def create_snapshot(
    snapshot: AgentSnapshot,
    request: Request,
    _: dict[str, Any] = Depends(_require_writer),
) -> AgentSnapshot:
    repo = _get_snapshot_repo(request)
    return await repo.create(snapshot)  # type: ignore[no-any-return]


@router.get("/{snapshot_id}")
async def get_snapshot(
    snapshot_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> AgentSnapshot:
    repo = _get_snapshot_repo(request)
    snap = await repo.get(snapshot_id)
    if snap is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snap


@router.get("/agent/{agent_id}")
async def list_agent_snapshots(
    agent_id: UUID,
    request: Request,
    limit: int = 20,
    _: dict[str, Any] = Depends(_require_reader),
) -> list[AgentSnapshot]:
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    repo = _get_snapshot_repo(request)
    return await repo.list_by_agent(agent_id, limit=limit)  # type: ignore[no-any-return]


@router.post("/diff")
@_limiter.limit("20/minute")
async def diff_snapshots(
    request: Request,
    before_id: UUID,
    after_id: UUID,
    _: dict[str, Any] = Depends(_require_reader),
) -> dict[str, Any]:
    from oseye.forensic.snapshot import diff_snapshots as _diff

    repo = _get_snapshot_repo(request)
    before = await repo.get(before_id)
    after = await repo.get(after_id)
    if before is None:
        raise HTTPException(status_code=404, detail=f"Snapshot {before_id} not found")
    if after is None:
        raise HTTPException(status_code=404, detail=f"Snapshot {after_id} not found")
    return _diff(before, after)
