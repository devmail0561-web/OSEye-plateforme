"""Response Actions router — /api/v1/response-actions.

Endpoints:
    GET    /api/v1/response-actions              — list actions (analyst+)
    GET    /api/v1/response-actions/{id}         — get action (analyst+)
    POST   /api/v1/response-actions/{id}/rollback — rollback (admin only)
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from oseye.api.auth.rbac import require_admin, require_analyst
from oseye.core.observability import get_logger
from oseye.storage.models import ResponseActionRow

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/response-actions", tags=["response-actions"])


def _get_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "response_actions_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Response actions repository not initialised",
        )
    return repo


def _get_executor(request: Request) -> Any:
    executor = getattr(request.app.state, "action_executor", None)
    if executor is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Action executor not initialised",
        )
    return executor


@router.get("")
async def list_response_actions(
    request: Request,
    agent_cn: str | None = Query(default=None, max_length=253),
    action_status: str | None = Query(default=None, max_length=50),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _auth: dict[str, Any] = Depends(require_analyst),
) -> list[dict]:
    """List response actions with optional filters."""
    repo = _get_repo(request)
    rows = await repo.list(agent_cn=agent_cn, status=action_status, limit=limit, offset=offset)
    return [_row_to_dict(r) for r in rows]


@router.get("/{command_id}")
async def get_response_action(
    command_id: str,
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict:
    """Get a single response action by command_id."""
    repo = _get_repo(request)
    row = await repo.get(command_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    return _row_to_dict(row)


_NON_REVERSIBLE: frozenset[str] = frozenset({"KILL_PROCESS"})


@router.post("/{command_id}/rollback", status_code=status.HTTP_204_NO_CONTENT)
async def rollback_response_action(
    command_id: str,
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> None:
    """Roll back an executed response action.

    Sends the appropriate inverse command to the agent:
      BLOCK_IP        → UNBLOCK_IP
      QUARANTINE_FILE → RESTORE_FILE

    AG-R-03: KILL_PROCESS is not reversible — returns 422.
    AG-R-02: Persist BEFORE emit to guarantee correct ordering; atomic
             conditional UPDATE prevents concurrent double-rollback races.
    """
    repo = _get_repo(request)
    row = await repo.get(command_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    # AG-R-03: reject non-reversible command types early.
    if row.command_type in _NON_REVERSIBLE:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{row.command_type} cannot be rolled back",
        )

    executor = _get_executor(request)
    try:
        payload = json.loads(row.payload) if row.payload else {}
    except json.JSONDecodeError:
        payload = {}

    # AG-R-02: atomically persist first; emit only if persist succeeded.
    success = await repo.atomic_mark_rolled_back(command_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="action is already rolled_back or not in executed state",
        )

    await executor.emit_rollback(
        cn=row.agent_cn,
        command_id=command_id,
        command_type=row.command_type,
        payload=payload,
    )
    _logger.info(
        "response_action_rollback_requested",
        command_id=command_id,
        agent_cn=row.agent_cn,
        command_type=row.command_type,
    )


def _row_to_dict(row: ResponseActionRow) -> dict:
    return {
        "command_id":     row.command_id,
        "decision_id":    row.decision_id,
        "agent_cn":       row.agent_cn,
        "command_type":   row.command_type,
        "payload":        json.loads(row.payload) if row.payload else {},
        "status":         row.status,
        "created_at":     row.created_at.isoformat() if row.created_at else None,
        "executed_at":    row.executed_at.isoformat() if row.executed_at else None,
        "rolled_back_at": row.rolled_back_at.isoformat() if row.rolled_back_at else None,
        "error":          row.error,
    }
