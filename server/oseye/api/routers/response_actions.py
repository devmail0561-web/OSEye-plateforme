"""Response Actions router — /api/v1/response-actions.

Endpoints:
    GET    /api/v1/response-actions              — list actions (analyst+)
    GET    /api/v1/response-actions/{id}         — get action (analyst+)
    POST   /api/v1/response-actions/{id}/rollback — rollback (admin only)
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from oseye.api.auth.rbac import require_analyst, require_admin
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
    agent_cn: str | None = None,
    action_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
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

    CIA — Disponibilité : the rollback is persisted before the command is sent.
    """
    repo = _get_repo(request)
    row = await repo.get(command_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    if row.status != "executed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot rollback action with status '{row.status}'",
        )

    executor = _get_executor(request)
    try:
        payload = json.loads(row.payload) if row.payload else {}
    except json.JSONDecodeError:
        payload = {}

    await executor.emit_rollback(
        cn=row.agent_cn,
        command_id=command_id,
        command_type=row.command_type,
        payload=payload,
    )
    await repo.mark_rolled_back(command_id)
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
