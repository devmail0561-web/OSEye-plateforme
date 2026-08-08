"""Decisions router — /api/v1/decisions.

Endpoints:
    GET  /api/v1/decisions              — list with optional filters
    GET  /api/v1/decisions/pending      — list awaiting human approval
    GET  /api/v1/decisions/{id}         — get single decision
    POST /api/v1/decisions/{id}/approve — operator approval
    POST /api/v1/decisions/{id}/reject  — operator rejection
"""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

from dataclasses import dataclass

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger
from oseye.core.pagination import PageResult
from oseye.core.schema import Decision


@dataclass
class _Pagination:
    limit: int
    offset: int

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/decisions", tags=["decisions"])

_require_reader = require_role("analyst", "admin")
_require_admin = require_role("admin")


def _get_decision_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "decision_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Decision repository not initialised",
        )
    return repo


def _get_human_queue(request: Request) -> Any:
    queue = getattr(request.app.state, "human_queue", None)
    if queue is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Human approval queue not initialised",
        )
    return queue


@router.get("")
async def list_decisions(
    request: Request,
    entity_id: str | None = None,
    decision_type: str | None = None,
    requires_human: bool | None = None,
    page: int = 1,
    page_size: int = 20,
    _: dict[str, Any] = Depends(_require_reader),
) -> PageResult[Decision]:
    """Return a paginated list of decisions with optional filters."""
    if page < 1:
        raise HTTPException(status_code=422, detail="page must be >= 1")
    if not 1 <= page_size <= 200:
        raise HTTPException(status_code=422, detail="page_size must be between 1 and 200")

    repo = _get_decision_repo(request)
    filters: dict[str, object] = {}
    if entity_id:
        filters["entity_id"] = entity_id
    if decision_type:
        filters["decision_type"] = decision_type
    if requires_human is not None:
        filters["requires_human"] = requires_human

    pagination = _Pagination(offset=(page - 1) * page_size, limit=page_size)
    return cast(PageResult[Decision], await repo.list_decisions(filters, pagination))


@router.get("/pending")
async def list_pending_decisions(
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> list[Decision]:
    """Return all decisions awaiting human approval."""
    repo = _get_decision_repo(request)
    return cast(list[Decision], await repo.get_pending())


@router.get("/{decision_id}")
async def get_decision(
    decision_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> Decision:
    """Return a single decision by ID."""
    repo = _get_decision_repo(request)
    decision: Decision | None = await repo.get(decision_id)
    if decision is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")
    return decision


@router.post("/{decision_id}/approve")
async def approve_decision(
    decision_id: UUID,
    request: Request,
    note: str = Body(default="", max_length=2000),
    current_user: dict[str, Any] = Depends(_require_admin),
) -> Decision:
    """Approve a decision pending human review. Admin only."""
    queue = _get_human_queue(request)
    operator: str = current_user.get("sub", "unknown")
    result: Decision | None = await queue.approve(decision_id, operator=operator, note=note)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")
    return result


@router.post("/{decision_id}/reject")
async def reject_decision(
    decision_id: UUID,
    request: Request,
    note: str = Body(default="", max_length=2000),
    current_user: dict[str, Any] = Depends(_require_admin),
) -> Decision:
    """Reject a decision pending human review. Admin only."""
    queue = _get_human_queue(request)
    operator: str = current_user.get("sub", "unknown")
    result: Decision | None = await queue.reject(decision_id, operator=operator, note=note)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")
    return result
