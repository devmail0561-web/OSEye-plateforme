"""Decisions router — /api/v1/decisions.

Endpoints:
    GET  /api/v1/decisions              — list with optional filters
    GET  /api/v1/decisions/pending      — list awaiting human approval
    GET  /api/v1/decisions/{id}         — get single decision
    POST /api/v1/decisions/{id}/approve — operator approval
    POST /api/v1/decisions/{id}/reject  — operator rejection
"""

from __future__ import annotations

import os as _os
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from slowapi import Limiter

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

# TODO(sec): each router instantiates its own Limiter; a shared request.app.state.limiter
# would allow the global RateLimitExceeded handler in app.py to intercept 429s correctly.
def _get_ip(request):
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for and _os.getenv("OSEYE_TRUST_PROXY", "").lower() == "true":
        return forwarded_for.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"

_limiter = Limiter(key_func=_get_ip)

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
    entity_id: str | None = Query(default=None, max_length=200),
    decision_type: str | None = Query(default=None, max_length=200),
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
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: dict[str, Any] = Depends(_require_reader),
) -> list[Decision]:
    """Return decisions awaiting human approval (paginated)."""
    repo = _get_decision_repo(request)
    all_pending = cast(list[Decision], await repo.get_pending())
    return all_pending[offset : offset + limit]


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


@router.get("/journal/verify")
@_limiter.limit("5/minute")
async def verify_journal_integrity(
    request: Request,
    limit: int = Query(default=1000, ge=1, le=10000),
    _auth: dict[str, Any] = Depends(_require_reader),
) -> dict[str, object]:
    """Verify the BLAKE3 hash chain integrity of the decision journal.

    Returns:
        ``{"intact": true, "checked": N, "broken_indices": []}`` when the
        chain is unbroken.  ``broken_indices`` lists the 0-based positions
        of decisions with a hash mismatch — non-empty means tampering or
        data corruption.
    """
    from oseye.decision.journal import DecisionJournal

    repo = _get_decision_repo(request)
    pagination = _Pagination(limit=limit, offset=0)
    page = await repo.list_decisions(filters={}, pagination=pagination)
    decisions = page.items

    journal = DecisionJournal()
    broken = journal.verify_chain(decisions)

    return {
        "intact": len(broken) == 0,
        "checked": len(decisions),
        "broken_indices": broken,
    }
