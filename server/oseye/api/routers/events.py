"""Events router — /api/v1/events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from oseye.api.auth.rbac import require_analyst
from oseye.core.schema import UniversalEvent

router = APIRouter(prefix="/api/v1", tags=["events"])

# ---------------------------------------------------------------------------
# Query parameter dataclasses
# ---------------------------------------------------------------------------


@dataclass
class EventQueryParams:
    hostname: str | None = None
    category: str | None = None
    severity: str | None = None
    from_ts: int | None = None
    to_ts: int | None = None
    agent_id: UUID | None = None
    limit: Annotated[int, Query(ge=1, le=500)] = 50
    offset: Annotated[int, Query(ge=0)] = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_event_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "event_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Event repository not initialised",
        )
    return repo


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/events")
async def list_events(
    request: Request,
    hostname: str | None = Query(default=None),
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    from_ts: int | None = Query(default=None),
    to_ts: int | None = Query(default=None),
    agent_id: UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """Return a paginated, filtered list of events."""
    repo = _get_event_repo(request)

    @dataclass
    class _Filter:
        hostname: str | None = None
        category: str | None = None
        type: str | None = None
        severity: str | None = None
        uid: int | None = None
        pid: int | None = None
        process_name: str | None = None
        resource: str | None = None
        rule_id: str | None = None
        mitre_technique: str | None = None
        from_ts: int | None = None
        to_ts: int | None = None
        agent_id: UUID | None = None
        incident_chain_id: UUID | None = None

    @dataclass
    class _Pagination:
        limit: int
        offset: int

    filters = _Filter(
        hostname=hostname,
        category=category,
        severity=severity,
        from_ts=from_ts,
        to_ts=to_ts,
        agent_id=agent_id,
    )
    pagination = _Pagination(limit=limit, offset=offset)
    page = await repo.query(filters, pagination)
    return {
        "items": [e.model_dump(mode="json") for e in page.items],
        "total": page.total,
        "limit": page.limit,
        "offset": page.offset,
    }


@router.get("/events/{event_id}")
async def get_event(
    event_id: UUID,
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> UniversalEvent:
    """Return a single event by ID."""
    repo = _get_event_repo(request)
    event: UniversalEvent | None = await repo.get(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
