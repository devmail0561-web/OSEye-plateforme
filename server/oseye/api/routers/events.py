"""Events router — /api/v1/events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from oseye.api.auth.rbac import require_analyst
from oseye.core.schema import UniversalEvent

router = APIRouter(prefix="/api/v1", tags=["events"])

# SEC-RATELIMIT-001: list events is expensive (full-table scan with filters).
# TODO(sec): each router instantiates its own Limiter; a shared request.app.state.limiter
# would allow the global RateLimitExceeded handler in app.py to intercept 429s correctly.
_limiter = Limiter(key_func=get_remote_address)

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
@_limiter.limit("60/minute")
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


@router.get("/events/{event_id}/chain")
@_limiter.limit("30/minute")
async def get_event_chain(
    event_id: UUID,
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    _auth: dict[str, Any] = Depends(require_analyst),
) -> list[UniversalEvent]:
    """Return all events in the same incident chain as *event_id*.

    The chain is identified by the ``incident_chain_id`` field set when the
    Decision Engine escalates a correlated incident.  Events are returned in
    chronological order (oldest first).  Returns a single-element list when the
    event has no chain (``incident_chain_id`` is null).
    """
    repo = _get_event_repo(request)
    event: UniversalEvent | None = await repo.get(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    if event.incident_chain_id is None:
        return [event]

    filters = _Filter(incident_chain_id=event.incident_chain_id)
    pagination = _Pagination(limit=limit, offset=0)
    page = await repo.query(filters, pagination)
    return sorted(page.items, key=lambda e: e.timestamp_ns)
