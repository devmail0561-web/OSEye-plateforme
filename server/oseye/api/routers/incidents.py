"""Incidents router — /api/v1/incidents."""

from __future__ import annotations

from typing import Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.params import Annotated

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger
from oseye.core.pagination import PageResult
from oseye.core.schema import Incident

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

_require_incident_reader = require_role("analyst", "admin")


def _get_incident_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "incident_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Incident repository not initialised",
        )
    return repo


@router.get("")
async def list_incidents(
    request: Request,
    # SEC-INPUT-001: max_length on filter string params to prevent DoS.
    # F12: rename param to incident_status to avoid shadowing fastapi.status.
    hostname: Annotated[str | None, Query(max_length=253)] = None,
    # SEC-INPUT-002: restrict status to known values to reject invalid inputs at the
    # FastAPI validation layer rather than forwarding garbage to the repository.
    incident_status: Annotated[
        Literal["open", "investigating", "contained", "resolved", "closed"] | None,
        Query(alias="status"),
    ] = None,
    page: int = 1,
    page_size: int = 20,
    _: dict[str, Any] = Depends(_require_incident_reader),
) -> PageResult[Incident]:
    """Return a paginated list of incidents with optional hostname/status filters."""
    if page < 1:
        raise HTTPException(
            status_code=422,
            detail="page must be >= 1",
        )
    if not 1 <= page_size <= 200:
        raise HTTPException(
            status_code=422,
            detail="page_size must be between 1 and 200",
        )

    repo = _get_incident_repo(request)
    return cast(PageResult[Incident], await repo.list_incidents(
        hostname=hostname,
        status=incident_status,
        page=page,
        page_size=page_size,
    ))


@router.get("/{incident_id}")
async def get_incident(
    incident_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_incident_reader),
) -> Incident:
    """Return a single incident by ID."""
    repo = _get_incident_repo(request)
    incident: Incident | None = await repo.get(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return incident
