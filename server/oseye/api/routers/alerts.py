"""Alerts router — /api/v1/alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel

from oseye.api.auth.rbac import require_analyst
from oseye.core.schema import Alert

router = APIRouter(prefix="/api/v1", tags=["alerts"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AlertPatch(BaseModel):
    """Partial update for an alert — only status and assigned_to."""

    status: str | None = None
    assigned_to: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_alert_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "alert_repo", None)
    if repo is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Alert repository not initialised",
        )
    return repo


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/alerts")
async def list_alerts(
    request: Request,
    alert_status: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """Return a paginated list of alerts with optional filters."""
    repo = _get_alert_repo(request)

    @dataclass
    class _Pagination:
        limit: int
        offset: int

    filters: dict[str, Any] = {}
    if alert_status is not None:
        filters["status"] = alert_status
    if severity is not None:
        filters["severity"] = severity
    if hostname is not None:
        filters["hostname"] = hostname

    page = await repo.list(filters, _Pagination(limit=limit, offset=offset))
    return {
        "items": [a.model_dump(mode="json") for a in page.items],
        "total": page.total,
        "limit": page.limit,
        "offset": page.offset,
    }


@router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: UUID,
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> Alert:
    """Return a single alert by ID."""
    repo = _get_alert_repo(request)
    alert: Alert | None = await repo.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}")
async def patch_alert(
    alert_id: UUID,
    patch: AlertPatch,
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> Alert:
    """Update status and/or assigned_to on an alert."""
    repo = _get_alert_repo(request)
    alert: Alert | None = await repo.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if patch.status is not None:
        alert.status = patch.status  # type: ignore[assignment]
    if patch.assigned_to is not None:
        alert.assigned_to = patch.assigned_to

    alert.updated_at = datetime.now(tz=UTC)
    await repo.update(alert)
    return alert
