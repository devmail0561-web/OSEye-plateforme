"""Alerts router — /api/v1/alerts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, StringConstraints

from oseye.api.auth.rbac import require_analyst
from oseye.core.observability import get_logger
from oseye.core.schema import Alert

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["alerts"])

_VALID_STATUSES = {"open", "acknowledged", "investigating", "resolved", "false_positive"}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AlertPatch(BaseModel):
    """Partial update for an alert — only status and assigned_to."""

    status: str | None = None
    assigned_to: Annotated[str, StringConstraints(max_length=200)] | None = None


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
# Routes — fixed routes BEFORE parameterised ones to avoid ambiguity
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


@router.get("/alerts/stats")
async def alerts_stats(
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """Return alert counts grouped by severity and status."""
    repo = _get_alert_repo(request)
    stats: dict[str, Any] = {}
    for sev in ("low", "medium", "high", "critical"):
        stats[sev] = await repo.count({"severity": sev})
    open_count = await repo.count({"status": "open"})
    return {"by_severity": stats, "open": open_count}


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
        if patch.status not in _VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid status: {patch.status}",
            )
        alert.status = patch.status  # type: ignore[assignment]
    if patch.assigned_to is not None:
        alert.assigned_to = patch.assigned_to

    alert.updated_at = datetime.now(tz=UTC)
    await repo.update(alert)
    return alert


@router.post("/alerts/{alert_id}/acknowledge", status_code=status.HTTP_200_OK)
async def acknowledge_alert(
    alert_id: UUID,
    request: Request,
    auth: dict[str, Any] = Depends(require_analyst),
) -> Alert:
    """Set alert status to 'acknowledged'."""
    repo = _get_alert_repo(request)
    alert: Alert | None = await repo.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.status = "acknowledged"
    alert.assigned_to = alert.assigned_to or auth.get("sub", "")
    alert.updated_at = datetime.now(tz=UTC)
    await repo.update(alert)

    ws_manager = getattr(request.app.state, "ws_alert_manager", None)
    if ws_manager is not None:
        await ws_manager.broadcast(
            json.dumps(
                {"event": "alert_updated", "alert_id": str(alert_id), "status": "acknowledged"}
            ).encode()
        )

    return alert


@router.post("/alerts/{alert_id}/false-positive", status_code=status.HTTP_200_OK)
async def mark_false_positive(
    alert_id: UUID,
    request: Request,
    auth: dict[str, Any] = Depends(require_analyst),
) -> Alert:
    """Mark alert as false positive, increment rule fp counter, log to rule_versions."""
    repo = _get_alert_repo(request)
    alert: Alert | None = await repo.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.status = "false_positive"
    alert.false_positive_count += 1
    alert.updated_at = datetime.now(tz=UTC)
    await repo.update(alert)

    # P3.14 — log to rule_versions
    rv_repo = getattr(request.app.state, "rule_version_repo", None)
    if rv_repo is not None and alert.rule_id:
        operator = str(auth.get("sub", "unknown"))
        try:
            await rv_repo.log_false_positive(
                rule_id=alert.rule_id,
                alert_id=str(alert_id),
                operator=operator,
                false_positive_count=alert.false_positive_count,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning("rule_version_log_failed", error=str(exc))

    return alert
