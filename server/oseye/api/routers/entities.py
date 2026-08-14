"""Entities router — /api/v1/entities.

Provides read-only risk profiles for observed entities (processes, users,
connections, files).  Profiles are computed on-the-fly from the alerts and
events tables — no separate entity table is required until Phase 6.

Endpoints:
    GET /entities/{entity_id}          — risk profile for a specific entity
    GET /entities                      — list top-N risky entities on a host
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from oseye.api.auth.rbac import require_analyst
from oseye.core.schema import EntityProfile

router = APIRouter(prefix="/api/v1", tags=["entities"])

_SEVERITY_WEIGHT = {"low": 1.0, "medium": 3.0, "high": 7.0, "critical": 15.0}


def _get_alert_repo(request: Request) -> Any:
    repo = getattr(request.app.state, "alert_repo", None)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Alert repository not available",
        )
    return repo


def _compute_risk(alerts: list[Any]) -> float:
    """Weighted risk score in [0, 100] from a list of Alert objects."""
    if not alerts:
        return 0.0
    raw = sum(_SEVERITY_WEIGHT.get(str(a.severity), 1.0) for a in alerts)
    # Logarithmic cap so a flood of low-sev alerts doesn't dwarf one critical
    import math
    return min(100.0, round(10.0 * math.log1p(raw), 2))


@router.get("/entities/{entity_id:path}")
async def get_entity(
    entity_id: str,
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> EntityProfile:
    """Return the risk profile for a specific entity.

    ``entity_id`` is the string stored on alerts, typically ``"hostname:pid"``
    for processes or an IP address for connections.
    """
    alert_repo = _get_alert_repo(request)
    alerts = await alert_repo.list_by_entity(entity_id)

    if not alerts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No alerts found for entity {entity_id!r}",
        )

    # Infer entity_type from entity_id shape
    if ":" in entity_id and entity_id.split(":")[-1].isdigit():
        entity_type = "process"
    elif "." in entity_id or ":" in entity_id:
        entity_type = "connection"
    else:
        entity_type = "file"

    hostname = alerts[0].hostname if alerts else ""
    last_seen: datetime | None = max((a.updated_at for a in alerts), default=None)

    return EntityProfile(
        entity_id=entity_id,
        entity_type=entity_type,  # type: ignore[arg-type]
        hostname=hostname,
        risk_score=_compute_risk(alerts),
        alert_count=len(alerts),
        last_seen=last_seen,
    )


@router.get("/entities")
async def list_entities(
    request: Request,
    hostname: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    _auth: dict[str, Any] = Depends(require_analyst),
) -> list[EntityProfile]:
    """List top-N entities ranked by risk score.

    Optionally filtered to a specific hostname.
    """
    alert_repo = _get_alert_repo(request)
    all_alerts = await alert_repo.list_all(hostname=hostname, limit=5000)

    # Group by entity_id
    by_entity: dict[str, list[Any]] = {}
    for a in all_alerts:
        by_entity.setdefault(a.entity_id, []).append(a)

    profiles: list[EntityProfile] = []
    for eid, alerts in by_entity.items():
        if ":" in eid and eid.split(":")[-1].isdigit():
            etype = "process"
        elif "." in eid or ":" in eid:
            etype = "connection"
        else:
            etype = "file"

        last_seen = max((a.updated_at for a in alerts), default=None)
        profiles.append(EntityProfile(
            entity_id=eid,
            entity_type=etype,  # type: ignore[arg-type]
            hostname=alerts[0].hostname,
            risk_score=_compute_risk(alerts),
            alert_count=len(alerts),
            last_seen=last_seen,
        ))

    profiles.sort(key=lambda p: p.risk_score, reverse=True)
    return profiles[:limit]
