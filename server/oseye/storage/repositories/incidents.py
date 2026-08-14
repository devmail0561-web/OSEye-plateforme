"""SQL implementation of IncidentRepository (M26 — Correlation Engine)."""

from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.core.pagination import PageResult
from oseye.core.schema import Incident, IncidentEvent
from oseye.storage.models import IncidentAlertRow, IncidentRow

# ---------------------------------------------------------------------------
# ORM ↔ Pydantic helpers
# ---------------------------------------------------------------------------

def _to_domain(row: IncidentRow, alerts: list[IncidentAlertRow]) -> Incident:
    sorted_alerts = sorted(alerts, key=lambda r: r.added_at)
    timeline = [
        IncidentEvent(
            alert_id=UUID(r.alert_id),
            timestamp=datetime.fromisoformat(r.added_at),
            severity=r.severity,  # type: ignore[arg-type]
            title=r.title,
            hostname=r.hostname,
            mitre_techniques=json.loads(r.mitre_techniques),
        )
        for r in sorted_alerts
    ]
    return Incident(
        incident_id=UUID(row.incident_id),
        created_at=datetime.fromisoformat(row.created_at),
        updated_at=datetime.fromisoformat(row.updated_at),
        hostname=row.hostname,
        severity=row.severity,  # type: ignore[arg-type]
        status=row.status,  # type: ignore[arg-type]
        alert_ids=[UUID(x) for x in json.loads(row.alert_ids)],
        timeline=timeline,
        mitre_tactics=json.loads(row.mitre_tactics),
        correlation_rule=row.correlation_rule,
        timeframe_seconds=row.timeframe_seconds,
        alert_count=row.alert_count,
    )


def _to_row(incident: Incident) -> IncidentRow:
    return IncidentRow(
        incident_id=str(incident.incident_id),
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
        hostname=incident.hostname,
        severity=incident.severity,
        status=incident.status,
        mitre_tactics=json.dumps(incident.mitre_tactics),
        correlation_rule=incident.correlation_rule,
        timeframe_seconds=incident.timeframe_seconds,
        alert_count=incident.alert_count,
        alert_ids=json.dumps([str(x) for x in incident.alert_ids]),
    )


async def _load_alerts(session: AsyncSession, incident_id: str) -> list[IncidentAlertRow]:
    result = await session.execute(
        select(IncidentAlertRow).where(IncidentAlertRow.incident_id == incident_id)
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class SQLIncidentRepository:
    """IncidentRepository backed by SQLAlchemy async session."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, incident: Incident) -> Incident:
        async with self._session_factory() as session:
            async with session.begin():
                row = _to_row(incident)
                session.add(row)
                for event in incident.timeline:
                    session.add(
                        IncidentAlertRow(
                            incident_id=str(incident.incident_id),
                            alert_id=str(event.alert_id),
                            added_at=event.timestamp.isoformat(),
                            severity=event.severity,
                            title=event.title,
                            hostname=event.hostname,
                            mitre_techniques=json.dumps(event.mitre_techniques),
                        )
                    )
        return incident

    async def get(self, incident_id: UUID) -> Incident | None:
        async with self._session_factory() as session:
            row = await session.get(IncidentRow, str(incident_id))
            if row is None:
                return None
            alerts = await _load_alerts(session, str(incident_id))
            return _to_domain(row, alerts)

    async def update(self, incident: Incident) -> Incident:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(IncidentRow, str(incident.incident_id))
                if row is None:
                    raise ValueError(f"Incident {incident.incident_id} not found")
                row.updated_at = incident.updated_at.isoformat()
                row.hostname = incident.hostname
                row.severity = incident.severity
                row.status = incident.status
                row.mitre_tactics = json.dumps(incident.mitre_tactics)
                row.correlation_rule = incident.correlation_rule
                row.timeframe_seconds = incident.timeframe_seconds
                row.alert_count = incident.alert_count
                row.alert_ids = json.dumps([str(x) for x in incident.alert_ids])
        return incident

    async def list_incidents(
        self,
        hostname: str | None,
        status: str | None,
        page: int,
        page_size: int,
    ) -> PageResult[Incident]:
        async with self._session_factory() as session:
            stmt = select(IncidentRow)
            if hostname is not None:
                stmt = stmt.where(IncidentRow.hostname == hostname)
            if status is not None:
                stmt = stmt.where(IncidentRow.status == status)

            count_stmt = select(func.count()).select_from(stmt.subquery())
            total: int = (await session.execute(count_stmt)).scalar_one()

            offset = (page - 1) * page_size
            rows = (
                await session.execute(
                    stmt.order_by(IncidentRow.created_at.desc())
                    .offset(offset)
                    .limit(page_size)
                )
            ).scalars().all()

            # DETTE-017: batch-load all alert rows in a single IN query instead
            # of one SELECT per incident row (N+1 → 2 queries total).
            incident_ids = [row.incident_id for row in rows]
            alerts_by_incident: dict[str, list[IncidentAlertRow]] = {
                iid: [] for iid in incident_ids
            }
            if incident_ids:
                alert_rows = (
                    await session.execute(
                        select(IncidentAlertRow).where(
                            IncidentAlertRow.incident_id.in_(incident_ids)
                        )
                    )
                ).scalars().all()
                for ar in alert_rows:
                    alerts_by_incident.setdefault(ar.incident_id, []).append(ar)

            items = [
                _to_domain(row, alerts_by_incident.get(row.incident_id, []))
                for row in rows
            ]
            return PageResult(items=items, total=total, limit=page_size, offset=offset)

    async def add_alert(self, incident_id: UUID, event: IncidentEvent) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                alert_row = IncidentAlertRow(
                    incident_id=str(incident_id),
                    alert_id=str(event.alert_id),
                    added_at=event.timestamp.isoformat(),
                    severity=event.severity,
                    title=event.title,
                    hostname=event.hostname,
                    mitre_techniques=json.dumps(event.mitre_techniques),
                )
                session.add(alert_row)

                incident_row = await session.get(IncidentRow, str(incident_id))
                if incident_row is None:
                    raise ValueError(f"Incident {incident_id} not found")

                existing_ids: list[str] = json.loads(incident_row.alert_ids)
                alert_id_str = str(event.alert_id)
                if alert_id_str not in existing_ids:
                    existing_ids.append(alert_id_str)
                incident_row.alert_ids = json.dumps(existing_ids)
                incident_row.alert_count = len(existing_ids)

    async def find_open_for_host(self, hostname: str, since: datetime) -> Incident | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(IncidentRow)
                .where(IncidentRow.hostname == hostname)
                .where(IncidentRow.status == "open")
                .where(IncidentRow.created_at >= since.isoformat())
                .order_by(IncidentRow.created_at.desc())
                .limit(1)
            )
            row = result.scalars().first()
            if row is None:
                return None
            alerts = await _load_alerts(session, row.incident_id)
            return _to_domain(row, alerts)

    async def find_open_incidents_for_host(
        self, hostname: str, since: datetime
    ) -> list[Incident]:
        """Return ALL open incidents for *hostname* created after *since*.

        Used by the CorrelationEngine to select the best match across multiple
        concurrent incidents on the same host.

        PC-09: batch-loads all alert rows in a single IN query (2 queries total)
        instead of one SELECT per incident (N+1).
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(IncidentRow)
                .where(IncidentRow.hostname == hostname)
                .where(IncidentRow.status == "open")
                .where(IncidentRow.created_at >= since.isoformat())
                .order_by(IncidentRow.created_at.desc())
                .limit(20)  # safety cap — a host shouldn't have hundreds of open incidents
            )
            rows = result.scalars().all()
            if not rows:
                return []

            # PC-09: batch-load all alert rows in one IN query
            incident_ids = [row.incident_id for row in rows]
            alerts_by_incident: dict[str, list[IncidentAlertRow]] = {
                iid: [] for iid in incident_ids
            }
            alert_rows = (
                await session.execute(
                    select(IncidentAlertRow).where(
                        IncidentAlertRow.incident_id.in_(incident_ids)
                    )
                )
            ).scalars().all()
            for ar in alert_rows:
                alerts_by_incident.setdefault(ar.incident_id, []).append(ar)

            return [
                _to_domain(row, alerts_by_incident.get(row.incident_id, []))
                for row in rows
            ]

    async def close_stale(self, cutoff: datetime) -> int:
        """Set status='resolved' on open incidents not updated since *cutoff*.

        Returns the number of incidents closed.

        PC-12: uses a single bulk UPDATE instead of loading all rows into memory
        and updating them one at a time.
        """
        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    update(IncidentRow)
                    .where(IncidentRow.status == "open")
                    .where(IncidentRow.updated_at < cutoff.isoformat())
                    .values(status="resolved")
                )
                return result.rowcount
