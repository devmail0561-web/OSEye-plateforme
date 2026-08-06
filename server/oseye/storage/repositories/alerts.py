"""SQL implementation of AlertRepository."""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.core.schema import Alert, AlertNote
from oseye.storage.interface import Pagination
from oseye.storage.models import AlertNoteRow, AlertRow


@dataclass
class PageResult[T]:
    items: list[T]
    total: int
    limit: int
    offset: int


def _row_to_alert(row: AlertRow, notes: list[AlertNote] | None = None) -> Alert:
    from datetime import datetime

    return Alert(
        alert_id=UUID(row.alert_id),
        created_at=datetime.fromisoformat(row.created_at),
        updated_at=datetime.fromisoformat(row.updated_at),
        severity=row.severity,  # type: ignore[arg-type]
        status=row.status,  # type: ignore[arg-type]
        rule_id=row.rule_id,
        ml_triggered=row.ml_triggered,
        ti_triggered=row.ti_triggered,
        entity_id=row.entity_id,
        hostname=row.hostname,
        trigger_event_id=UUID(row.trigger_event_id),
        related_event_ids=[UUID(x) for x in json.loads(row.related_event_ids)],
        incident_chain_id=UUID(row.incident_chain_id) if row.incident_chain_id else None,
        title=row.title,
        description=row.description,
        mitre_techniques=json.loads(row.mitre_techniques),
        assigned_to=row.assigned_to,
        notes=notes or [],
        false_positive_count=row.false_positive_count,
    )


def _alert_to_row(alert: Alert) -> AlertRow:
    return AlertRow(
        alert_id=str(alert.alert_id),
        created_at=alert.created_at.isoformat(),
        updated_at=alert.updated_at.isoformat(),
        severity=alert.severity,
        status=alert.status,
        rule_id=alert.rule_id,
        ml_triggered=alert.ml_triggered,
        ti_triggered=alert.ti_triggered,
        entity_id=alert.entity_id,
        hostname=alert.hostname,
        trigger_event_id=str(alert.trigger_event_id),
        related_event_ids=json.dumps([str(x) for x in alert.related_event_ids]),
        incident_chain_id=str(alert.incident_chain_id) if alert.incident_chain_id else None,
        title=alert.title,
        description=alert.description,
        mitre_techniques=json.dumps(alert.mitre_techniques),
        assigned_to=alert.assigned_to,
        false_positive_count=alert.false_positive_count,
    )


def _note_to_row(note: AlertNote, alert_id: str) -> AlertNoteRow:
    return AlertNoteRow(
        note_id=str(note.note_id),
        alert_id=alert_id,
        created_at=note.created_at.isoformat(),
        updated_at=note.updated_at.isoformat() if note.updated_at else None,
        author=note.author,
        content=note.content,
    )


def _row_to_note(row: AlertNoteRow) -> AlertNote:
    from datetime import datetime

    return AlertNote(
        note_id=UUID(row.note_id),
        created_at=datetime.fromisoformat(row.created_at),
        updated_at=datetime.fromisoformat(row.updated_at) if row.updated_at else None,
        author=row.author,
        content=row.content,
    )


class SQLAlertRepository:
    """AlertRepository backed by SQLAlchemy async session."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, alert: Alert) -> Alert:
        async with self._session_factory() as session:
            async with session.begin():
                row = _alert_to_row(alert)
                session.add(row)
                for note in alert.notes:
                    session.add(_note_to_row(note, str(alert.alert_id)))
        return alert

    async def get(self, alert_id: UUID) -> Alert | None:
        async with self._session_factory() as session:
            row = await session.get(AlertRow, str(alert_id))
            if row is None:
                return None
            note_rows = (
                await session.execute(
                    select(AlertNoteRow).where(AlertNoteRow.alert_id == str(alert_id))
                )
            ).scalars().all()
            notes = [_row_to_note(n) for n in note_rows]
            return _row_to_alert(row, notes)

    async def update(self, alert: Alert) -> Alert:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(AlertRow, str(alert.alert_id))
                if row is None:
                    raise ValueError(f"Alert {alert.alert_id} not found")
                updated = _alert_to_row(alert)
                row.updated_at = updated.updated_at
                row.severity = updated.severity
                row.status = updated.status
                row.rule_id = updated.rule_id
                row.ml_triggered = updated.ml_triggered
                row.ti_triggered = updated.ti_triggered
                row.entity_id = updated.entity_id
                row.hostname = updated.hostname
                row.trigger_event_id = updated.trigger_event_id
                row.related_event_ids = updated.related_event_ids
                row.incident_chain_id = updated.incident_chain_id
                row.title = updated.title
                row.description = updated.description
                row.mitre_techniques = updated.mitre_techniques
                row.assigned_to = updated.assigned_to
                row.false_positive_count = updated.false_positive_count
        return alert

    async def list(self, filters: dict[str, object], pagination: Pagination) -> PageResult[Alert]:
        async with self._session_factory() as session:
            stmt = select(AlertRow)
            if filters.get("status"):
                stmt = stmt.where(AlertRow.status == filters["status"])
            if filters.get("severity"):
                stmt = stmt.where(AlertRow.severity == filters["severity"])
            if filters.get("hostname"):
                stmt = stmt.where(AlertRow.hostname == filters["hostname"])

            count_stmt = select(func.count()).select_from(stmt.subquery())
            total: int = (await session.execute(count_stmt)).scalar_one()

            rows = (
                await session.execute(
                    stmt.offset(pagination.offset).limit(pagination.limit)
                )
            ).scalars().all()
            items = [_row_to_alert(r) for r in rows]
            return PageResult(
                items=items, total=total, limit=pagination.limit, offset=pagination.offset
            )

    async def count(self, filters: dict[str, object]) -> int:
        async with self._session_factory() as session:
            stmt = select(func.count(AlertRow.alert_id))
            if filters.get("status"):
                stmt = stmt.where(AlertRow.status == filters["status"])
            if filters.get("severity"):
                stmt = stmt.where(AlertRow.severity == filters["severity"])
            return (await session.execute(stmt)).scalar_one()
