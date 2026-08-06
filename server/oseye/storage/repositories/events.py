"""SQL implementation of EventRepository."""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.core.schema import UniversalEvent
from oseye.storage.interface import EventFilter, Pagination
from oseye.storage.models import EventRow


@dataclass
class PageResult[T]:
    items: list[T]
    total: int
    limit: int
    offset: int


def _row_to_event(row: EventRow) -> UniversalEvent:
    return UniversalEvent(
        event_id=UUID(row.event_id),
        timestamp_ns=row.timestamp_ns,
        hostname=row.hostname,
        agent_id=UUID(row.agent_id),
        category=row.category,  # type: ignore[arg-type]
        type=row.type,
        severity=row.severity,  # type: ignore[arg-type]
        collector=row.collector,
        os=row.os,  # type: ignore[arg-type]
        uid=row.uid,
        gid=row.gid,
        pid=row.pid,
        ppid=row.ppid,
        process_name=row.process_name,
        executable=row.executable,
        cmdline=row.cmdline,
        cwd=row.cwd,
        session_id=row.session_id,
        resource=row.resource,
        result=row.result,
        file_hash_before=row.file_hash_before,
        file_hash_after=row.file_hash_after,
        src_ip=row.src_ip,
        src_port=row.src_port,
        dst_ip=row.dst_ip,
        dst_port=row.dst_port,
        protocol=row.protocol,
        bytes_sent=row.bytes_sent,
        bytes_recv=row.bytes_recv,
        hash_chain=row.hash_chain,
        signature=row.signature,
        ml_score=row.ml_score,
        risk_score=row.risk_score,
        rule_match_ids=json.loads(row.rule_match_ids),
        mitre_techniques=json.loads(row.mitre_techniques),
        ti_tags=json.loads(row.ti_tags),
        incident_chain_id=UUID(row.incident_chain_id) if row.incident_chain_id else None,
        extra=json.loads(row.extra),
    )


def _event_to_row(event: UniversalEvent) -> EventRow:
    return EventRow(
        event_id=str(event.event_id),
        timestamp_ns=event.timestamp_ns,
        hostname=event.hostname,
        agent_id=str(event.agent_id),
        category=event.category,
        type=event.type,
        severity=event.severity,
        collector=event.collector,
        os=event.os,
        uid=event.uid,
        gid=event.gid,
        pid=event.pid,
        ppid=event.ppid,
        process_name=event.process_name,
        executable=event.executable,
        cmdline=event.cmdline,
        cwd=event.cwd,
        session_id=event.session_id,
        resource=event.resource,
        result=event.result,
        file_hash_before=event.file_hash_before,
        file_hash_after=event.file_hash_after,
        src_ip=event.src_ip,
        src_port=event.src_port,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        protocol=event.protocol,
        bytes_sent=event.bytes_sent,
        bytes_recv=event.bytes_recv,
        hash_chain=event.hash_chain,
        signature=event.signature,
        ml_score=event.ml_score,
        risk_score=event.risk_score,
        rule_match_ids=json.dumps(event.rule_match_ids),
        mitre_techniques=json.dumps(event.mitre_techniques),
        ti_tags=json.dumps(event.ti_tags),
        incident_chain_id=str(event.incident_chain_id) if event.incident_chain_id else None,
        extra=json.dumps(event.extra),
    )


def _apply_filters(stmt: Select[tuple[EventRow]], filters: EventFilter) -> Select[tuple[EventRow]]:
    """Apply EventFilter predicates to a SQLAlchemy select statement."""
    from sqlalchemy import and_

    conditions = []
    if filters.hostname is not None:
        conditions.append(EventRow.hostname == filters.hostname)
    if filters.category is not None:
        conditions.append(EventRow.category == filters.category)
    if filters.type is not None:
        conditions.append(EventRow.type == filters.type)
    if filters.severity is not None:
        conditions.append(EventRow.severity == filters.severity)
    if filters.uid is not None:
        conditions.append(EventRow.uid == filters.uid)
    if filters.pid is not None:
        conditions.append(EventRow.pid == filters.pid)
    if filters.process_name is not None:
        conditions.append(EventRow.process_name == filters.process_name)
    if filters.resource is not None:
        conditions.append(EventRow.resource == filters.resource)
    if filters.agent_id is not None:
        conditions.append(EventRow.agent_id == str(filters.agent_id))
    if filters.incident_chain_id is not None:
        conditions.append(EventRow.incident_chain_id == str(filters.incident_chain_id))
    if filters.from_ts is not None:
        conditions.append(EventRow.timestamp_ns >= filters.from_ts)
    if filters.to_ts is not None:
        conditions.append(EventRow.timestamp_ns <= filters.to_ts)
    # rule_id and mitre_technique require JSON search — skip for SQLite compat
    if conditions:
        return stmt.where(and_(*conditions))
    return stmt


class SQLEventRepository:
    """EventRepository backed by SQLAlchemy async session."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def insert_batch(self, events: list[UniversalEvent]) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                for event in events:
                    row = _event_to_row(event)
                    session.add(row)

    async def get(self, event_id: UUID) -> UniversalEvent | None:
        async with self._session_factory() as session:
            result = await session.get(EventRow, str(event_id))
            if result is None:
                return None
            return _row_to_event(result)

    async def query(
        self, filters: EventFilter, pagination: Pagination
    ) -> PageResult[UniversalEvent]:
        async with self._session_factory() as session:
            base_stmt = select(EventRow)
            base_stmt = _apply_filters(base_stmt, filters)
            count_stmt = select(func.count()).select_from(base_stmt.subquery())
            total: int = (await session.execute(count_stmt)).scalar_one()

            data_stmt = (
                _apply_filters(select(EventRow), filters)
                .offset(pagination.offset)
                .limit(pagination.limit)
                .order_by(EventRow.timestamp_ns.desc())
            )
            rows = (await session.execute(data_stmt)).scalars().all()
            items = [_row_to_event(r) for r in rows]
            return PageResult(
                items=items,
                total=total,
                limit=pagination.limit,
                offset=pagination.offset,
            )

    async def count(self, filters: EventFilter) -> int:
        async with self._session_factory() as session:
            stmt = select(func.count()).select_from(
                _apply_filters(select(EventRow), filters).subquery()
            )
            return (await session.execute(stmt)).scalar_one()
