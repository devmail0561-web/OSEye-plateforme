"""Agent snapshot storage and diff utilities."""

from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.core.schema import AgentSnapshot, ConnectionInfo, ProcessInfo
from oseye.storage.models import SnapshotRow


def diff_snapshots(
    before: AgentSnapshot, after: AgentSnapshot
) -> dict[str, list[dict]]:
    """Return processes/connections added or removed between two snapshots."""
    before_pids = {p.pid: p for p in before.processes}
    after_pids = {p.pid: p for p in after.processes}

    new_processes = [p.model_dump() for pid, p in after_pids.items() if pid not in before_pids]
    terminated_processes = [
        p.model_dump() for pid, p in before_pids.items() if pid not in after_pids
    ]

    def _conn_key(c: ConnectionInfo) -> tuple[str, int, str, int]:
        return (c.proto, c.local_port, c.remote_addr, c.remote_port)

    before_conns = {_conn_key(c): c for c in before.connections}
    after_conns = {_conn_key(c): c for c in after.connections}

    new_connections = [c.model_dump() for k, c in after_conns.items() if k not in before_conns]
    closed_connections = [
        c.model_dump() for k, c in before_conns.items() if k not in after_conns
    ]

    return {
        "new_processes": new_processes,
        "terminated_processes": terminated_processes,
        "new_connections": new_connections,
        "closed_connections": closed_connections,
    }


def _row_to_snapshot(row: SnapshotRow) -> AgentSnapshot:
    import logging as _logging
    _log = _logging.getLogger(__name__)
    try:
        processes_raw = json.loads(row.processes or "[]")
    except (json.JSONDecodeError, TypeError):
        _log.warning("snapshot_corrupt_processes id=%s", str(getattr(row, 'id', '?')))
        processes_raw = []
    try:
        connections_raw = json.loads(row.connections or "[]")
    except (json.JSONDecodeError, TypeError):
        _log.warning("snapshot_corrupt_connections id=%s", str(getattr(row, 'id', '?')))
        connections_raw = []
    return AgentSnapshot(
        snapshot_id=UUID(row.snapshot_id),
        agent_id=UUID(row.agent_id),
        hostname=row.hostname,
        taken_at=datetime.fromisoformat(row.taken_at),
        processes=[ProcessInfo.model_validate(p) for p in processes_raw],
        connections=[ConnectionInfo.model_validate(c) for c in connections_raw],
        case_id=UUID(row.case_id) if row.case_id else None,
    )


def _snapshot_to_row(snap: AgentSnapshot) -> SnapshotRow:
    return SnapshotRow(
        snapshot_id=str(snap.snapshot_id),
        agent_id=str(snap.agent_id),
        hostname=snap.hostname,
        taken_at=snap.taken_at.isoformat(),
        processes=json.dumps([p.model_dump() for p in snap.processes]),
        connections=json.dumps([c.model_dump() for c in snap.connections]),
        case_id=str(snap.case_id) if snap.case_id else None,
    )


class SQLSnapshotRepository:
    """Snapshot repository backed by SQLAlchemy async session."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, snap: AgentSnapshot) -> AgentSnapshot:
        async with self._session_factory() as session:
            async with session.begin():
                session.add(_snapshot_to_row(snap))
        return snap

    async def get(self, snapshot_id: UUID) -> AgentSnapshot | None:
        async with self._session_factory() as session:
            row = await session.get(SnapshotRow, str(snapshot_id))
            return _row_to_snapshot(row) if row is not None else None

    async def list_by_agent(self, agent_id: UUID, limit: int = 50) -> list[AgentSnapshot]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(SnapshotRow)
                    .where(SnapshotRow.agent_id == str(agent_id))
                    .order_by(SnapshotRow.taken_at.desc())
                    .limit(limit)
                )
            ).scalars().all()
        return [_row_to_snapshot(r) for r in rows]

    async def list_by_case(self, case_id: UUID) -> list[AgentSnapshot]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(SnapshotRow)
                    .where(SnapshotRow.case_id == str(case_id))
                    .order_by(SnapshotRow.taken_at.asc())
                )
            ).scalars().all()
        return [_row_to_snapshot(r) for r in rows]
