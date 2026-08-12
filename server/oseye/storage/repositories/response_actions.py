"""Repository for response actions (BLOCK_IP, QUARANTINE_FILE, KILL_PROCESS)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import ResponseActionRow


class SQLResponseActionsRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(
        self,
        command_id: str,
        decision_id: str,
        agent_cn: str,
        command_type: str,
        payload: str,
    ) -> ResponseActionRow:
        row = ResponseActionRow(
            command_id=command_id,
            decision_id=decision_id,
            agent_cn=agent_cn,
            command_type=command_type,
            payload=payload,
            status="pending_report",
            created_at=datetime.now(UTC),
        )
        async with self._session_factory() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
        return row

    async def get(self, command_id: str) -> ResponseActionRow | None:
        async with self._session_factory() as session:
            return await session.get(ResponseActionRow, command_id)

    async def list(
        self,
        agent_cn: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ResponseActionRow]:
        async with self._session_factory() as session:
            q = select(ResponseActionRow).order_by(
                ResponseActionRow.created_at.desc()
            ).limit(limit).offset(offset)
            if agent_cn:
                q = q.where(ResponseActionRow.agent_cn == agent_cn)
            if status:
                q = q.where(ResponseActionRow.status == status)
            result = await session.execute(q)
            return list(result.scalars().all())

    async def mark_executed(self, command_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(ResponseActionRow)
                .where(ResponseActionRow.command_id == command_id)
                .values(status="executed", executed_at=datetime.now(UTC))
            )
            await session.commit()

    async def mark_failed(self, command_id: str, error: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(ResponseActionRow)
                .where(ResponseActionRow.command_id == command_id)
                .values(status="failed", error=error)
            )
            await session.commit()

    async def mark_rolled_back(self, command_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(ResponseActionRow)
                .where(ResponseActionRow.command_id == command_id)
                .values(status="rolled_back", rolled_back_at=datetime.now(UTC))
            )
            await session.commit()
