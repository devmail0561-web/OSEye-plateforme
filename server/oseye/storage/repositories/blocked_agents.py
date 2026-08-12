"""Repository for blocked (revoked) agent CNs."""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import BlockedAgentRow


class SQLBlockedAgentsRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def block(self, cn: str, reason: str | None = None) -> None:
        async with self._session_factory() as session:
            stmt = sqlite_insert(BlockedAgentRow).values(cn=cn, reason=reason)
            stmt = stmt.on_conflict_do_nothing(index_elements=["cn"])
            await session.execute(stmt)
            await session.commit()

    async def unblock(self, cn: str) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(BlockedAgentRow).where(BlockedAgentRow.cn == cn))
            await session.commit()

    async def is_blocked(self, cn: str) -> bool:
        async with self._session_factory() as session:
            row = await session.get(BlockedAgentRow, cn)
            return row is not None

    async def list_blocked(self) -> list[str]:
        async with self._session_factory() as session:
            result = await session.execute(select(BlockedAgentRow.cn))
            return list(result.scalars().all())
