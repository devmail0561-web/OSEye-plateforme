"""Repository for tracked agents (last_seen, online status, active profile)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import AgentRow


class SQLAgentRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def upsert(
        self,
        cn: str,
        online: bool,
        ip_address: str | None = None,
        version: str | None = None,
        active_profile: str = "workstation",
    ) -> None:
        """Insert or update an agent record."""
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            row = await session.get(AgentRow, cn)
            if row is None:
                row = AgentRow(
                    cn=cn,
                    first_seen=now,
                    last_seen=now,
                    version=version,
                    active_profile=active_profile,
                    ip_address=ip_address,
                    online=online,
                )
                session.add(row)
            else:
                row.last_seen = now
                row.online = online
                if ip_address is not None:
                    row.ip_address = ip_address
                if version is not None:
                    row.version = version
                if active_profile:
                    row.active_profile = active_profile
            await session.commit()

    async def set_offline(self, cn: str) -> None:
        """Mark an agent as offline."""
        async with self._session_factory() as session:
            row = await session.get(AgentRow, cn)
            if row is not None:
                row.online = False
                await session.commit()

    async def list(self) -> list[AgentRow]:
        """Return all known agents ordered by last_seen desc."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(AgentRow).order_by(AgentRow.last_seen.desc())
            )
            return list(result.scalars().all())

    async def get(self, cn: str) -> AgentRow | None:
        async with self._session_factory() as session:
            return await session.get(AgentRow, cn)
