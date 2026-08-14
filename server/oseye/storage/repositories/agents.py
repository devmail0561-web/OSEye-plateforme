"""Repository for tracked agents (last_seen, online status, active profile)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
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
        """Insert or update an agent record using a dialect-agnostic select+update/insert.

        Replaces the previous SQLite-specific INSERT OR REPLACE so that this
        repository works with both SQLite (development) and PostgreSQL (production).
        """
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            existing = (
                await session.execute(select(AgentRow).where(AgentRow.cn == cn))
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    AgentRow(
                        cn=cn,
                        first_seen=now,
                        last_seen=now,
                        version=version,
                        active_profile=active_profile,
                        ip_address=ip_address,
                        online=online,
                    )
                )
            else:
                existing.last_seen = now
                existing.online = online
                if ip_address is not None:
                    existing.ip_address = ip_address
                if version is not None:
                    existing.version = version
                if active_profile:
                    existing.active_profile = active_profile
            await session.flush()
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

    async def update_last_seen(self, cn: str) -> None:
        """Update the last_seen timestamp for an agent without touching other fields."""
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            await session.execute(
                update(AgentRow).where(AgentRow.cn == cn).values(last_seen=now)
            )
            await session.commit()

    async def reset_all_offline(self) -> None:
        """Mark every agent offline — call once at server startup to clear stale online flags."""
        async with self._session_factory() as session:
            await session.execute(update(AgentRow).values(online=False))
            await session.commit()
