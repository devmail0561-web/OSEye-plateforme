"""SQLite async backend for development use.

Uses aiosqlite via SQLAlchemy's async interface.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from oseye.storage.migrations import run_migrations


class SQLiteBackend:
    """Async SQLite backend. Creates tables on init via run_migrations."""

    def __init__(self, db_url: str) -> None:
        self._engine: AsyncEngine = create_async_engine(
            db_url,
            echo=False,
            future=True,
        )
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self._engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    async def init(self) -> None:
        """Create all tables (and triggers if applicable)."""
        await run_migrations(self._engine)

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory
