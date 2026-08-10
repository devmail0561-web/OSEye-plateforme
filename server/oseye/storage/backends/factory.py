"""Backend factory — returns SQLite or PostgreSQL backend based on settings."""

from __future__ import annotations

from oseye.config import Settings
from oseye.storage.backends.sqlite import SQLiteBackend


class _PostgreSQLBackend:
    """Async PostgreSQL backend for production use."""

    def __init__(self, settings: Settings) -> None:
        from sqlalchemy.ext.asyncio import (
            AsyncEngine,
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        self._engine: AsyncEngine = create_async_engine(
            settings.db_url,
            echo=False,
            future=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
        )
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self._engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    async def init(self) -> None:
        from oseye.storage.migrations import run_migrations
        await run_migrations(self._engine)

    @property
    def session_factory(self):  # type: ignore[return]
        return self._session_factory

    async def close(self) -> None:
        await self._engine.dispose()


def create_backend(settings: Settings) -> SQLiteBackend | _PostgreSQLBackend:
    """Return the appropriate storage backend for the configured db_backend."""
    if settings.db_backend == "postgresql":
        return _PostgreSQLBackend(settings)
    return SQLiteBackend(settings.db_url)
