"""Unit tests for the storage backend factory."""

from __future__ import annotations

import pytest

from oseye.config import Settings
from oseye.storage.backends.factory import _PostgreSQLBackend, create_backend
from oseye.storage.backends.sqlite import SQLiteBackend


def _settings(**kwargs) -> Settings:
    base = {
        "db_url": "sqlite+aiosqlite:///:memory:",
        "db_backend": "sqlite",
    }
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def test_create_backend_sqlite_explicit() -> None:
    settings = _settings(db_backend="sqlite")
    backend = create_backend(settings)
    assert isinstance(backend, SQLiteBackend)


def test_create_backend_sqlite_default() -> None:
    settings = _settings()  # db_backend defaults to "sqlite"
    backend = create_backend(settings)
    assert isinstance(backend, SQLiteBackend)


def test_create_backend_postgresql() -> None:
    settings = _settings(
        db_backend="postgresql",
        db_url="postgresql+asyncpg://oseye:pw@localhost:5432/oseye",
    )
    backend = create_backend(settings)
    assert isinstance(backend, _PostgreSQLBackend)
    assert backend.session_factory is not None
