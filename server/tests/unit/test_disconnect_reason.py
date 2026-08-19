"""Tests for agent disconnect_reason field (P1 fix)."""

from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")

import pytest

from oseye.storage.models import AgentRow
from oseye.storage.repositories.agents import SQLAgentRepository


# ---------------------------------------------------------------------------
# Schema / model tests
# ---------------------------------------------------------------------------


def test_agent_row_has_disconnect_reason_column() -> None:
    """AgentRow ORM model has a disconnect_reason column."""
    assert hasattr(AgentRow, "disconnect_reason")


def test_agent_row_disconnect_reason_nullable() -> None:
    """disconnect_reason column is nullable (no default required)."""
    col = AgentRow.__table__.c["disconnect_reason"]
    assert col.nullable is True


# ---------------------------------------------------------------------------
# Repository tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_offline_with_reason() -> None:
    """set_offline persists disconnect_reason when provided."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from oseye.storage.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    repo = SQLAgentRepository(factory)

    from datetime import UTC, datetime

    async with factory() as session:
        async with session.begin():
            session.add(
                AgentRow(
                    cn="test-host",
                    first_seen=datetime.now(UTC),
                    last_seen=datetime.now(UTC),
                    online=True,
                )
            )

    await repo.set_offline("test-host", reason="CANCELLED")

    row = await repo.get("test-host")
    assert row is not None
    assert row.online is False
    assert row.disconnect_reason == "CANCELLED"

    await engine.dispose()


@pytest.mark.asyncio
async def test_set_offline_without_reason_leaves_reason_none() -> None:
    """set_offline without reason leaves disconnect_reason as None."""
    from datetime import UTC, datetime

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from oseye.storage.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    repo = SQLAgentRepository(factory)

    async with factory() as session:
        async with session.begin():
            session.add(
                AgentRow(
                    cn="test-host2",
                    first_seen=datetime.now(UTC),
                    last_seen=datetime.now(UTC),
                    online=True,
                )
            )

    await repo.set_offline("test-host2")

    row = await repo.get("test-host2")
    assert row is not None
    assert row.online is False
    assert row.disconnect_reason is None

    await engine.dispose()


# ---------------------------------------------------------------------------
# Router dict test
# ---------------------------------------------------------------------------


def test_row_to_dict_exposes_disconnect_reason() -> None:
    """_row_to_dict includes disconnect_reason in the returned dict."""
    from oseye.api.routers.agents import _row_to_dict
    from datetime import UTC, datetime

    row = AgentRow(
        cn="host-x",
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        online=False,
        disconnect_reason="UNAVAILABLE",
    )
    result = _row_to_dict(row)
    assert result["disconnect_reason"] == "UNAVAILABLE"


def test_row_to_dict_disconnect_reason_none_when_absent() -> None:
    """_row_to_dict returns None for disconnect_reason when not set."""
    from oseye.api.routers.agents import _row_to_dict
    from datetime import UTC, datetime

    row = AgentRow(
        cn="host-y",
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        online=True,
    )
    result = _row_to_dict(row)
    assert result["disconnect_reason"] is None


# ---------------------------------------------------------------------------
# Bus publish test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_agent_disconnected_sends_to_bus() -> None:
    """_publish_agent_disconnected publishes a JSON message on agent:disconnected."""
    from unittest.mock import AsyncMock, MagicMock

    from oseye.bus.memory_bus import InMemoryEventBus
    from oseye.ingest.grpc_service import AgentServiceServicer
    from oseye.ingest.validator import BatchValidator

    bus = InMemoryEventBus()
    loop = asyncio.get_event_loop()

    servicer = AgentServiceServicer(
        bus=bus,
        validator=BatchValidator(),
        loop=loop,
    )

    sub = await bus.subscribe("agent:disconnected")
    collected: list[dict] = []

    async def _reader() -> None:
        async for msg in sub:
            collected.append(json.loads(msg))
            break

    reader_task = asyncio.create_task(_reader())
    servicer._publish_agent_disconnected("test-agent", "CANCELLED")
    await asyncio.sleep(0.05)
    await asyncio.wait_for(reader_task, timeout=1.0)

    assert len(collected) == 1
    assert collected[0]["agent_cn"] == "test-agent"
    assert collected[0]["reason"] == "CANCELLED"
