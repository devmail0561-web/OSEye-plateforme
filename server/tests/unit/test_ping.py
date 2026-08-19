"""Tests for POST /api/v1/agents/{cn}/ping endpoint."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.bus.memory_bus import InMemoryEventBus
from oseye.config import Settings
from oseye.storage.migrations import run_migrations


@pytest_asyncio.fixture
async def app_with_bus():
    settings = Settings(
        jwt_private_key_path="/dev/null",
        jwt_public_key_path="/dev/null",
        jwt_access_token_expire_minutes=15,
        api_cors_origins=["*"],
    )
    application = create_app(settings)
    application.state.jwt_handler = JWTHandler(
        private_key_path="", public_key_path="", expire_minutes=15,
        secret="test-secret-hs256-for-pytest-32ch",
    )
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)

    bus = InMemoryEventBus()
    application.state.bus = bus

    blocked_repo = AsyncMock()
    blocked_repo.list_blocked = AsyncMock(return_value=[])
    blocked_repo.block = AsyncMock()
    blocked_repo.unblock = AsyncMock()
    application.state.blocked_agents_repo = blocked_repo

    agent_repo = AsyncMock()
    agent_repo.list = AsyncMock(return_value=[])
    agent_repo.get = AsyncMock(return_value=None)
    application.state.agent_repo = agent_repo

    servicer = MagicMock()
    servicer.block_agent = MagicMock()
    servicer.unblock_agent = MagicMock()
    servicer._pending_pings = {}
    servicer._pending_pings_lock = __import__("threading").Lock()

    def register_ping(command_id, event):
        with servicer._pending_pings_lock:
            servicer._pending_pings[command_id] = event

    def unregister_ping(command_id):
        with servicer._pending_pings_lock:
            servicer._pending_pings.pop(command_id, None)

    servicer.register_ping = register_ping
    servicer.unregister_ping = unregister_ping

    application.state.grpc_servicer = servicer

    yield application, bus, servicer
    await engine.dispose()
    await bus.close()


@pytest_asyncio.fixture
async def client_with_bus(app_with_bus):
    app, bus, servicer = app_with_bus
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c, bus, servicer


async def _analyst_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/v1/auth/token", data={"username": "analyst", "password": "analyst123"}
    )
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_ping_returns_timeout_when_no_agent_replies(
    client_with_bus,
) -> None:
    """Ping returns {status: timeout} when no agent replies within timeout."""
    client, bus, servicer = client_with_bus
    token = await _analyst_token(client)
    resp = await client.post(
        "/api/v1/agents/ghost-host/ping?timeout=0.5",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["cn"] == "ghost-host"
    assert data["status"] == "timeout"
    assert data["latency_ms"] is None


@pytest.mark.asyncio
async def test_ping_returns_ok_when_agent_replies(client_with_bus) -> None:
    """Ping returns {status: ok, latency_ms: N} when agent replies quickly."""
    client, bus, servicer = client_with_bus
    token = await _analyst_token(client)

    # Simulate agent: subscribe to commands and signal the ping event immediately.
    async def fake_agent() -> None:
        sub = await bus.subscribe("commands:fast-host")
        async for msg in sub:
            import json as _json
            cmd = _json.loads(msg)
            cmd_id = cmd.get("command_id")
            if cmd_id:
                with servicer._pending_pings_lock:
                    evt = servicer._pending_pings.get(cmd_id)
                if evt is not None:
                    evt.set()
            break

    agent_task = asyncio.create_task(fake_agent())

    resp = await client.post(
        "/api/v1/agents/fast-host/ping?timeout=2.0",
        headers={"Authorization": f"Bearer {token}"},
    )
    await agent_task

    assert resp.status_code == 200
    data = resp.json()
    assert data["cn"] == "fast-host"
    assert data["status"] == "ok"
    assert isinstance(data["latency_ms"], int)
    assert data["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_ping_requires_auth(client_with_bus) -> None:
    """Ping endpoint requires authentication."""
    client, _bus, _svc = client_with_bus
    resp = await client.post("/api/v1/agents/some-host/ping")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_ping_no_bus_returns_503(app_with_bus) -> None:
    """Ping returns 503 when bus is not initialised."""
    app, _bus, _svc = app_with_bus
    del app.state.bus

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        token_resp = await c.post(
            "/api/v1/auth/token", data={"username": "analyst", "password": "analyst123"}
        )
        token = token_resp.json()["access_token"]
        resp = await c.post(
            "/api/v1/agents/host/ping",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_ping_cleans_up_pending_entry_on_timeout(client_with_bus) -> None:
    """After a timeout, the pending ping entry is removed from the servicer."""
    client, _bus, servicer = client_with_bus
    token = await _analyst_token(client)

    await client.post(
        "/api/v1/agents/gone-host/ping?timeout=0.3",
        headers={"Authorization": f"Bearer {token}"},
    )
    # After the request completes, no pending ping should remain.
    with servicer._pending_pings_lock:
        assert len(servicer._pending_pings) == 0
