"""Tests for GET /api/v1/agents/{cn}/collectors endpoint (P3)."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-hs256-for-pytest-32ch")

from oseye.api.app import create_app  # noqa: E402
from oseye.api.auth.jwt import JWTHandler  # noqa: E402
from oseye.config import Settings  # noqa: E402
from oseye.storage.migrations import run_migrations  # noqa: E402

TEST_SECRET = "test-secret-hs256-for-pytest-32ch"


def _make_servicer(healths: dict | None = None):
    servicer = MagicMock()
    servicer.block_agent = MagicMock()
    servicer.unblock_agent = MagicMock()
    _store = healths or {}

    def _get(cn: str):
        return list(_store.get(cn, []))

    servicer.get_collector_healths = MagicMock(side_effect=_get)
    return servicer


@pytest_asyncio.fixture
async def app():
    settings = Settings(
        jwt_private_key_path="/dev/null",
        jwt_public_key_path="/dev/null",
        jwt_access_token_expire_minutes=15,
        api_cors_origins=["*"],
    )
    application = create_app(settings)
    application.state.jwt_handler = JWTHandler(
        private_key_path="", public_key_path="", expire_minutes=15, secret=TEST_SECRET
    )
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)
    sf: async_sessionmaker[AsyncSession] = async_sessionmaker(
        bind=engine, expire_on_commit=False, class_=AsyncSession
    )

    blocked_repo = AsyncMock()
    blocked_repo.list_blocked = AsyncMock(return_value=[])
    blocked_repo.block = AsyncMock()
    blocked_repo.unblock = AsyncMock()
    application.state.blocked_agents_repo = blocked_repo

    agent_repo = AsyncMock()
    agent_repo.list = AsyncMock(return_value=[])
    agent_repo.get = AsyncMock(return_value=None)
    application.state.agent_repo = agent_repo

    application.state.grpc_servicer = _make_servicer()
    yield application
    await engine.dispose()


@pytest_asyncio.fixture
async def app_with_healths():
    settings = Settings(
        jwt_private_key_path="/dev/null",
        jwt_public_key_path="/dev/null",
        jwt_access_token_expire_minutes=15,
        api_cors_origins=["*"],
    )
    application = create_app(settings)
    application.state.jwt_handler = JWTHandler(
        private_key_path="", public_key_path="", expire_minutes=15, secret=TEST_SECRET
    )
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)

    blocked_repo = AsyncMock()
    blocked_repo.list_blocked = AsyncMock(return_value=[])
    application.state.blocked_agents_repo = blocked_repo

    agent_repo = AsyncMock()
    agent_repo.list = AsyncMock(return_value=[])
    agent_repo.get = AsyncMock(return_value=None)
    application.state.agent_repo = agent_repo

    healths = {
        "host-01": [
            {"name": "ebpf", "running": True, "error_count": 0, "events_total": 42, "throttle_pct": 0.0, "last_error": ""},
            {"name": "netlink", "running": True, "error_count": 1, "events_total": 10, "throttle_pct": 0.0, "last_error": "timeout"},
        ]
    }
    application.state.grpc_servicer = _make_servicer(healths)
    yield application
    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


@pytest_asyncio.fixture
async def client_with_healths(app_with_healths):
    async with AsyncClient(transport=ASGITransport(app=app_with_healths), base_url="http://testserver") as c:
        yield c


async def _analyst_token(c: AsyncClient) -> str:
    resp = await c.post("/api/v1/auth/token", data={"username": "analyst", "password": "analyst123"})
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_collectors_endpoint_returns_200_empty(client: AsyncClient) -> None:
    """GET /agents/{cn}/collectors returns 200 with empty list when no health data."""
    token = await _analyst_token(client)
    resp = await client.get(
        "/api/v1/agents/host-unknown/collectors",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["cn"] == "host-unknown"
    assert body["collectors"] == []


@pytest.mark.asyncio
async def test_collectors_endpoint_returns_health_data(client_with_healths: AsyncClient) -> None:
    """GET /agents/{cn}/collectors returns collector health when data is available."""
    token = await _analyst_token(client_with_healths)
    resp = await client_with_healths.get(
        "/api/v1/agents/host-01/collectors",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["cn"] == "host-01"
    assert len(body["collectors"]) == 2
    names = {c["name"] for c in body["collectors"]}
    assert "ebpf" in names
    assert "netlink" in names


@pytest.mark.asyncio
async def test_collectors_endpoint_requires_auth(client: AsyncClient) -> None:
    """GET /agents/{cn}/collectors requires authentication."""
    resp = await client.get("/api/v1/agents/host-01/collectors")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_collectors_endpoint_ebpf_health_fields(client_with_healths: AsyncClient) -> None:
    """Collector health entry for ebpf has all expected fields."""
    token = await _analyst_token(client_with_healths)
    resp = await client_with_healths.get(
        "/api/v1/agents/host-01/collectors",
        headers={"Authorization": f"Bearer {token}"},
    )
    body = resp.json()
    ebpf = next(c for c in body["collectors"] if c["name"] == "ebpf")
    assert ebpf["running"] is True
    assert ebpf["error_count"] == 0
    assert ebpf["events_total"] == 42


@pytest.mark.asyncio
async def test_collectors_endpoint_no_servicer(app) -> None:
    """GET /agents/{cn}/collectors returns empty list when servicer is missing."""
    app.state.grpc_servicer = None
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        token = await _analyst_token(c)
        resp = await c.get(
            "/api/v1/agents/host-01/collectors",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert resp.json()["collectors"] == []
