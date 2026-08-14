"""Tests for the /api/v1/agents router."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.config import Settings
from oseye.storage.migrations import run_migrations

TEST_SECRET = "test-secret-hs256-for-pytest-32ch"


@pytest_asyncio.fixture
async def app():  # type: ignore[no-untyped-def]
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

    # Mock repos
    blocked_repo = AsyncMock()
    blocked_repo.list_blocked = AsyncMock(return_value=["host-compromised"])
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
    application.state.grpc_servicer = servicer

    yield application
    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


async def _admin_token(client: AsyncClient) -> str:
    resp = await client.post("/api/v1/auth/token", data={"username": "admin", "password": "admin123"})
    return resp.json()["access_token"]


async def _analyst_token(client: AsyncClient) -> str:
    resp = await client.post("/api/v1/auth/token", data={"username": "analyst", "password": "analyst123"})
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_list_agents_analyst(client: AsyncClient) -> None:
    token = await _analyst_token(client)
    resp = await client.get("/api/v1/agents", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_blocked_admin_only(client: AsyncClient) -> None:
    token = await _admin_token(client)
    resp = await client.get("/api/v1/agents/blocked", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "host-compromised" in resp.json()


@pytest.mark.asyncio
async def test_list_blocked_analyst_forbidden(client: AsyncClient) -> None:
    token = await _analyst_token(client)
    resp = await client.get("/api/v1/agents/blocked", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_block_agent(client: AsyncClient, app) -> None:  # type: ignore[no-untyped-def]
    token = await _admin_token(client)
    resp = await client.delete("/api/v1/agents/bad-host", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 204
    app.state.grpc_servicer.block_agent.assert_called_once_with("bad-host")
    app.state.blocked_agents_repo.block.assert_called_once_with("bad-host")


@pytest.mark.asyncio
async def test_unblock_agent(client: AsyncClient, app) -> None:  # type: ignore[no-untyped-def]
    token = await _admin_token(client)
    resp = await client.post("/api/v1/agents/bad-host/unblock", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 204
    app.state.grpc_servicer.unblock_agent.assert_called_once_with("bad-host")
