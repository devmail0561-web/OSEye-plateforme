"""Unit tests for OSEye REST API — uses SQLite :memory: and HS256 JWT."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.config import Settings
from oseye.storage.migrations import run_migrations
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.events import SQLEventRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEST_SECRET = "test-secret-hs256-not-for-production-x"
TEST_USER = "analyst"
TEST_PASSWORD = "analyst123"


@pytest_asyncio.fixture
async def app():  # type: ignore[no-untyped-def]
    """Build a FastAPI test application backed by SQLite :memory:."""
    settings = Settings(
        jwt_private_key_path="/dev/null",
        jwt_public_key_path="/dev/null",
        jwt_access_token_expire_minutes=15,
        api_cors_origins=["*"],
    )
    application = create_app(settings)

    # Override JWT handler with HS256 (no PEM files needed)
    application.state.jwt_handler = JWTHandler(
        private_key_path="",
        public_key_path="",
        expire_minutes=15,
        secret=TEST_SECRET,
    )

    # In-memory SQLite DB
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)
    session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )
    application.state.event_repo = SQLEventRepository(session_factory)
    application.state.alert_repo = SQLAlertRepository(session_factory)

    yield application

    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c


async def _get_token(client: AsyncClient, username: str = TEST_USER) -> str:
    """Helper: obtain an access token via POST /api/v1/auth/token."""
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": username, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    # API-11: public health endpoint no longer discloses service/version details
    assert "service" not in body
    assert "version" not in body


@pytest.mark.asyncio
async def test_login_returns_token(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": TEST_USER, "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 10


@pytest.mark.asyncio
async def test_events_requires_auth(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/events")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_events_list_empty(client: AsyncClient) -> None:
    token = await _get_token(client)
    resp = await client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0


@pytest.mark.asyncio
async def test_events_rate_limit_not_on_health(client: AsyncClient) -> None:
    """Health endpoint should not be rate-limited — hit it 10 times."""
    for _ in range(10):
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_alert_list_empty(client: AsyncClient) -> None:
    token = await _get_token(client)
    resp = await client.get(
        "/api/v1/alerts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0
