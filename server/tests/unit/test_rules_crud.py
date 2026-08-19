"""Tests for admin-managed rules CRUD endpoints."""

from __future__ import annotations

import os

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.config import Settings
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.migrations import run_migrations
from oseye.storage.repositories.rules import SQLRuleRepository

TEST_SECRET = "test-secret-hs256-for-pytest-32ch"


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
    application.state.rule_repo = SQLRuleRepository(sf)
    yield application
    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


async def _admin_token(client: AsyncClient) -> str:
    resp = await client.post("/api/v1/auth/token", data={"username": "admin", "password": "admin123"})
    return resp.json()["access_token"]


async def _analyst_token(client: AsyncClient) -> str:
    resp = await client.post("/api/v1/auth/token", data={"username": "analyst", "password": "analyst123"})
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_create_rule_returns_201(client: AsyncClient) -> None:
    """POST /rules creates a rule and returns 201 with the rule data."""
    token = await _admin_token(client)
    resp = await client.post(
        "/api/v1/rules",
        json={"name": "Test Rule", "rule_type": "anomaly", "severity": "high"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Rule"
    assert data["rule_type"] == "anomaly"
    assert data["severity"] == "high"
    assert data["version"] == 1
    assert "rule_id" in data


@pytest.mark.asyncio
async def test_get_db_rule_returns_created(client: AsyncClient) -> None:
    """GET /rules/db/{id} returns the previously created rule."""
    token = await _admin_token(client)
    create_resp = await client.post(
        "/api/v1/rules",
        json={"name": "Get Test Rule", "rule_type": "surveillance"},
        headers={"Authorization": f"Bearer {token}"},
    )
    rule_id = create_resp.json()["rule_id"]

    get_resp = await client.get(
        f"/api/v1/rules/db/{rule_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["rule_id"] == rule_id
    assert get_resp.json()["name"] == "Get Test Rule"


@pytest.mark.asyncio
async def test_update_rule_increments_version(client: AsyncClient) -> None:
    """PUT /rules/db/{id} updates the rule and increments its version."""
    token = await _admin_token(client)
    create_resp = await client.post(
        "/api/v1/rules",
        json={"name": "Original Name", "severity": "low"},
        headers={"Authorization": f"Bearer {token}"},
    )
    rule_id = create_resp.json()["rule_id"]
    assert create_resp.json()["version"] == 1

    update_resp = await client.put(
        f"/api/v1/rules/db/{rule_id}",
        json={"name": "Updated Name"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert update_resp.status_code == 200
    data = update_resp.json()
    assert data["name"] == "Updated Name"
    assert data["version"] == 2


@pytest.mark.asyncio
async def test_delete_rule_admin_only(client: AsyncClient) -> None:
    """DELETE /rules/db/{id} deletes the rule (admin only)."""
    token = await _admin_token(client)
    create_resp = await client.post(
        "/api/v1/rules",
        json={"name": "To Delete"},
        headers={"Authorization": f"Bearer {token}"},
    )
    rule_id = create_resp.json()["rule_id"]

    del_resp = await client.delete(
        f"/api/v1/rules/db/{rule_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_resp.status_code == 204

    get_resp = await client.get(
        f"/api/v1/rules/db/{rule_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_analyst_cannot_create_rule(client: AsyncClient) -> None:
    """Analyst role cannot create rules (admin only)."""
    token = await _analyst_token(client)
    resp = await client.post(
        "/api/v1/rules",
        json={"name": "Forbidden Rule"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_rule_invalid_severity_returns_422(client: AsyncClient) -> None:
    """POST /rules with invalid severity returns 422."""
    token = await _admin_token(client)
    resp = await client.post(
        "/api/v1/rules",
        json={"name": "Bad Rule", "severity": "extreme"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_db_rules_returns_created(client: AsyncClient) -> None:
    """GET /rules/db lists all admin-managed rules."""
    token = await _admin_token(client)
    await client.post(
        "/api/v1/rules",
        json={"name": "List Rule 1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await client.post(
        "/api/v1/rules",
        json={"name": "List Rule 2"},
        headers={"Authorization": f"Bearer {token}"},
    )

    resp = await client.get(
        "/api/v1/rules/db",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2
    names = [r["name"] for r in data["items"]]
    assert "List Rule 1" in names
    assert "List Rule 2" in names
