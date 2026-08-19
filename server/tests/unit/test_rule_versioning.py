"""Tests for rule versioning (P9) — change log and profile linking."""

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
from oseye.core.schema import SurveillanceProfile
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
    resp = await client.post(
        "/api/v1/auth/token", data={"username": "admin", "password": "admin123"}
    )
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# SurveillanceProfile unit tests
# ---------------------------------------------------------------------------


def test_surveillance_profile_has_rule_ids_field() -> None:
    """SurveillanceProfile accepts and stores rule_ids."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    p = SurveillanceProfile(
        name="test",
        created_at=now,
        updated_at=now,
        rule_ids=["rule-001", "rule-002"],
    )
    assert "rule-001" in p.rule_ids
    assert "rule-002" in p.rule_ids


def test_surveillance_profile_rule_ids_default_empty() -> None:
    """SurveillanceProfile.rule_ids defaults to empty list."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    p = SurveillanceProfile(name="test", created_at=now, updated_at=now)
    assert p.rule_ids == []


# ---------------------------------------------------------------------------
# Change log integration tests (via API)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_writes_change_log_entry(client: AsyncClient) -> None:
    """Creating a rule writes a 'created' entry in the change log."""
    token = await _admin_token(client)
    resp = await client.post(
        "/api/v1/rules",
        json={"name": "Versioned Rule", "rule_type": "anomaly", "author": "tester"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    rule_id = resp.json()["rule_id"]

    hist = await client.get(
        f"/api/v1/rules/db/{rule_id}/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hist.status_code == 200
    data = hist.json()
    assert data["total"] == 1
    assert data["items"][0]["change_type"] == "created"
    assert data["items"][0]["version"] == 1


@pytest.mark.asyncio
async def test_update_writes_change_log_entry(client: AsyncClient) -> None:
    """Updating a rule writes an 'updated' entry and shows version bump."""
    token = await _admin_token(client)
    create_resp = await client.post(
        "/api/v1/rules",
        json={"name": "To Update"},
        headers={"Authorization": f"Bearer {token}"},
    )
    rule_id = create_resp.json()["rule_id"]

    await client.put(
        f"/api/v1/rules/db/{rule_id}",
        json={"name": "Updated Name"},
        headers={"Authorization": f"Bearer {token}"},
    )

    hist = await client.get(
        f"/api/v1/rules/db/{rule_id}/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    items = hist.json()["items"]
    assert len(items) == 2
    change_types = {e["change_type"] for e in items}
    assert "created" in change_types
    assert "updated" in change_types
    updated_entry = next(e for e in items if e["change_type"] == "updated")
    assert updated_entry["version"] == 2


@pytest.mark.asyncio
async def test_delete_writes_change_log_entry(client: AsyncClient) -> None:
    """Deleting a rule writes a 'deleted' entry in the change log."""
    token = await _admin_token(client)
    create_resp = await client.post(
        "/api/v1/rules",
        json={"name": "To Delete"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_resp.status_code == 201
    rule_id = create_resp.json()["rule_id"]

    del_resp = await client.delete(
        f"/api/v1/rules/db/{rule_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_resp.status_code == 204

    # History endpoint must still return entries for deleted rules
    hist = await client.get(
        f"/api/v1/rules/db/{rule_id}/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hist.status_code == 200
    data = hist.json()
    change_types = [e["change_type"] for e in data["items"]]
    assert "deleted" in change_types
    deleted_entry = next(e for e in data["items"] if e["change_type"] == "deleted")
    assert deleted_entry["rule_id"] == rule_id


@pytest.mark.asyncio
async def test_history_endpoint_rule_not_found(client: AsyncClient) -> None:
    """GET /rules/db/{id}/history returns 404 for unknown rule."""
    token = await _admin_token(client)
    resp = await client.get(
        "/api/v1/rules/db/nonexistent-id/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_assign_profile_updates_rule(client: AsyncClient) -> None:
    """POST /rules/db/{id}/assign-profile updates profile_id on the rule."""
    token = await _admin_token(client)
    create_resp = await client.post(
        "/api/v1/rules",
        json={"name": "Profile Rule"},
        headers={"Authorization": f"Bearer {token}"},
    )
    rule_id = create_resp.json()["rule_id"]

    assign_resp = await client.post(
        f"/api/v1/rules/db/{rule_id}/assign-profile",
        json={"profile_id": "webserver"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert assign_resp.status_code == 200
    assert assign_resp.json()["profile_id"] == "webserver"


@pytest.mark.asyncio
async def test_assign_profile_rule_not_found(client: AsyncClient) -> None:
    """POST assign-profile on unknown rule returns 404."""
    token = await _admin_token(client)
    resp = await client.post(
        "/api/v1/rules/db/no-such-rule/assign-profile",
        json={"profile_id": "dns"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
