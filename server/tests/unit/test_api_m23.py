"""Unit tests for M23 — Rules API, extended Alerts API, WS alerts."""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.config import Settings
from oseye.core.schema import Alert
from oseye.rule_engine import RuleEngine
from oseye.storage.migrations import run_migrations
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.events import SQLEventRepository

_RULES_ROOT = Path(__file__).parent.parent.parent.parent / "rules"

TEST_SECRET = "test-secret-hs256-not-for-production"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
        private_key_path="",
        public_key_path="",
        expire_minutes=15,
        secret=TEST_SECRET,
    )

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)
    session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        bind=engine, expire_on_commit=False, class_=AsyncSession
    )
    application.state.event_repo = SQLEventRepository(session_factory)
    application.state.alert_repo = SQLAlertRepository(session_factory)

    if _RULES_ROOT.exists():
        application.state.rule_engine = RuleEngine(rules_root=_RULES_ROOT, hot_reload=False)

    yield application
    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


_token_cache: dict[str, str] = {}


async def _token(client: AsyncClient, role: str = "analyst") -> str:
    if role in _token_cache:
        return _token_cache[role]
    username = "analyst" if role == "analyst" else "admin"
    password = os.getenv("OSEYE_ANALYST_PASSWORD", "analyst123") if role == "analyst" else os.getenv("OSEYE_ADMIN_PASSWORD", "admin123")
    resp = await client.post(
        "/api/v1/auth/token", data={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.text
    tok = str(resp.json()["access_token"])
    _token_cache[role] = tok
    return tok


def _make_alert(hostname: str = "host1", severity: str = "high") -> Alert:
    now = datetime.now(tz=UTC)
    return Alert(
        alert_id=uuid.uuid4(),
        created_at=now,
        updated_at=now,
        severity=severity,  # type: ignore[arg-type]
        status="open",
        rule_id="rule_shadow_read",
        entity_id=f"{hostname}:1234",
        hostname=hostname,
        trigger_event_id=uuid.uuid4(),
        title="Test alert",
        description="Test",
        mitre_techniques=["T1003.008"],
    )


# ---------------------------------------------------------------------------
# Rules API tests
# ---------------------------------------------------------------------------


class TestRulesAPI:
    @pytest.mark.asyncio
    async def test_list_rules(self, client: AsyncClient) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        tok = await _token(client)
        resp = await client.get("/api/v1/rules", headers={"Authorization": f"Bearer {tok}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 25
        assert len(data["items"]) >= 25

    @pytest.mark.asyncio
    async def test_list_rules_enabled_only(self, client: AsyncClient) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        tok = await _token(client)
        resp = await client.get(
            "/api/v1/rules?enabled_only=true",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["enabled"] is True

    @pytest.mark.asyncio
    async def test_get_rule_by_id(self, client: AsyncClient) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        tok = await _token(client)
        resp = await client.get(
            "/api/v1/rules/rule_shadow_read",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == "rule_shadow_read"
        assert resp.json()["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_get_rule_not_found(self, client: AsyncClient) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        tok = await _token(client)
        resp = await client.get(
            "/api/v1/rules/nonexistent_rule_xyz",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_validate_valid_condition(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.post(
            "/api/v1/rules/validate",
            json={"condition": "event.category == 'file' and event.uid != 0"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is True
        assert resp.json()["error"] is None

    @pytest.mark.asyncio
    async def test_validate_invalid_condition(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.post(
            "/api/v1/rules/validate",
            json={"condition": "this is not valid python !!!"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False
        assert resp.json()["error"] is not None

    @pytest.mark.asyncio
    async def test_validate_disallowed_ast(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.post(
            "/api/v1/rules/validate",
            json={"condition": "__import__('os').system('id')"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    @pytest.mark.asyncio
    async def test_reload_requires_admin(self, client: AsyncClient) -> None:
        tok = await _token(client, role="analyst")
        resp = await client.post(
            "/api/v1/rules/reload",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_rules_require_auth(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/rules")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_rules_engine_not_init(self, client: AsyncClient, app: object) -> None:
        # Remove rule_engine from state
        if hasattr(app, "state") and hasattr(app.state, "rule_engine"):  # type: ignore[union-attr]
            del app.state.rule_engine  # type: ignore[union-attr]
        tok = await _token(client)
        resp = await client.get("/api/v1/rules", headers={"Authorization": f"Bearer {tok}"})
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Extended Alerts API tests
# ---------------------------------------------------------------------------


class TestAlertsExtended:
    @pytest_asyncio.fixture(autouse=True)
    async def _seed_alert(self, app: object) -> None:
        repo: SQLAlertRepository = app.state.alert_repo  # type: ignore[union-attr]
        self._alert = _make_alert()
        await repo.create(self._alert)

    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.post(
            f"/api/v1/alerts/{self._alert.alert_id}/acknowledge",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    @pytest.mark.asyncio
    async def test_mark_false_positive(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.post(
            f"/api/v1/alerts/{self._alert.alert_id}/false-positive",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "false_positive"
        assert resp.json()["false_positive_count"] == 1

    @pytest.mark.asyncio
    async def test_acknowledge_nonexistent(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.post(
            f"/api/v1/alerts/{uuid.uuid4()}/acknowledge",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_false_positive_nonexistent(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.post(
            f"/api/v1/alerts/{uuid.uuid4()}/false-positive",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_patch_invalid_status(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.patch(
            f"/api/v1/alerts/{self._alert.alert_id}",
            json={"status": "invalid_status_xyz"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_alerts_stats(self, client: AsyncClient) -> None:
        tok = await _token(client)
        resp = await client.get(
            "/api/v1/alerts/stats",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "by_severity" in data
        assert "open" in data
        assert data["by_severity"]["high"] >= 1  # our seeded alert

    @pytest.mark.asyncio
    async def test_alerts_stats_require_auth(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/alerts/stats")
        assert resp.status_code in (401, 403)
