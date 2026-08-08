"""Unit tests for M24 — API Keys (P3.12), RBAC (P3.13), false-positive rule_versions (P3.14)."""

from __future__ import annotations

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
from oseye.storage.migrations import run_migrations
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.api_keys import SQLApiKeyRepository
from oseye.storage.repositories.events import SQLEventRepository
from oseye.storage.repositories.rule_versions import SQLRuleVersionRepository

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
    application.state.api_key_repo = SQLApiKeyRepository(session_factory)
    application.state.rule_version_repo = SQLRuleVersionRepository(session_factory)

    if _RULES_ROOT.exists():
        from oseye.rule_engine import RuleEngine
        application.state.rule_engine = RuleEngine(rules_root=_RULES_ROOT, hot_reload=False)

    yield application
    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):  # type: ignore[no-untyped-def]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


def _token(client: AsyncClient, role: str = "analyst") -> str:  # type: ignore[override]
    """Generate a JWT directly via JWTHandler — avoids hitting the rate-limited /auth/token."""
    app = client._transport.app  # type: ignore[attr-defined]
    handler = app.state.jwt_handler
    username = "analyst" if role == "analyst" else "admin"
    roles = ["analyst"] if role == "analyst" else ["admin", "analyst"]
    return handler.create_token(subject=username, roles=roles)


def _make_alert(rule_id: str = "rule_test", hostname: str = "host1") -> Alert:
    now = datetime.now(tz=UTC)
    return Alert(
        alert_id=uuid.uuid4(),
        created_at=now,
        updated_at=now,
        severity="high",
        status="open",
        rule_id=rule_id,
        entity_id=f"{hostname}:1234",
        hostname=hostname,
        trigger_event_id=uuid.uuid4(),
        title="Test alert",
    )


# ---------------------------------------------------------------------------
# P3.12 — API Keys
# ---------------------------------------------------------------------------


class TestApiKeys:
    @pytest.mark.asyncio
    async def test_create_api_key_admin_only(self, client: AsyncClient) -> None:
        admin_tok = _token(client, "admin")
        resp = await client.post(
            "/api/v1/api-keys",
            json={"name": "ci-bot", "roles": ["analyst"]},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["key"].startswith("osk_")
        assert data["name"] == "ci-bot"
        assert data["roles"] == ["analyst"]

    @pytest.mark.asyncio
    async def test_create_api_key_forbidden_for_analyst(self, client: AsyncClient) -> None:
        tok = _token(client, "analyst")
        resp = await client.post(
            "/api/v1/api-keys",
            json={"name": "should-fail", "roles": ["analyst"]},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_list_api_keys(self, client: AsyncClient) -> None:
        admin_tok = _token(client, "admin")
        await client.post(
            "/api/v1/api-keys",
            json={"name": "list-test", "roles": ["analyst"]},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        resp = await client.get(
            "/api/v1/api-keys", headers={"Authorization": f"Bearer {admin_tok}"}
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    @pytest.mark.asyncio
    async def test_revoke_api_key(self, client: AsyncClient) -> None:
        admin_tok = _token(client, "admin")
        create_resp = await client.post(
            "/api/v1/api-keys",
            json={"name": "to-revoke", "roles": ["analyst"]},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        key_id = create_resp.json()["key_id"]
        resp = await client.delete(
            f"/api/v1/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_key(self, client: AsyncClient) -> None:
        admin_tok = _token(client, "admin")
        resp = await client.delete(
            "/api/v1/api-keys/nonexistent-id",
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_api_key_authenticates_endpoint(self, client: AsyncClient) -> None:
        """A valid API key can call protected endpoints."""
        admin_tok = _token(client, "admin")
        create_resp = await client.post(
            "/api/v1/api-keys",
            json={"name": "caller", "roles": ["analyst"]},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        raw_key = create_resp.json()["key"]

        resp = await client.get(
            "/api/v1/alerts", headers={"X-API-Key": raw_key}
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_revoked_api_key_rejected(self, client: AsyncClient) -> None:
        admin_tok = _token(client, "admin")
        create_resp = await client.post(
            "/api/v1/api-keys",
            json={"name": "revoke-me", "roles": ["analyst"]},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        data = create_resp.json()
        raw_key, key_id = data["key"], data["key_id"]

        await client.delete(
            f"/api/v1/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        resp = await client.get("/api/v1/alerts", headers={"X-API-Key": raw_key})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_api_key_rejected(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/alerts", headers={"X-API-Key": "osk_invalid"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# P3.13 — RBAC enforced on all endpoints
# ---------------------------------------------------------------------------


class TestRBACEnforced:
    @pytest.mark.asyncio
    async def test_events_unauthenticated(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/events")
        assert resp.status_code in (401, 403)  # unauthenticated → 401

    @pytest.mark.asyncio
    async def test_alerts_unauthenticated(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/alerts")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_rules_unauthenticated(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/rules")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_api_keys_unauthenticated(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/api-keys")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_health_public(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_analyst_cannot_access_api_keys(self, client: AsyncClient) -> None:
        tok = _token(client, "analyst")
        resp = await client.get(
            "/api/v1/api-keys", headers={"Authorization": f"Bearer {tok}"}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_reload_rules(self, client: AsyncClient) -> None:
        tok = _token(client, "analyst")
        resp = await client.post(
            "/api/v1/rules/reload", headers={"Authorization": f"Bearer {tok}"}
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# P3.14 — false-positive feedback → rule_versions
# ---------------------------------------------------------------------------


class TestFalsePositiveFeedback:
    @pytest.mark.asyncio
    async def test_false_positive_logs_rule_version(self, client: AsyncClient, app) -> None:  # type: ignore[no-untyped-def]
        alert = _make_alert(rule_id="rule_ssh_bruteforce")
        await app.state.alert_repo.create(alert)

        tok = _token(client, "analyst")
        resp = await client.post(
            f"/api/v1/alerts/{alert.alert_id}/false-positive",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "false_positive"
        assert data["false_positive_count"] == 1

        # Verify rule_versions row was inserted
        from sqlalchemy import select
        from oseye.storage.models import RuleVersionRow
        engine = app.state.rule_version_repo._session_factory.kw["bind"]
        async with app.state.rule_version_repo._session_factory() as session:
            rows = (
                await session.execute(
                    select(RuleVersionRow).where(RuleVersionRow.rule_id == "rule_ssh_bruteforce")
                )
            ).scalars().all()
        assert len(rows) == 1
        assert rows[0].event_type == "false_positive"
        assert rows[0].false_positive_count == 1

    @pytest.mark.asyncio
    async def test_false_positive_increments_count(self, client: AsyncClient, app) -> None:  # type: ignore[no-untyped-def]
        alert = _make_alert(rule_id="rule_port_scan")
        await app.state.alert_repo.create(alert)
        tok = _token(client, "analyst")
        url = f"/api/v1/alerts/{alert.alert_id}/false-positive"
        headers = {"Authorization": f"Bearer {tok}"}

        r1 = await client.post(url, headers=headers)
        assert r1.json()["false_positive_count"] == 1
        r2 = await client.post(url, headers=headers)
        assert r2.json()["false_positive_count"] == 2

    @pytest.mark.asyncio
    async def test_false_positive_no_rule_id_does_not_crash(
        self, client: AsyncClient, app  # type: ignore[no-untyped-def]
    ) -> None:
        alert = _make_alert(rule_id=None)  # type: ignore[arg-type]
        alert.rule_id = None
        await app.state.alert_repo.create(alert)
        tok = _token(client, "analyst")
        resp = await client.post(
            f"/api/v1/alerts/{alert.alert_id}/false-positive",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 200
