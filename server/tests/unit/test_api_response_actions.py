"""Unit tests for the Response Actions API — /api/v1/response-actions.

Covers:
  1. GET /response-actions       — empty list, list with items, filter by agent_cn
  2. GET /response-actions/{id}  — 200 with existing item, 404 if absent
  3. POST /response-actions/{id}/rollback — 204 success, 404 absent, 409 conflict
  4. Auth — analyst can read, admin can rollback, no-auth → 401, analyst rollback → 403
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.config import Settings
from oseye.storage.migrations import run_migrations
from oseye.storage.repositories.response_actions import SQLResponseActionsRepository

TEST_SECRET = "test-secret-hs256-not-for-production"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def app():  # type: ignore[no-untyped-def]
    """FastAPI test application backed by SQLite :memory: + mock executor."""
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
    application.state.response_actions_repo = SQLResponseActionsRepository(session_factory)

    # Action executor is only called during rollback — mock it so no gRPC needed.
    application.state.action_executor = AsyncMock()

    yield application
    await engine.dispose()


@pytest_asyncio.fixture
async def client(app):  # type: ignore[no-untyped-def]
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c


async def _token(client: AsyncClient, role: str = "analyst") -> str:
    """Obtain a JWT for the given role via POST /api/v1/auth/token."""
    username = "analyst" if role == "analyst" else "admin"
    password = "analyst123" if role == "analyst" else "admin123"
    resp = await client.post(
        "/api/v1/auth/token",
        data={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Seed helper
# ---------------------------------------------------------------------------


async def _seed_action(
    app,  # type: ignore[no-untyped-def]
    *,
    agent_cn: str = "agent-1.oseye.local",
    command_type: str = "BLOCK_IP",
    payload: str = '{"ip": "10.0.0.1"}',
    make_executed: bool = False,
    make_rolled_back: bool = False,
) -> str:
    """Create a ResponseActionRow via the real repo; return command_id."""
    repo: SQLResponseActionsRepository = app.state.response_actions_repo
    cmd_id = str(uuid.uuid4())
    await repo.create(
        command_id=cmd_id,
        decision_id=str(uuid.uuid4()),
        agent_cn=agent_cn,
        command_type=command_type,
        payload=payload,
    )
    if make_executed or make_rolled_back:
        await repo.mark_executed(cmd_id)
    if make_rolled_back:
        await repo.mark_rolled_back(cmd_id)
    return cmd_id


# ---------------------------------------------------------------------------
# 1. GET /response-actions — list
# ---------------------------------------------------------------------------


class TestListResponseActions:
    @pytest.mark.asyncio
    async def test_list_empty(self, client: AsyncClient) -> None:
        """Empty repo → returns an empty list."""
        tok = await _token(client)
        resp = await client.get("/api/v1/response-actions", headers=_auth(tok))
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_list_with_items(self, client: AsyncClient, app: object) -> None:
        """Seeded rows are returned in the list."""
        await _seed_action(app)
        await _seed_action(app, command_type="QUARANTINE_FILE")
        tok = await _token(client)
        resp = await client.get("/api/v1/response-actions", headers=_auth(tok))
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2
        # Verify expected keys are present
        for item in body:
            assert "command_id" in item
            assert "agent_cn" in item
            assert "command_type" in item
            assert "status" in item

    @pytest.mark.asyncio
    async def test_filter_by_agent_cn(self, client: AsyncClient, app: object) -> None:
        """Filter by agent_cn returns only matching rows."""
        await _seed_action(app, agent_cn="agent-alpha.oseye.local")
        await _seed_action(app, agent_cn="agent-beta.oseye.local")
        tok = await _token(client)
        resp = await client.get(
            "/api/v1/response-actions?agent_cn=agent-alpha.oseye.local",
            headers=_auth(tok),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["agent_cn"] == "agent-alpha.oseye.local"


# ---------------------------------------------------------------------------
# 2. GET /response-actions/{id}
# ---------------------------------------------------------------------------


class TestGetResponseAction:
    @pytest.mark.asyncio
    async def test_get_existing(self, client: AsyncClient, app: object) -> None:
        """Returns 200 with full action data for an existing command_id."""
        cmd_id = await _seed_action(app, command_type="BLOCK_IP")
        tok = await _token(client)
        resp = await client.get(f"/api/v1/response-actions/{cmd_id}", headers=_auth(tok))
        assert resp.status_code == 200
        body = resp.json()
        assert body["command_id"] == cmd_id
        assert body["command_type"] == "BLOCK_IP"
        assert body["status"] == "pending_report"

    @pytest.mark.asyncio
    async def test_get_not_found(self, client: AsyncClient) -> None:
        """Returns 404 for a command_id that does not exist."""
        tok = await _token(client)
        resp = await client.get(
            f"/api/v1/response-actions/{uuid.uuid4()}",
            headers=_auth(tok),
        )
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 3. POST /response-actions/{id}/rollback
# ---------------------------------------------------------------------------


class TestRollbackResponseAction:
    @pytest.mark.asyncio
    async def test_rollback_success(self, client: AsyncClient, app: object) -> None:
        """Rollback an 'executed' action → 204 and executor is called."""
        cmd_id = await _seed_action(app, make_executed=True)
        tok = await _token(client, role="admin")
        resp = await client.post(
            f"/api/v1/response-actions/{cmd_id}/rollback",
            headers=_auth(tok),
        )
        assert resp.status_code == 204
        # Executor must have been invoked
        executor: AsyncMock = app.state.action_executor  # type: ignore[union-attr]
        executor.emit_rollback.assert_called_once()
        call_kwargs = executor.emit_rollback.call_args.kwargs
        assert call_kwargs["command_id"] == cmd_id

    @pytest.mark.asyncio
    async def test_rollback_not_found(self, client: AsyncClient) -> None:
        """Returns 404 when command_id does not exist."""
        tok = await _token(client, role="admin")
        resp = await client.post(
            f"/api/v1/response-actions/{uuid.uuid4()}/rollback",
            headers=_auth(tok),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_rollback_conflict_already_rolled_back(
        self, client: AsyncClient, app: object
    ) -> None:
        """Returns 409 when action is already rolled back (status != 'executed')."""
        cmd_id = await _seed_action(app, make_rolled_back=True)
        tok = await _token(client, role="admin")
        resp = await client.post(
            f"/api/v1/response-actions/{cmd_id}/rollback",
            headers=_auth(tok),
        )
        assert resp.status_code == 409
        assert "rolled_back" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_rollback_conflict_pending(
        self, client: AsyncClient, app: object
    ) -> None:
        """Returns 409 when action is still pending (status != 'executed')."""
        cmd_id = await _seed_action(app)  # default status: pending_report
        tok = await _token(client, role="admin")
        resp = await client.post(
            f"/api/v1/response-actions/{cmd_id}/rollback",
            headers=_auth(tok),
        )
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 4. Auth — role enforcement
# ---------------------------------------------------------------------------


class TestResponseActionsAuth:
    @pytest.mark.asyncio
    async def test_list_no_auth(self, client: AsyncClient) -> None:
        """GET /response-actions without token → 401."""
        resp = await client.get("/api/v1/response-actions")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_get_no_auth(self, client: AsyncClient) -> None:
        """GET /response-actions/{id} without token → 401."""
        resp = await client.get(f"/api/v1/response-actions/{uuid.uuid4()}")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_rollback_no_auth(self, client: AsyncClient) -> None:
        """POST /rollback without token → 401."""
        resp = await client.post(
            f"/api/v1/response-actions/{uuid.uuid4()}/rollback"
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_list_analyst_allowed(self, client: AsyncClient) -> None:
        """analyst role can read the list."""
        tok = await _token(client, role="analyst")
        resp = await client.get("/api/v1/response-actions", headers=_auth(tok))
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_admin_allowed(self, client: AsyncClient) -> None:
        """admin role can also read the list."""
        tok = await _token(client, role="admin")
        resp = await client.get("/api/v1/response-actions", headers=_auth(tok))
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_rollback_analyst_forbidden(
        self, client: AsyncClient, app: object
    ) -> None:
        """analyst cannot rollback — must receive 403."""
        cmd_id = await _seed_action(app, make_executed=True)
        tok = await _token(client, role="analyst")
        resp = await client.post(
            f"/api/v1/response-actions/{cmd_id}/rollback",
            headers=_auth(tok),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_rollback_admin_allowed(
        self, client: AsyncClient, app: object
    ) -> None:
        """admin can successfully rollback an executed action."""
        cmd_id = await _seed_action(app, make_executed=True)
        tok = await _token(client, role="admin")
        resp = await client.post(
            f"/api/v1/response-actions/{cmd_id}/rollback",
            headers=_auth(tok),
        )
        assert resp.status_code == 204
