"""Integration — ingest gRPC → bus → storage_writer → DB → API GET /events.

Tests the interaction chain:
  AgentServiceServicer.IngestEvents
    → InMemoryEventBus (topic events:raw:{cn})
    → NormalizerEngine.process
    → InMemoryEventBus (topic events:normalized)
    → StorageWriter._flush
    → SQLEventRepository.insert_batch
    → GET /api/v1/events returns the stored event

All components are real (no mocks); only the transport layer is replaced by
direct in-process calls.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.bus.memory_bus import InMemoryEventBus
from oseye.config import Settings
from oseye.ingest.grpc_service import AgentServiceServicer
from oseye.ingest.validator import BatchValidator
from oseye.normalizer.engine import NormalizerEngine
from oseye.storage.migrations import run_migrations
from oseye.storage.repositories.events import SQLEventRepository
from oseye.workers.storage_writer import StorageWriter

TEST_SECRET = "integration-test-hs256-secret-min32bytes"
TEST_CN = str(uuid.uuid4())  # simulated mTLS CN = agent UUID


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(db_engine):
    return async_sessionmaker(
        bind=db_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )


@pytest_asyncio.fixture
async def repo(session_factory):
    return SQLEventRepository(session_factory)


@pytest_asyncio.fixture
async def bus():
    return InMemoryEventBus()


@pytest_asyncio.fixture
async def normalizer(bus):
    return NormalizerEngine(bus=bus, hostname="integration-host")


@pytest_asyncio.fixture
async def app_client(session_factory):
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
    application.state.event_repo = SQLEventRepository(session_factory)
    application.state.alert_repo = MagicMock()

    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as client:
        yield client, application


def _analyst_token(app: Any) -> str:
    return app.state.jwt_handler.create_token(subject="tester", roles=["analyst"])


# ---------------------------------------------------------------------------
# Helpers — build a fake procfs RawEvent payload (what the agent sends)
# ---------------------------------------------------------------------------


def _raw_procfs_payload(pid: int = 1234) -> bytes:
    return json.dumps({
        "pid": pid,
        "ppid": 1,
        "name": "bash",
        "exe": "/bin/bash",
        "cmdline": "bash -c 'echo hello'",
        "uid": 1000,
        "gid": 1000,
        "state": "S",
    }).encode()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_normalizer_publishes_to_normalized_topic(bus, normalizer):
    """NormalizerEngine.process publishes to events:normalized."""
    received: list[bytes] = []

    async def _collect() -> None:
        async for msg in await bus.subscribe("events:normalized"):
            received.append(msg)
            break

    collector_task = asyncio.create_task(_collect())
    await asyncio.sleep(0.01)

    await normalizer.process(
        raw_payload=_raw_procfs_payload(),
        source="procfs",
        os_name="linux",
        agent_id=TEST_CN,
    )

    await asyncio.wait_for(collector_task, timeout=2.0)
    assert len(received) == 1
    data = json.loads(received[0])
    assert data["category"] == "process"
    assert data["collector"] == "procfs"
    assert data["pid"] == 1234


@pytest.mark.asyncio
async def test_storage_writer_persists_normalized_event(bus, repo):
    """StorageWriter reads events:normalized and inserts them into the DB."""
    stop = asyncio.Event()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=10)
    task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.02)  # let writer subscribe

    event_json = json.dumps({
        "event_id": str(uuid.uuid4()),
        "timestamp_ns": time.time_ns(),
        "hostname": "integration-host",
        "agent_id": str(uuid.uuid4()),
        "category": "process",
        "type": "snapshot",
        "severity": "info",
        "collector": "procfs",
        "hash_chain": "a" * 64,
        "pid": 999,
        "process_name": "bash",
        "executable": "/bin/bash",
    }).encode()

    await bus.publish("events:normalized", event_json)
    await asyncio.sleep(0.2)  # allow timer flush

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    from dataclasses import dataclass as _dc

    @_dc
    class _F:
        hostname: str | None = None
        category: str | None = None
        type: str | None = None
        severity: str | None = None
        uid: int | None = None
        pid: int | None = None
        process_name: str | None = None
        resource: str | None = None
        rule_id: str | None = None
        mitre_technique: str | None = None
        from_ts: int | None = None
        to_ts: int | None = None
        agent_id: Any = None
        incident_chain_id: Any = None

    @_dc
    class _P:
        limit: int = 10
        offset: int = 0

    page = await repo.query(_F(), _P())
    assert page.total >= 1
    assert any(e.pid == 999 for e in page.items)


@pytest.mark.asyncio
async def test_full_pipeline_normalizer_to_api(bus, normalizer, repo, app_client):
    """End-to-end: normalizer → storage_writer → GET /api/v1/events."""
    client, app = app_client

    stop = asyncio.Event()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=10)
    write_task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.02)

    # Inject a raw event through the normalizer.
    await normalizer.process(
        raw_payload=_raw_procfs_payload(pid=4242),
        source="procfs",
        os_name="linux",
        agent_id=TEST_CN,
    )

    # Allow flush.
    await asyncio.sleep(0.2)
    stop.set()
    write_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await write_task

    # Sync the app's repo with the one that received the writes.
    app.state.event_repo = repo

    token = _analyst_token(app)
    resp = await client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        params={"category": "process"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    pids = [e["pid"] for e in body["items"]]
    assert 4242 in pids


@pytest.mark.asyncio
async def test_ingest_servicer_publishes_to_bus(bus):
    """AgentServiceServicer.IngestEvents publishes normalised events on events:normalized.

    pb_to_event already normalises the protobuf payload, so the servicer publishes
    directly to events:normalized (not events:raw) to avoid a double-normalisation pass.
    """
    validator = BatchValidator()
    servicer = AgentServiceServicer(bus=bus, validator=validator)

    topic = "events:normalized"
    received: list[bytes] = []

    async def _collect() -> None:
        async for msg in await bus.subscribe(topic):
            received.append(msg)
            break

    collector_task = asyncio.create_task(_collect())
    await asyncio.sleep(0.01)

    # Build a fake protobuf event — all fields that normalizer_bridge accesses.
    class _FakeEvent:
        event_id = b""
        timestamp_ns = time.time_ns()
        hostname = "host"
        agent_id = b""
        category = "process"
        type = "snapshot"
        severity = "info"
        collector = "procfs"
        os = "linux"
        hash_chain = b"a" * 32
        signature = b""
        extra_json = b""
        uid = 1000
        gid = 1000
        pid = 1234
        ppid = 1
        process_name = "bash"
        executable = "/bin/bash"
        cmdline = "bash"
        cwd = ""
        session_id = 0
        resource = ""
        result = "success"
        file_hash_before = ""
        file_hash_after = ""
        src_ip = ""
        src_port = 0
        dst_ip = ""
        dst_port = 0
        protocol = ""
        bytes_sent = 0
        bytes_recv = 0

    class _FakeRequest:
        events = [_FakeEvent()]
        batch_signature = b""
        public_key = b""

        def __iter__(self):
            yield self

    class _FakeContext:
        def peer_identities(self):
            # Return a DER-encoded cert that has CN = TEST_CN — skip real cert,
            # patch _extract_cn_from_context instead.
            return None

        def is_active(self):
            return True

        def abort(self, code, detail):
            raise RuntimeError(f"aborted: {detail}")

    # Patch _extract_cn to return our test CN without a real cert.
    import oseye.ingest.grpc_service as svc
    original = svc._extract_cn_from_context
    svc._extract_cn_from_context = lambda _ctx: TEST_CN  # type: ignore[assignment]

    try:
        servicer.IngestEvents(_FakeRequest(), _FakeContext())
        await asyncio.wait_for(collector_task, timeout=2.0)
    finally:
        svc._extract_cn_from_context = original  # type: ignore[assignment]

    assert len(received) >= 1


@pytest.mark.asyncio
async def test_api_returns_404_for_unknown_event(app_client):
    """GET /api/v1/events/{id} returns 404 for a non-existent event."""
    client, app = app_client
    token = _analyst_token(app)
    resp = await client.get(
        f"/api/v1/events/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_requires_auth(app_client):
    """GET /api/v1/events returns 403 without a valid token."""
    client, _app = app_client
    resp = await client.get("/api/v1/events")
    assert resp.status_code in (401, 403)
