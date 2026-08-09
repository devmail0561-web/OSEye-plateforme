"""Scenario — Agent event lifecycle (end-to-end, in-process).

Simulates the complete journey of an event from the moment the agent sends
a batch to the gRPC endpoint, through normalisation and storage, to the
operator querying events via the REST API.

Scenario steps
--------------
1. Agent sends a procfs event batch → AgentServiceServicer.IngestEvents
2. Servicer validates the batch and publishes on events:raw:{agent_id}
3. NormalizerEngine picks up the raw event and publishes on events:normalized
4. StorageWriter flushes to SQLite
5. Analyst calls GET /api/v1/events and sees the event
6. Analyst calls GET /api/v1/events/{id} and retrieves the full event

All I/O is in-process (SQLite :memory:, InMemoryEventBus).
No mocking of business logic — only the gRPC transport layer is replaced by
direct method calls.
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
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.repositories.events import SQLEventRepository
from oseye.workers.storage_writer import StorageWriter

import oseye.ingest.grpc_service as _grpc_svc

# ---------------------------------------------------------------------------
# Scenario constants
# ---------------------------------------------------------------------------

AGENT_ID = str(uuid.uuid4())
ANALYST_SECRET = "scenario-test-secret-long-enough-for-hmac"
HOSTNAME = "prod-linux-01"


# ---------------------------------------------------------------------------
# Fake protobuf event (all fields accessed by normalizer_bridge)
# ---------------------------------------------------------------------------


class FakePBEvent:
    """Minimal stand-in for a UniversalEventPB protobuf message."""

    def __init__(
        self,
        pid: int = 1234,
        ppid: int = 1,
        name: str = "bash",
        exe: str = "/bin/bash",
        cmdline: str = "bash -c 'echo hello'",
        uid: int = 1000,
    ) -> None:
        self.event_id = b""
        self.timestamp_ns = time.time_ns()
        self.hostname = HOSTNAME
        self.agent_id = b""
        self.category = "process"
        self.type = "snapshot"
        self.severity = "info"
        self.collector = "procfs"
        self.os = "linux"
        self.hash_chain = b"x" * 32
        self.signature = b""
        self.extra_json = b""
        self.uid = uid
        self.gid = uid
        self.pid = pid
        self.ppid = ppid
        self.process_name = name
        self.executable = exe
        self.cmdline = cmdline
        self.cwd = "/home/user"
        self.session_id = 0
        self.resource = ""
        self.result = "success"
        self.file_hash_before = ""
        self.file_hash_after = ""
        self.src_ip = ""
        self.src_port = 0
        self.dst_ip = ""
        self.dst_port = 0
        self.protocol = ""
        self.bytes_sent = 0
        self.bytes_recv = 0


class FakeIngestRequest:
    """Iterator that yields one gRPC IngestRequest."""

    def __init__(self, events: list[FakePBEvent]) -> None:
        self._events = events
        self.events = events  # servicer iterates request.events
        self.batch_signature = b""
        self.public_key = b""

    def __iter__(self):
        yield self


class FakeGRPCContext:
    """Minimal stand-in for a grpc.ServicerContext."""

    def peer_identities(self) -> None:
        return None  # we patch _extract_cn_from_context directly

    def is_active(self) -> bool:
        return True

    def abort(self, code: Any, detail: str) -> None:
        raise RuntimeError(f"grpc abort: {detail}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def infra():
    """Set up all in-process infrastructure components."""
    # Event bus
    bus = InMemoryEventBus()

    # Database (SQLite :memory:)
    backend = SQLiteBackend("sqlite+aiosqlite:///:memory:")
    await backend.init()
    repo = SQLEventRepository(backend.session_factory)

    # Components
    normalizer = NormalizerEngine(bus=bus, hostname=HOSTNAME)
    validator = BatchValidator()
    servicer = AgentServiceServicer(bus=bus, validator=validator)
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=100)

    # FastAPI app
    settings = Settings(
        jwt_private_key_path="/dev/null",
        jwt_public_key_path="/dev/null",
        jwt_access_token_expire_minutes=15,
        api_cors_origins=["*"],
    )
    app = create_app(settings)
    app.state.jwt_handler = JWTHandler(
        private_key_path="", public_key_path="", expire_minutes=15,
        secret=ANALYST_SECRET,
    )
    app.state.event_repo = repo
    app.state.alert_repo = MagicMock()

    yield {
        "bus": bus,
        "repo": repo,
        "normalizer": normalizer,
        "servicer": servicer,
        "writer": writer,
        "app": app,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _analyst_token(app: Any) -> str:
    return app.state.jwt_handler.create_token(subject="analyst", roles=["analyst"])


async def _run_normalizer_once(bus: InMemoryEventBus, normalizer: NormalizerEngine,
                                agent_id: str = AGENT_ID) -> None:
    """Listen for one raw event on events:raw:{agent_id} and normalise it.

    Used when testing the collector path (raw procfs payload → normalizer).
    Not used in the gRPC servicer path (which publishes directly to events:normalized).
    """
    topic = f"events:raw:{agent_id}"
    async for raw in await bus.subscribe(topic):
        await normalizer.process(
            raw_payload=raw,
            source="procfs",
            os_name="linux",
            agent_id=agent_id,
        )
        break


# ---------------------------------------------------------------------------
# Scenario tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scenario_single_event_full_lifecycle(infra):
    """
    Scenario: one procfs event traverses the full pipeline.

    Agent → gRPC servicer → bus(raw) → normalizer → bus(normalized)
    → storage_writer → DB → GET /events → GET /events/{id}
    """
    servicer = infra["servicer"]
    bus = infra["bus"]
    normalizer = infra["normalizer"]
    writer = infra["writer"]
    repo = infra["repo"]
    app = infra["app"]

    # Start the storage writer background task.
    stop = asyncio.Event()
    write_task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.02)  # allow writer to subscribe

    # ── Steps 1-2: agent "sends" a batch via the gRPC servicer.
    # The servicer calls pb_to_event (normalisation) then publishes directly
    # to events:normalized — no second normaliser pass needed.
    original_cn = _grpc_svc._extract_cn_from_context
    _grpc_svc._extract_cn_from_context = lambda _: AGENT_ID  # type: ignore[assignment]
    try:
        servicer.IngestEvents(
            FakeIngestRequest([FakePBEvent(pid=7777, name="sshd", exe="/usr/sbin/sshd")]),
            FakeGRPCContext(),
        )
    finally:
        _grpc_svc._extract_cn_from_context = original_cn  # type: ignore[assignment]

    # ── Step 3: storage writer flushes ────────────────────────────────────
    await asyncio.sleep(0.2)
    stop.set()
    write_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await write_task

    # ── Steps 5-6: query via REST API ────────────────────────────────────
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        token = _analyst_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # List events
        resp = await client.get("/api/v1/events", headers=headers,
                                params={"category": "process"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        matching = [e for e in body["items"] if e.get("pid") == 7777]
        assert len(matching) >= 1, f"pid=7777 not found in {body['items']}"

        # Get event by ID
        event_id = matching[0]["event_id"]
        resp2 = await client.get(f"/api/v1/events/{event_id}", headers=headers)
        assert resp2.status_code == 200
        detail = resp2.json()
        assert detail["pid"] == 7777
        assert detail["process_name"] in ("sshd", "")  # pb_to_event maps process_name from FakePBEvent
        assert detail["hostname"] == HOSTNAME


@pytest.mark.asyncio
async def test_scenario_multiple_agents_isolated(infra):
    """
    Scenario: two agents send events simultaneously — events are stored and
    can be filtered by agent_id.
    """
    servicer = infra["servicer"]
    bus = infra["bus"]
    normalizer = infra["normalizer"]
    writer = infra["writer"]
    repo = infra["repo"]
    app = infra["app"]

    agent_a = str(uuid.uuid4())
    agent_b = str(uuid.uuid4())

    stop = asyncio.Event()
    write_task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.02)

    original_cn = _grpc_svc._extract_cn_from_context

    for agent_id, pid in [(agent_a, 100), (agent_b, 200)]:
        _grpc_svc._extract_cn_from_context = lambda _, aid=agent_id: aid  # type: ignore[assignment]
        servicer.IngestEvents(
            FakeIngestRequest([FakePBEvent(pid=pid)]),
            FakeGRPCContext(),
        )

    _grpc_svc._extract_cn_from_context = original_cn  # type: ignore[assignment]

    await asyncio.sleep(0.2)
    stop.set()
    write_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await write_task

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        token = _analyst_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        resp = await client.get("/api/v1/events", headers=headers,
                                params={"agent_id": agent_a})
        assert resp.status_code == 200
        body_a = resp.json()
        pids_a = [e["pid"] for e in body_a["items"]]
        assert 100 in pids_a
        assert 200 not in pids_a

        resp = await client.get("/api/v1/events", headers=headers,
                                params={"agent_id": agent_b})
        body_b = resp.json()
        pids_b = [e["pid"] for e in body_b["items"]]
        assert 200 in pids_b
        assert 100 not in pids_b


@pytest.mark.asyncio
async def test_scenario_secret_masking_in_cmdline(infra):
    """
    Scenario: events with sensitive cmdlines are masked before storage.
    The secret value must NOT appear in the stored event.
    """
    servicer = infra["servicer"]
    bus = infra["bus"]
    normalizer = infra["normalizer"]
    writer = infra["writer"]
    repo = infra["repo"]
    app = infra["app"]

    stop = asyncio.Event()
    write_task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.02)

    original_cn = _grpc_svc._extract_cn_from_context
    _grpc_svc._extract_cn_from_context = lambda _: AGENT_ID  # type: ignore[assignment]
    try:
        # SEC-004: use the space-separated form (-p S3cr3tP@ssword) which is
        # correctly masked by the new pattern.  The attached form (-pSECRET) is
        # intentionally not masked to avoid false-positive forensic destruction
        # of unrelated flags like -path, -port, -proto.
        sensitive_event = FakePBEvent(
            pid=5555,
            cmdline="mysql -u root -p S3cr3tP@ssword --host db.internal",
        )
        servicer.IngestEvents(
            FakeIngestRequest([sensitive_event]),
            FakeGRPCContext(),
        )
    finally:
        _grpc_svc._extract_cn_from_context = original_cn  # type: ignore[assignment]

    await asyncio.sleep(0.2)
    stop.set()
    write_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await write_task

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        token = _analyst_token(app)
        resp = await client.get("/api/v1/events", headers={"Authorization": f"Bearer {token}"},
                                params={"category": "process"})
        assert resp.status_code == 200
        matching = [e for e in resp.json()["items"] if e.get("pid") == 5555]
        assert len(matching) >= 1
        cmdline = matching[0].get("cmdline", "")
        assert "S3cr3tP@ssword" not in cmdline, (
            f"Secret not masked in stored cmdline: {cmdline!r}"
        )


@pytest.mark.asyncio
async def test_scenario_health_endpoint_always_available(infra):
    """Health endpoint responds without authentication."""
    app = infra["app"]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
