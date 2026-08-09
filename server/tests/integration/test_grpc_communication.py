"""Integration — vrai test de communication gRPC Python→Python avec mTLS.

Lance un serveur grpc.aio réel avec des certificats auto-signés générés en
mémoire, envoie un IngestRequest via le stub Python (comme le ferait l'agent
Go), et vérifie que l'event est reçu, que le CN est extrait, et que l'event
est stocké en DB.

Ce test prouve que le canal de communication agent→serveur fonctionne
réellement — pas seulement que les modules s'importent.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import socket
import time
import uuid
from concurrent import futures
from dataclasses import dataclass
from typing import Any

import grpc
import grpc.aio
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.bus.memory_bus import InMemoryEventBus
from oseye.ingest.grpc_service import AgentServiceServicer, register_servicer
from oseye.ingest.validator import BatchValidator
from oseye.storage.migrations import run_migrations
from oseye.storage.repositories.events import SQLEventRepository
from oseye.workers.storage_writer import StorageWriter

# conftest.py adds repo root to sys.path so this import works
from server.gen import event_pb2 as pb2  # type: ignore[import-not-found]
from server.gen import event_pb2_grpc as pb2_grpc  # type: ignore[import-not-found]


# ---------------------------------------------------------------------------
# In-memory PKI — generate CA + server cert + agent cert at test time
# ---------------------------------------------------------------------------

AGENT_CN = str(uuid.uuid4())


def _generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OSEye-Test-CA")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _generate_cert(
    cn: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    server: bool = False,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    return key, builder.sign(ca_key, hashes.SHA256())


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_pb_event(pid: int = 1234, cmdline: str = "bash") -> pb2.UniversalEventPB:
    return pb2.UniversalEventPB(
        timestamp_ns=time.time_ns(),
        hostname="test-host",
        category="process",
        type="snapshot",
        severity="info",
        collector="procfs",
        os="linux",
        pid=pid,
        ppid=1,
        process_name="bash",
        executable="/bin/bash",
        cmdline=cmdline,
        uid=1000,
        gid=1000,
        hash_chain=b"a" * 32,
    )


@dataclass
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


@dataclass
class _P:
    limit: int = 50
    offset: int = 0


# ---------------------------------------------------------------------------
# Fixture — real mTLS gRPC server + authenticated stub
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def grpc_infra():
    """Start a real grpc.aio server with mTLS, return (stub, repo, stop, task)."""
    # Generate in-memory PKI
    ca_key, ca_cert = _generate_ca()
    srv_key, srv_cert = _generate_cert("oseye-server", ca_key, ca_cert, server=True)
    agent_key, agent_cert = _generate_cert(AGENT_CN, ca_key, ca_cert)

    # Server credentials — require client cert (mTLS)
    server_creds = grpc.ssl_server_credentials(
        [(_pem_key(srv_key), _pem_cert(srv_cert))],
        root_certificates=_pem_cert(ca_cert),
        require_client_auth=True,
    )
    # Client credentials — present agent cert + verify server cert
    client_creds = grpc.ssl_channel_credentials(
        root_certificates=_pem_cert(ca_cert),
        private_key=_pem_key(agent_key),
        certificate_chain=_pem_cert(agent_cert),
    )

    # Infrastructure
    bus = InMemoryEventBus()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)
    sf: async_sessionmaker[AsyncSession] = async_sessionmaker(
        bind=engine, expire_on_commit=False, class_=AsyncSession
    )
    repo = SQLEventRepository(sf)

    stop = asyncio.Event()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=100)
    write_task = asyncio.create_task(writer.run(stop_event=stop), name="writer")
    await asyncio.sleep(0.02)

    # gRPC server
    validator = BatchValidator()
    servicer = AgentServiceServicer(bus=bus, validator=validator)
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=4))
    register_servicer(servicer, server)
    port = _free_port()
    server.add_secure_port(f"127.0.0.1:{port}", server_creds)
    await server.start()

    # gRPC client stub
    channel = grpc.aio.secure_channel(f"127.0.0.1:{port}", client_creds)
    stub = pb2_grpc.AgentServiceStub(channel)

    yield stub, repo, stop, write_task

    await channel.close()
    await server.stop(grace=1)
    stop.set()
    write_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await write_task
    await engine.dispose()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grpc_ingest_single_event(grpc_infra):
    """Agent envoie un IngestRequest → serveur accepte → event stocké en DB."""
    stub, repo, _, _ = grpc_infra

    async def _send():
        yield pb2.IngestRequest(events=[_make_pb_event(pid=8888)])

    response = await stub.IngestEvents(_send())
    assert response.accepted == 1
    assert response.rejected == 0

    await asyncio.sleep(0.2)
    page = await repo.query(_F(), _P())
    assert page.total >= 1
    assert 8888 in {e.pid for e in page.items}


@pytest.mark.asyncio
async def test_grpc_ingest_batch(grpc_infra):
    """Agent envoie un batch de N events → tous acceptés et stockés."""
    stub, repo, _, _ = grpc_infra

    n = 10
    events = [_make_pb_event(pid=2000 + i) for i in range(n)]

    async def _send():
        yield pb2.IngestRequest(events=events)

    response = await stub.IngestEvents(_send())
    assert response.accepted == n
    assert response.rejected == 0

    await asyncio.sleep(0.2)
    page = await repo.query(_F(), _P())
    stored_pids = {e.pid for e in page.items}
    for i in range(n):
        assert 2000 + i in stored_pids, f"pid {2000+i} manquant en DB"


@pytest.mark.asyncio
async def test_grpc_ingest_multiple_requests(grpc_infra):
    """Un stream contient plusieurs IngestRequest successifs."""
    stub, repo, _, _ = grpc_infra

    async def _send():
        for pid in [3100, 3200, 3300]:
            yield pb2.IngestRequest(events=[_make_pb_event(pid=pid)])

    response = await stub.IngestEvents(_send())
    assert response.accepted == 3

    await asyncio.sleep(0.2)
    page = await repo.query(_F(), _P())
    pids = {e.pid for e in page.items}
    assert {3100, 3200, 3300}.issubset(pids)


@pytest.mark.asyncio
async def test_grpc_cn_used_as_agent_id(grpc_infra):
    """Le CN du cert client est utilisé comme agent_id (SEC-PREV-001)."""
    stub, repo, _, _ = grpc_infra

    async def _send():
        # Envoyer un agent_id différent dans le payload — doit être ignoré
        fake_agent_id = uuid.uuid4().bytes
        ev = _make_pb_event(pid=5555)
        ev = pb2.UniversalEventPB(
            agent_id=fake_agent_id,
            timestamp_ns=ev.timestamp_ns,
            hostname=ev.hostname,
            category=ev.category,
            type=ev.type,
            severity=ev.severity,
            collector=ev.collector,
            os=ev.os,
            pid=ev.pid,
            ppid=ev.ppid,
            hash_chain=ev.hash_chain,
        )
        yield pb2.IngestRequest(events=[ev])

    await stub.IngestEvents(_send())
    await asyncio.sleep(0.2)

    page = await repo.query(_F(), _P())
    matching = [e for e in page.items if e.pid == 5555]
    assert len(matching) == 1
    # agent_id doit correspondre au CN, pas au payload
    stored_agent_id = str(matching[0].agent_id)
    assert stored_agent_id == AGENT_CN, (
        f"agent_id stocké {stored_agent_id!r} ≠ CN {AGENT_CN!r} — SEC-PREV-001 violé"
    )


@pytest.mark.asyncio
async def test_grpc_secret_masked_over_wire(grpc_infra):
    """Cmdline avec mot de passe envoyé via gRPC → masqué avant stockage."""
    stub, repo, _, _ = grpc_infra

    async def _send():
        # SEC-004: use the space-separated form (-p TopSecret123) which is correctly
        # masked by the new pattern.  The attached form (-pSECRET) is no longer
        # masked to avoid false-positive forensic destruction of -path / -port flags.
        yield pb2.IngestRequest(events=[
            _make_pb_event(pid=9999, cmdline="mysqldump -u root -p TopSecret123 mydb")
        ])

    response = await stub.IngestEvents(_send())
    assert response.accepted == 1

    await asyncio.sleep(0.2)
    page = await repo.query(_F(), _P())
    matching = [e for e in page.items if e.pid == 9999]
    assert len(matching) == 1
    cmdline = matching[0].cmdline or ""
    assert "TopSecret123" not in cmdline, f"Secret non masqué en DB : {cmdline!r}"


@pytest.mark.asyncio
async def test_grpc_concurrent_clients(grpc_infra):
    """Deux clients envoient des batches simultanément — les deux sont traités."""
    stub, repo, _, _ = grpc_infra

    async def _client(pid: int) -> pb2.IngestResponse:
        async def _send():
            yield pb2.IngestRequest(events=[_make_pb_event(pid=pid)])
        return await stub.IngestEvents(_send())

    resp_a, resp_b = await asyncio.gather(_client(7001), _client(7002))
    assert resp_a.accepted == 1
    assert resp_b.accepted == 1

    await asyncio.sleep(0.2)
    page = await repo.query(_F(), _P())
    pids = {e.pid for e in page.items}
    assert 7001 in pids
    assert 7002 in pids


@pytest.mark.asyncio
async def test_grpc_rejects_unauthenticated_client():
    """Un client sans cert reçoit UNAUTHENTICATED — le serveur n'accepte pas."""
    ca_key, ca_cert = _generate_ca()
    srv_key, srv_cert = _generate_cert("oseye-server", ca_key, ca_cert, server=True)

    server_creds = grpc.ssl_server_credentials(
        [(_pem_key(srv_key), _pem_cert(srv_cert))],
        root_certificates=_pem_cert(ca_cert),
        require_client_auth=True,
    )

    bus = InMemoryEventBus()
    validator = BatchValidator()
    servicer = AgentServiceServicer(bus=bus, validator=validator)
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=2))
    register_servicer(servicer, server)
    port = _free_port()
    server.add_secure_port(f"127.0.0.1:{port}", server_creds)
    await server.start()

    # Client with no client cert — only CA for server verification
    no_auth_creds = grpc.ssl_channel_credentials(root_certificates=_pem_cert(ca_cert))
    channel = grpc.aio.secure_channel(f"127.0.0.1:{port}", no_auth_creds)
    stub = pb2_grpc.AgentServiceStub(channel)

    async def _send():
        yield pb2.IngestRequest(events=[_make_pb_event()])

    with pytest.raises(grpc.aio.AioRpcError) as exc_info:
        await stub.IngestEvents(_send())

    # Should fail at TLS handshake level (no client cert) or UNAUTHENTICATED
    assert exc_info.value.code() in (
        grpc.StatusCode.UNAVAILABLE,
        grpc.StatusCode.UNAUTHENTICATED,
    )

    await channel.close()
    await server.stop(grace=1)
