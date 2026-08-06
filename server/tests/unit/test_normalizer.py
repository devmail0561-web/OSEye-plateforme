"""Unit tests for the normalizer — adapters, engine, and secret masker."""

from __future__ import annotations

import json
import uuid

import pytest

from oseye.bus.memory_bus import InMemoryEventBus
from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux.auditd import AuditdAdapter
from oseye.normalizer.adapters.linux.ebpf import EBPFAdapter
from oseye.normalizer.adapters.linux.procfs import ProcfsAdapter
from oseye.normalizer.engine import NormalizerEngine
from oseye.normalizer.secret_masker import mask

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AGENT_ID = str(uuid.uuid4())
_HOSTNAME = "test-host"


def _raw(data: dict[str, object]) -> bytes:
    return json.dumps(data).encode()


# ---------------------------------------------------------------------------
# ProcfsAdapter
# ---------------------------------------------------------------------------


def test_procfs_normalize() -> None:
    adapter = ProcfsAdapter()
    payload = _raw(
        {
            "pid": 1234,
            "ppid": 1,
            "name": "bash",
            "exe": "/bin/bash",
            "cmdline": "bash -c echo hello",
            "uid": 1000,
            "gid": 1000,
            "state": "S",
        }
    )
    event = adapter.normalize(payload, _HOSTNAME, _AGENT_ID)

    assert isinstance(event, UniversalEvent)
    assert event.category == "process"
    assert event.type == "snapshot"
    assert event.severity == "info"
    assert event.collector == "procfs"
    assert event.pid == 1234
    assert event.ppid == 1
    assert event.uid == 1000
    assert event.gid == 1000
    assert event.process_name == "bash"
    assert event.executable == "/bin/bash"
    assert event.cmdline == "bash -c echo hello"
    assert event.hostname == _HOSTNAME
    assert event.agent_id == uuid.UUID(_AGENT_ID)
    # Auto-generated fields must be present
    assert event.event_id is not None
    assert event.timestamp_ns > 0


# ---------------------------------------------------------------------------
# AuditdAdapter
# ---------------------------------------------------------------------------


def test_auditd_execve() -> None:
    adapter = AuditdAdapter()
    payload = _raw(
        {
            "type": "SYSCALL",
            "syscall": "execve",
            "pid": 5678,
            "ppid": 100,
            "uid": 0,
            "exe": "/usr/bin/python3",
            "comm": "python3",
            "key": "exec_monitor",
        }
    )
    event = adapter.normalize(payload, _HOSTNAME, _AGENT_ID)

    assert event.category == "process"
    assert event.type == "exec"
    assert event.collector == "auditd"
    assert event.pid == 5678
    assert event.executable == "/usr/bin/python3"
    assert event.process_name == "python3"


def test_auditd_connect() -> None:
    adapter = AuditdAdapter()
    payload = _raw(
        {
            "type": "SYSCALL",
            "syscall": "connect",
            "pid": 999,
            "ppid": 1,
            "uid": 0,
            "exe": "/usr/bin/curl",
            "comm": "curl",
        }
    )
    event = adapter.normalize(payload, _HOSTNAME, _AGENT_ID)

    assert event.category == "network"
    assert event.type == "connect"


def test_auditd_unknown_syscall_falls_back() -> None:
    adapter = AuditdAdapter()
    payload = _raw({"type": "SYSCALL", "syscall": "mmap", "pid": 1, "ppid": 0, "uid": 0})
    event = adapter.normalize(payload, _HOSTNAME, _AGENT_ID)

    assert event.category == "process"
    assert event.type == "mmap"


# ---------------------------------------------------------------------------
# EBPFAdapter
# ---------------------------------------------------------------------------


def test_ebpf_execve() -> None:
    adapter = EBPFAdapter()
    payload = _raw(
        {
            "event_type": "execve",
            "pid": 9012,
            "ppid": 200,
            "uid": 500,
            "gid": 500,
            "comm": "curl",
            "exe": "/usr/bin/curl",
            "args": ["curl", "https://example.com"],
            "ret": 0,
        }
    )
    event = adapter.normalize(payload, _HOSTNAME, _AGENT_ID)

    assert event.category == "process"
    assert event.type == "exec"
    assert event.collector == "ebpf"
    assert event.pid == 9012
    assert event.process_name == "curl"
    assert "curl" in event.cmdline


def test_ebpf_connect_with_network_fields() -> None:
    adapter = EBPFAdapter()
    payload = _raw(
        {
            "event_type": "connect",
            "pid": 1111,
            "ppid": 10,
            "uid": 0,
            "gid": 0,
            "comm": "wget",
            "exe": "/usr/bin/wget",
            "src_ip": "192.168.1.5",
            "src_port": 54321,
            "dst_ip": "93.184.216.34",
            "dst_port": 443,
            "ret": 0,
        }
    )
    event = adapter.normalize(payload, _HOSTNAME, _AGENT_ID)

    assert event.category == "network"
    assert event.type == "connect"
    assert event.src_ip == "192.168.1.5"
    assert event.src_port == 54321
    assert event.dst_ip == "93.184.216.34"
    assert event.dst_port == 443


def test_ebpf_unlink_maps_to_file_delete() -> None:
    adapter = EBPFAdapter()
    payload = _raw({"event_type": "unlink", "pid": 42, "ppid": 1, "uid": 0, "gid": 0})
    event = adapter.normalize(payload, _HOSTNAME, _AGENT_ID)

    assert event.category == "file"
    assert event.type == "delete"


# ---------------------------------------------------------------------------
# Secret masker
# ---------------------------------------------------------------------------


def test_secret_masker_password() -> None:
    result = mask("mysql -u root -p password123 --host db")
    assert "password123" not in result
    assert "***" in result


def test_secret_masker_key_value() -> None:
    result = mask("app --api_key=supersecret123")
    assert "supersecret123" not in result
    assert "***" in result


def test_secret_masker_bearer_token() -> None:
    result = mask("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def'")
    assert "eyJhbGciOiJIUzI1NiJ9.abc.def" not in result
    assert "***" in result


def test_secret_masker_no_false_positive() -> None:
    safe = "ls -la /home/user"
    assert mask(safe) == safe


# ---------------------------------------------------------------------------
# NormalizerEngine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_dispatch() -> None:
    bus = InMemoryEventBus()
    engine = NormalizerEngine(bus, _HOSTNAME)

    sub = await bus.subscribe("events:normalized")

    payload = _raw(
        {
            "pid": 42,
            "ppid": 1,
            "name": "sshd",
            "exe": "/usr/sbin/sshd",
            "cmdline": "sshd -D",
            "uid": 0,
            "gid": 0,
        }
    )
    event = await engine.process(payload, source="procfs", os_name="linux", agent_id=_AGENT_ID)

    assert event is not None
    assert event.category == "process"
    assert event.type == "snapshot"
    assert event.pid == 42

    # Verify the message was published on the bus
    import asyncio

    published: bytes = await asyncio.wait_for(sub.__anext__(), timeout=1.0)
    data = json.loads(published)
    assert data["pid"] == 42
    assert data["collector"] == "procfs"


@pytest.mark.asyncio
async def test_engine_unknown_source_returns_none() -> None:
    bus = InMemoryEventBus()
    engine = NormalizerEngine(bus, _HOSTNAME)

    result = await engine.process(
        b'{"foo": "bar"}',
        source="unknown_collector",
        os_name="linux",
        agent_id=_AGENT_ID,
    )
    assert result is None


@pytest.mark.asyncio
async def test_engine_register_custom_adapter() -> None:
    """register_adapter overrides the built-in mapping."""
    bus = InMemoryEventBus()
    engine = NormalizerEngine(bus, _HOSTNAME)

    # Register a custom adapter for a new OS/source pair
    engine.register_adapter("linux", "custom_src", ProcfsAdapter())

    payload = _raw({"pid": 7, "ppid": 1, "name": "test", "exe": "/bin/test", "uid": 0, "gid": 0})
    event = await engine.process(payload, source="custom_src", os_name="linux", agent_id=_AGENT_ID)

    assert event is not None
    assert event.collector == "procfs"
