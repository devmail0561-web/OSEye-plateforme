"""Unit tests for the normalizer — adapters, engine, and secret masker."""

from __future__ import annotations

import json
import uuid

import pytest

from oseye.bus.memory_bus import InMemoryEventBus
from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux.auditd import AuditdAdapter
from oseye.normalizer.adapters.linux.ebpf import EBPFAdapter
from oseye.normalizer.adapters.linux.fanotify import FanotifyAdapter
from oseye.normalizer.adapters.linux.inotify import InotifyAdapter
from oseye.normalizer.adapters.linux.journald import JournaldAdapter
from oseye.normalizer.adapters.linux.netlink import NetlinkAdapter
from oseye.normalizer.adapters.linux.procfs import ProcfsAdapter
from oseye.normalizer.adapters.linux.syslog import SyslogAdapter
from oseye.normalizer.adapters.linux.udev import UdevAdapter
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
    # eBPF adapter intentionally does not extract src_ip/src_port (audit fix)
    assert event.src_ip is None
    assert event.src_port is None
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


# ---------------------------------------------------------------------------
# FanotifyAdapter
# ---------------------------------------------------------------------------


def test_fanotify_normalize_open() -> None:
    adapter = FanotifyAdapter()
    event = adapter.normalize(
        _raw({"event_type": "open", "path": "/etc/passwd", "pid": 42}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.category == "file"
    assert event.type == "open"
    assert event.severity == "info"
    assert event.resource == "/etc/passwd"
    assert event.pid == 42
    assert event.collector == "fanotify"


def test_fanotify_normalize_modify_is_medium() -> None:
    adapter = FanotifyAdapter()
    event = adapter.normalize(
        _raw({"event_type": "modify", "path": "/etc/shadow"}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.severity == "medium"


def test_fanotify_normalize_missing_fields() -> None:
    adapter = FanotifyAdapter()
    event = adapter.normalize(b"{}", _HOSTNAME, _AGENT_ID)
    assert event.category == "file"
    assert event.resource == ""
    assert event.type == ""


# ---------------------------------------------------------------------------
# InotifyAdapter
# ---------------------------------------------------------------------------


def test_inotify_normalize_full_path() -> None:
    adapter = InotifyAdapter()
    event = adapter.normalize(
        _raw({"event_type": "create", "full_path": "/tmp/evil.sh", "base_path": "/tmp"}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.category == "file"
    assert event.type == "create"
    assert event.resource == "/tmp/evil.sh"
    assert event.collector == "inotify"


def test_inotify_normalize_delete_severity() -> None:
    # M12 fix: "warning" is not a valid severity in the schema — assert "medium".
    adapter = InotifyAdapter()
    for ev_type in ("create", "delete", "moved_from", "moved_to"):
        event = adapter.normalize(_raw({"event_type": ev_type}), _HOSTNAME, _AGENT_ID)
        assert event.severity == "medium", f"{ev_type} should be medium, got {event.severity!r}"


def test_inotify_normalize_missing_fields() -> None:
    adapter = InotifyAdapter()
    event = adapter.normalize(b"{}", _HOSTNAME, _AGENT_ID)
    assert event.category == "file"
    assert event.resource == ""


# ---------------------------------------------------------------------------
# NetlinkAdapter
# ---------------------------------------------------------------------------


def test_netlink_normalize_new_connection() -> None:
    adapter = NetlinkAdapter()
    event = adapter.normalize(
        _raw({"event": "new", "local_addr": "10.0.0.1:1234", "remote_addr": "8.8.8.8:53", "proto": "udp"}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.category == "network"
    assert event.type == "new"
    assert event.src_ip == "10.0.0.1"
    assert event.src_port == 1234
    assert event.dst_ip == "8.8.8.8"
    assert event.dst_port == 53
    assert event.protocol == "udp"
    assert event.collector == "netlink"


def test_netlink_normalize_closed_connection() -> None:
    adapter = NetlinkAdapter()
    event = adapter.normalize(
        _raw({"event": "closed", "local_addr": "10.0.0.1:5000", "remote_addr": "1.2.3.4:80", "proto": "tcp"}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.type == "closed"


def test_netlink_normalize_missing_fields() -> None:
    adapter = NetlinkAdapter()
    event = adapter.normalize(b"{}", _HOSTNAME, _AGENT_ID)
    assert event.category == "network"
    assert event.src_ip == ""
    assert event.dst_ip == ""


# ---------------------------------------------------------------------------
# JournaldAdapter
# ---------------------------------------------------------------------------


def test_journald_normalize_full() -> None:
    adapter = JournaldAdapter()
    event = adapter.normalize(
        _raw({"priority": "3", "unit": "sshd.service", "comm": "sshd", "pid": 1234}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.category == "log"
    assert event.type == "journal_entry"
    assert event.severity == "high"
    assert event.resource == "sshd.service"
    assert event.process_name == "sshd"
    assert event.pid == 1234
    assert event.collector == "journald"


def test_journald_normalize_priority_mapping() -> None:
    adapter = JournaldAdapter()
    for prio, expected in (("0", "critical"), ("4", "medium"), ("7", "info")):
        event = adapter.normalize(_raw({"priority": prio}), _HOSTNAME, _AGENT_ID)
        assert event.severity == expected, f"priority {prio!r} → {event.severity!r}, want {expected!r}"


def test_journald_normalize_missing_fields() -> None:
    adapter = JournaldAdapter()
    event = adapter.normalize(b"{}", _HOSTNAME, _AGENT_ID)
    assert event.category == "log"
    assert event.severity == "info"


# ---------------------------------------------------------------------------
# SyslogAdapter
# ---------------------------------------------------------------------------


def test_syslog_normalize_full() -> None:
    adapter = SyslogAdapter()
    event = adapter.normalize(
        _raw({"severity": "warning", "program": "kernel", "hostname": "box1"}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.category == "log"
    assert event.type == "syslog_entry"
    assert event.severity == "medium"
    assert event.resource == "kernel"
    assert event.collector == "syslog"


def test_syslog_normalize_critical_severities() -> None:
    adapter = SyslogAdapter()
    for sev in ("emerg", "alert", "crit", "critical"):
        event = adapter.normalize(_raw({"severity": sev}), _HOSTNAME, _AGENT_ID)
        assert event.severity == "critical", f"sev {sev!r} should be critical"


def test_syslog_normalize_missing_fields() -> None:
    adapter = SyslogAdapter()
    event = adapter.normalize(b"{}", _HOSTNAME, _AGENT_ID)
    assert event.category == "log"
    assert event.severity == "info"


# ---------------------------------------------------------------------------
# UdevAdapter
# ---------------------------------------------------------------------------


def test_udev_normalize_add() -> None:
    adapter = UdevAdapter()
    event = adapter.normalize(
        _raw({"action": "add", "devpath": "/devices/pci0000:00/0000:00:14.0/usb1/1-1"}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.category == "device"
    assert event.type == "add"
    assert event.severity == "info"
    assert event.resource == "/devices/pci0000:00/0000:00:14.0/usb1/1-1"
    assert event.collector == "udev"


def test_udev_normalize_remove() -> None:
    adapter = UdevAdapter()
    event = adapter.normalize(_raw({"action": "remove", "devpath": "/devices/usb1/1-1"}), _HOSTNAME, _AGENT_ID)
    assert event.type == "remove"


def test_udev_normalize_missing_fields() -> None:
    adapter = UdevAdapter()
    event = adapter.normalize(b"{}", _HOSTNAME, _AGENT_ID)
    assert event.category == "device"
    assert event.resource == ""
    assert event.type == ""


# ---------------------------------------------------------------------------
# NormalizerEngine — Phase 2 adapters registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_dispatches_phase2_collectors() -> None:
    """All Phase 2 collectors must be registered in the engine by default."""
    bus = InMemoryEventBus()
    engine = NormalizerEngine(bus, _HOSTNAME)

    for source, payload in (
        ("fanotify", _raw({"event_type": "open", "path": "/etc/hosts"})),
        ("inotify", _raw({"event_type": "create", "full_path": "/tmp/x"})),
        ("netlink", _raw({"event": "new", "local_addr": "1.2.3.4:1000", "remote_addr": "5.6.7.8:80", "proto": "tcp"})),
        ("journald", _raw({"priority": "5", "unit": "cron.service"})),
        ("syslog", _raw({"severity": "info", "program": "crond"})),
        ("udev", _raw({"action": "add", "devpath": "/devices/usb"})),
    ):
        event = await engine.process(payload, source=source, os_name="linux", agent_id=_AGENT_ID)
        assert event is not None, f"engine returned None for source={source!r}"
        assert event.collector == source


# ---------------------------------------------------------------------------
# Robustness — C1/C2/H8/H9/F08/F10/F13/F14 fixes
# ---------------------------------------------------------------------------


def test_fanotify_pid_null_does_not_crash() -> None:
    """C2/F13 fix: pid=null must not raise TypeError."""
    adapter = FanotifyAdapter()
    event = adapter.normalize(_raw({"event_type": "open", "path": "/tmp/x", "pid": None}), _HOSTNAME, _AGENT_ID)
    assert event.pid == 0


def test_fanotify_pid_absent_defaults_to_zero() -> None:
    """F02 fix: absent pid must use 0, not -1."""
    adapter = FanotifyAdapter()
    event = adapter.normalize(_raw({"event_type": "open", "path": "/tmp/x"}), _HOSTNAME, _AGENT_ID)
    assert event.pid == 0


def test_journald_pid_null_does_not_crash() -> None:
    """C2/F13 fix: journald pid=null must not raise TypeError."""
    adapter = JournaldAdapter()
    event = adapter.normalize(_raw({"priority": "3", "pid": None}), _HOSTNAME, _AGENT_ID)
    assert event.pid == 0


def test_journald_pid_empty_string_does_not_crash() -> None:
    """F14 fix: journald _PID="" must not raise ValueError."""
    adapter = JournaldAdapter()
    event = adapter.normalize(_raw({"priority": "5", "pid": ""}), _HOSTNAME, _AGENT_ID)
    assert event.pid == 0


def test_journald_pid_string_parsed_correctly() -> None:
    """journald emits _PID as a JSON string — must be parsed to int."""
    adapter = JournaldAdapter()
    event = adapter.normalize(_raw({"priority": "5", "pid": "1234"}), _HOSTNAME, _AGENT_ID)
    assert event.pid == 1234


def test_inotify_null_paths_produce_empty_resource() -> None:
    """F08 fix: full_path=null and base_path=null must produce resource="" not "None"."""
    adapter = InotifyAdapter()
    event = adapter.normalize(_raw({"event_type": "create", "full_path": None, "base_path": None}), _HOSTNAME, _AGENT_ID)
    assert event.resource == ""


def test_netlink_ipv6_bare_address_no_brackets() -> None:
    """F16 fix: bare [::1] without port must strip brackets."""
    from oseye.normalizer.adapters.linux.netlink import _split_addr
    ip, port = _split_addr("[::1]")
    assert ip == "::1"
    assert port == 0


def test_fanotify_uses_agent_timestamp() -> None:
    """H10 fix: timestamp_ns must use the agent-side value from the payload."""
    adapter = FanotifyAdapter()
    agent_ts_value = 1_700_000_000_000_000_000
    event = adapter.normalize(
        _raw({"event_type": "open", "path": "/x", "timestamp_ns": agent_ts_value}),
        _HOSTNAME,
        _AGENT_ID,
    )
    assert event.timestamp_ns == agent_ts_value


@pytest.mark.asyncio
async def test_engine_invalid_agent_id_returns_none() -> None:
    """H8/F10 fix: engine must return None gracefully on bad agent_id."""
    bus = InMemoryEventBus()
    engine = NormalizerEngine(bus, _HOSTNAME)
    result = await engine.process(
        _raw({"event_type": "open", "path": "/tmp/x"}),
        source="fanotify",
        os_name="linux",
        agent_id="not-a-valid-uuid",
    )
    assert result is None


@pytest.mark.asyncio
async def test_engine_corrupted_json_returns_none() -> None:
    """C1/H9/F15 fix: engine must return None gracefully on invalid JSON payload."""
    bus = InMemoryEventBus()
    engine = NormalizerEngine(bus, _HOSTNAME)
    result = await engine.process(
        b"NOT JSON AT ALL",
        source="fanotify",
        os_name="linux",
        agent_id=_AGENT_ID,
    )
    assert result is None


@pytest.mark.asyncio
async def test_engine_adapter_exception_returns_none() -> None:
    """C1/F12 fix: any adapter exception must be caught; engine returns None."""
    bus = InMemoryEventBus()
    engine = NormalizerEngine(bus, _HOSTNAME)

    # Register a broken adapter that always raises.
    def _broken(_raw: bytes, _host: str, _aid: str) -> None:  # type: ignore[return]
        raise RuntimeError("simulated adapter crash")

    engine._adapters[("linux", "broken")] = _broken  # type: ignore[assignment]

    result = await engine.process(b"{}", source="broken", os_name="linux", agent_id=_AGENT_ID)
    assert result is None
