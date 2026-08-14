"""Integration tests for Phase 2 normalizer adapters.

Each test feeds a representative raw JSON payload (as produced by the
corresponding Go collector) through the adapter and verifies the resulting
UniversalEvent has correct category, type, and required fields.
"""

from __future__ import annotations

import json
import uuid

import pytest

from oseye.normalizer.adapters.linux.fanotify import FanotifyAdapter
from oseye.normalizer.adapters.linux.inotify import InotifyAdapter
from oseye.normalizer.adapters.linux.journald import JournaldAdapter
from oseye.normalizer.adapters.linux.netlink import NetlinkAdapter
from oseye.normalizer.adapters.linux.syslog import SyslogAdapter
from oseye.normalizer.adapters.linux.udev import UdevAdapter

_HOSTNAME = "test-host"
_AGENT_ID = str(uuid.uuid4())


def _raw(data: dict) -> bytes:
    return json.dumps(data).encode()


# ── Fanotify ──────────────────────────────────────────────────────────────────

class TestFanotifyAdapter:
    def setup_method(self) -> None:
        self.adapter = FanotifyAdapter()

    def test_file_modify(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "fanotify",
            "pid": 1234,
            "path": "/etc/passwd",
            "event_type": "modify",
            "timestamp_ns": 1_700_000_000_000_000_000,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "file"
        assert ev.hostname == _HOSTNAME
        assert str(ev.agent_id) == _AGENT_ID
        assert ev.timestamp_ns == 1_700_000_000_000_000_000

    def test_file_access(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "fanotify",
            "pid": 42,
            "path": "/etc/shadow",
            "event_type": "access",
            "timestamp_ns": 0,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "file"
        assert ev.pid == 42

    def test_missing_pid_defaults_zero(self) -> None:
        raw = _raw({"os": "linux", "source": "fanotify", "path": "/tmp/x", "event_type": "create"})
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.pid == 0


# ── Inotify ───────────────────────────────────────────────────────────────────

class TestInotifyAdapter:
    def setup_method(self) -> None:
        self.adapter = InotifyAdapter()

    def test_file_create(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "inotify",
            "mask": 256,  # IN_CREATE
            "name": "evil.sh",
            "watch_path": "/tmp",
            "timestamp_ns": 1_700_000_000_000_000_001,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "file"
        assert ev.hostname == _HOSTNAME

    def test_file_delete(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "inotify",
            "mask": 512,  # IN_DELETE
            "name": "gone.txt",
            "watch_path": "/home/user",
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "file"


# ── Netlink ───────────────────────────────────────────────────────────────────

class TestNetlinkAdapter:
    def setup_method(self) -> None:
        self.adapter = NetlinkAdapter()

    def test_tcp_established(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "netlink",
            "local_addr": "192.168.1.10",
            "local_port": 54321,
            "remote_addr": "8.8.8.8",
            "remote_port": 443,
            "state": "ESTABLISHED",
            "protocol": "tcp",
            "timestamp_ns": 1_700_000_000_000_000_002,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "network"
        assert ev.hostname == _HOSTNAME

    def test_udp_connection(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "netlink",
            "local_addr": "0.0.0.0",
            "local_port": 514,
            "remote_addr": "10.0.0.1",
            "remote_port": 514,
            "state": "CLOSE",
            "protocol": "udp",
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "network"


# ── Journald ──────────────────────────────────────────────────────────────────

class TestJournaldAdapter:
    def setup_method(self) -> None:
        self.adapter = JournaldAdapter()

    def test_systemd_unit_log(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "journald",
            "unit": "sshd.service",
            "message": "Failed password for root from 1.2.3.4 port 22 ssh2",
            "priority": 3,
            "timestamp_ns": 1_700_000_000_000_000_003,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "log"
        assert ev.hostname == _HOSTNAME

    def test_empty_unit(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "journald",
            "message": "kernel: OOM killer invoked",
            "priority": 2,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "log"


# ── Udev ──────────────────────────────────────────────────────────────────────

class TestUdevAdapter:
    def setup_method(self) -> None:
        self.adapter = UdevAdapter()

    def test_usb_add(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "udev",
            "action": "add",
            "devpath": "/devices/pci0000:00/usb1/1-1",
            "subsystem": "usb",
            "devtype": "usb_device",
            "timestamp_ns": 1_700_000_000_000_000_004,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "device"
        assert ev.hostname == _HOSTNAME

    def test_block_remove(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "udev",
            "action": "remove",
            "devpath": "/devices/pci0000:00/sda",
            "subsystem": "block",
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "device"


# ── Syslog ────────────────────────────────────────────────────────────────────

class TestSyslogAdapter:
    def setup_method(self) -> None:
        self.adapter = SyslogAdapter()

    def test_rfc3164(self) -> None:
        raw = _raw({
            "os": "linux",
            "source": "syslog",
            "facility": 1,
            "severity": 3,
            "hostname": "myhost",
            "message": "su: pam_unix(su:auth): authentication failure",
            "timestamp_ns": 1_700_000_000_000_000_005,
        })
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "log"
        assert ev.hostname == _HOSTNAME

    def test_minimal_payload(self) -> None:
        raw = _raw({"os": "linux", "source": "syslog", "message": "test message"})
        ev = self.adapter.normalize(raw, _HOSTNAME, _AGENT_ID)
        assert ev.category == "log"
