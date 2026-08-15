"""Tests for Windows + macOS normalizer adapters."""

from __future__ import annotations

import json
import uuid


def _raw(data: dict) -> bytes:
    return json.dumps(data).encode()


_HOSTNAME = "test-host"
_AGENT_ID = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

class TestToolhelp32Adapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.windows.toolhelp32 import Toolhelp32Adapter
        self.adapter = Toolhelp32Adapter()

    def test_basic(self) -> None:
        ev = self.adapter.normalize(
            _raw({"pid": 1234, "ppid": 1, "name": "notepad.exe", "threads": 4}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.category == "process"
        assert ev.type == "snapshot"
        assert ev.pid == 1234
        assert ev.ppid == 1
        assert ev.process_name == "notepad.exe"
        assert ev.os == "windows"
        assert ev.collector == "toolhelp32"

    def test_missing_fields_default(self) -> None:
        ev = self.adapter.normalize(_raw({}), _HOSTNAME, _AGENT_ID)
        assert ev.pid == 0
        assert ev.ppid == 0
        assert ev.process_name == ""


class TestEtwAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.windows.etw import EtwAdapter
        self.adapter = EtwAdapter()

    def test_process_create(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "process_create", "pid": 5678, "provider": "Kernel-Process"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.category == "process"
        assert ev.severity == "info"
        assert ev.pid == 5678

    def test_logon_failure(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "logon_failure"}), _HOSTNAME, _AGENT_ID,
        )
        assert ev.category == "user"
        assert ev.severity == "medium"

    def test_service_installed(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "service_installed"}), _HOSTNAME, _AGENT_ID,
        )
        assert ev.category == "audit"
        assert ev.severity == "high"

    def test_unknown_event_defaults_to_audit(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "something_unknown"}), _HOSTNAME, _AGENT_ID,
        )
        # Unknown events default to "audit", not "process"
        assert ev.category == "audit"
        assert ev.severity == "info"

    def test_resource_truncated(self) -> None:
        long_msg = "x" * 600
        ev = self.adapter.normalize(
            _raw({"event_type": "event", "Message": long_msg}), _HOSTNAME, _AGENT_ID,
        )
        assert len(ev.resource) <= 515  # 512 + "…"


class TestRegistryAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.windows.registry import RegistryAdapter
        self.adapter = RegistryAdapter()

    def test_run_key_is_high(self) -> None:
        ev = self.adapter.normalize(
            _raw({"hive": "HKLM", "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                  "event_type": "key_changed"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "high"
        assert ev.category == "audit"

    def test_runonce_key_is_high(self) -> None:
        ev = self.adapter.normalize(
            _raw({"hive": "HKCU", "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                  "event_type": "key_changed"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "high"

    def test_no_false_positive_runner(self) -> None:
        """A key path containing 'Runner' should NOT match 'Run' component."""
        ev = self.adapter.normalize(
            _raw({"hive": "HKLM", "key_path": r"SOFTWARE\MyApp\TaskRunner",
                  "event_type": "key_changed"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "medium"  # not high

    def test_non_persistence_key_is_medium(self) -> None:
        ev = self.adapter.normalize(
            _raw({"hive": "HKLM", "key_path": r"SOFTWARE\7-Zip",
                  "event_type": "key_changed"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "medium"

    def test_resource_combines_hive_and_path(self) -> None:
        ev = self.adapter.normalize(
            _raw({"hive": "HKLM", "key_path": r"SOFTWARE\Test"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.resource == r"HKLM\SOFTWARE\Test"


class TestEventlogAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.windows.eventlog import EventlogAdapter
        self.adapter = EventlogAdapter()

    def test_error_is_high(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "error", "source": "System"}), _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "high"
        assert ev.category == "log"
        assert ev.resource == "System"

    def test_audit_failure_is_high(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "audit_failure"}), _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "high"

    def test_information_is_info(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "information"}), _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "info"


class TestFswatchAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.windows.fswatch import FswatchAdapter
        self.adapter = FswatchAdapter()

    def test_basic_create(self) -> None:
        ev = self.adapter.normalize(
            _raw({"path": r"C:\Users\bob", "name": "evil.bat", "event_type": "create"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.category == "file"
        assert ev.type == "create"
        assert "evil.bat" in ev.resource

    def test_no_double_backslash(self) -> None:
        """Trailing backslash on path must not produce double backslash."""
        ev = self.adapter.normalize(
            _raw({"path": r"C:\Users\bob\\", "name": "file.txt", "event_type": "modify"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert "\\\\" not in ev.resource

    def test_system32_delete_is_high(self) -> None:
        ev = self.adapter.normalize(
            _raw({"path": r"C:\Windows\System32", "name": "cmd.exe", "event_type": "delete"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "high"

    def test_no_name_uses_path_only(self) -> None:
        ev = self.adapter.normalize(
            _raw({"path": r"C:\Temp", "name": "", "event_type": "modify"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.resource == r"C:\Temp"


class TestWinnetstatAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.windows.winnetstat import WinnetstatAdapter
        self.adapter = WinnetstatAdapter()

    def test_external_connection_is_low(self) -> None:
        ev = self.adapter.normalize(
            _raw({"local_addr": "192.168.1.5", "local_port": 12345,
                  "remote_addr": "8.8.8.8", "remote_port": 443,
                  "state": "ESTABLISHED", "proto": "tcp", "pid": 999}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "low"
        assert ev.category == "network"
        assert ev.dst_ip == "8.8.8.8"
        assert ev.dst_port == 443
        assert ev.pid == 999

    def test_loopback_is_info(self) -> None:
        ev = self.adapter.normalize(
            _raw({"local_addr": "127.0.0.1", "local_port": 5432,
                  "remote_addr": "127.0.0.1", "remote_port": 5432,
                  "state": "LISTEN", "proto": "tcp"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "info"


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

class TestPsAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.darwin.ps import PsAdapter
        self.adapter = PsAdapter()

    def test_basic(self) -> None:
        ev = self.adapter.normalize(
            _raw({"pid": 42, "ppid": 1, "uid": 501, "name": "bash"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.category == "process"
        assert ev.pid == 42
        assert ev.uid == 501
        assert ev.process_name == "bash"
        assert ev.os == "darwin"

    def test_process_name_not_masked(self) -> None:
        """Process names containing 'password' or 'token' must NOT be redacted."""
        ev = self.adapter.normalize(
            _raw({"pid": 1, "ppid": 0, "uid": 0, "name": "PasswordVault"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.process_name == "PasswordVault"
        assert "***" not in ev.process_name


class TestKqueueAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.darwin.kqueue import KqueueAdapter
        self.adapter = KqueueAdapter()

    def test_write_is_low(self) -> None:
        ev = self.adapter.normalize(
            _raw({"path": "/home/user/doc.txt", "event_type": "write"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "low"
        assert ev.category == "file"

    def test_sensitive_delete_is_high(self) -> None:
        ev = self.adapter.normalize(
            _raw({"path": "/etc/hosts", "event_type": "delete"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "high"

    def test_launchdaemons_write_is_medium(self) -> None:
        ev = self.adapter.normalize(
            _raw({"path": "/Library/LaunchDaemons/com.evil.plist", "event_type": "write"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "medium"


class TestUnifiedlogAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.darwin.unifiedlog import UnifiedlogAdapter
        self.adapter = UnifiedlogAdapter()

    def test_error_is_high(self) -> None:
        ev = self.adapter.normalize(
            _raw({"process": "kernel", "level": "error", "message": "panic", "pid": 0}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "high"
        assert ev.category == "log"

    def test_sudo_info_elevated_to_medium(self) -> None:
        ev = self.adapter.normalize(
            _raw({"process": "sudo", "level": "info", "message": "user ran command", "pid": 100}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "medium"

    def test_regular_info_stays_info(self) -> None:
        ev = self.adapter.normalize(
            _raw({"process": "mdworker", "level": "info", "message": "indexing", "pid": 200}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "info"

    def test_message_truncated(self) -> None:
        ev = self.adapter.normalize(
            _raw({"process": "kernel", "level": "info", "message": "x" * 600}),
            _HOSTNAME, _AGENT_ID,
        )
        assert len(ev.resource) <= 512


class TestDarwinnetAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.darwin.darwinnet import DarwinnetAdapter
        self.adapter = DarwinnetAdapter()

    def test_external_is_low(self) -> None:
        ev = self.adapter.normalize(
            _raw({"local_addr": "192.168.1.2", "local_port": 54321,
                  "remote_addr": "1.1.1.1", "remote_port": 443,
                  "state": "ESTABLISHED", "proto": "tcp"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "low"
        assert ev.dst_ip == "1.1.1.1"

    def test_wildcard_remote_is_info(self) -> None:
        ev = self.adapter.normalize(
            _raw({"local_addr": "0.0.0.0", "local_port": 8080,
                  "remote_addr": "*", "remote_port": 0,
                  "state": "LISTEN", "proto": "tcp"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.severity == "info"


class TestEsAdapter:
    def setup_method(self) -> None:
        from oseye.normalizer.adapters.darwin.es import EsAdapter
        self.adapter = EsAdapter()

    def test_status_event(self) -> None:
        ev = self.adapter.normalize(
            _raw({"event_type": "collector_status", "available": False,
                  "message": "EndpointSecurity requires entitlement"}),
            _HOSTNAME, _AGENT_ID,
        )
        assert ev.category == "audit"
        assert ev.type == "collector_status"
        assert ev.severity == "info"
        assert ev.os == "darwin"

    def test_no_dead_code_branch(self) -> None:
        """Both available=True and available=False must yield info severity."""
        ev1 = self.adapter.normalize(
            _raw({"event_type": "es_event", "available": True}), _HOSTNAME, _AGENT_ID,
        )
        ev2 = self.adapter.normalize(
            _raw({"event_type": "es_event", "available": False}), _HOSTNAME, _AGENT_ID,
        )
        assert ev1.severity == ev2.severity == "info"
