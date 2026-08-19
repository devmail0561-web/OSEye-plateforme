"""Tests for rule_type distinction anomaly/surveillance."""
from __future__ import annotations

import os

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")

import pytest

from oseye.rule_engine.models import RuleDefinition, RuleMatch


# ---------------------------------------------------------------------------
# RuleDefinition
# ---------------------------------------------------------------------------


def test_rule_definition_rule_type_defaults_to_anomaly() -> None:
    """RuleDefinition.rule_type defaults to 'anomaly'."""
    rule = RuleDefinition(
        id="r1",
        name="Test",
        enabled=True,
        severity="high",
        condition="event.category == 'process'",
        timeframe=None,
        threshold=None,
        actions=["ALERT"],
        tags=[],
        mitre=[],
        platforms=[],
        categories=[],
        explanation="",
        source="builtin",
    )
    assert rule.rule_type == "anomaly"


def test_rule_definition_rule_type_surveillance() -> None:
    """RuleDefinition accepts 'surveillance' rule_type."""
    rule = RuleDefinition(
        id="r2",
        name="Audit rule",
        enabled=True,
        severity="low",
        condition="event.category == 'file'",
        timeframe=None,
        threshold=None,
        actions=["ALERT"],
        tags=[],
        mitre=[],
        platforms=[],
        categories=[],
        explanation="",
        source="custom",
        rule_type="surveillance",
    )
    assert rule.rule_type == "surveillance"


# ---------------------------------------------------------------------------
# RuleMatch
# ---------------------------------------------------------------------------


def test_rule_match_rule_type_defaults_to_anomaly() -> None:
    """RuleMatch.rule_type defaults to 'anomaly'."""
    match = RuleMatch(
        rule_id="r1",
        rule_name="Test",
        severity="high",
        actions=["ALERT"],
        tags=[],
        mitre=[],
        explanation="",
    )
    assert match.rule_type == "anomaly"


def test_rule_match_rule_type_surveillance() -> None:
    """RuleMatch accepts 'surveillance'."""
    match = RuleMatch(
        rule_id="r2",
        rule_name="Audit",
        severity="low",
        actions=["ALERT"],
        tags=[],
        mitre=[],
        explanation="",
        rule_type="surveillance",
    )
    assert match.rule_type == "surveillance"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parser_reads_rule_type_from_yaml() -> None:
    """Parser extracts rule_type from YAML dict."""
    from oseye.rule_engine.parser import _parse_rule

    data = {
        "id": "test_surveillance",
        "name": "Audit access",
        "enabled": True,
        "severity": "low",
        "condition": "event.category == 'file'",
        "actions": ["ALERT"],
        "rule_type": "surveillance",
    }
    rule = _parse_rule(data, "custom")
    assert rule is not None
    assert rule.rule_type == "surveillance"


def test_parser_defaults_rule_type_to_anomaly() -> None:
    """Parser defaults rule_type to 'anomaly' when absent."""
    from oseye.rule_engine.parser import _parse_rule

    data = {
        "id": "test_default",
        "name": "Test",
        "severity": "high",
        "condition": "event.category == 'process'",
    }
    rule = _parse_rule(data, "builtin")
    assert rule is not None
    assert rule.rule_type == "anomaly"


def test_parser_invalid_rule_type_falls_back_to_anomaly() -> None:
    """Parser falls back to 'anomaly' for invalid rule_type values."""
    from oseye.rule_engine.parser import _parse_rule

    data = {
        "id": "test_bad_type",
        "name": "Bad",
        "severity": "low",
        "condition": "event.category == 'file'",
        "rule_type": "invalid_value",
    }
    rule = _parse_rule(data, "custom")
    assert rule is not None
    assert rule.rule_type == "anomaly"


# ---------------------------------------------------------------------------
# schema.Rule
# ---------------------------------------------------------------------------


def test_schema_rule_has_rule_type() -> None:
    """schema.Rule has rule_type field defaulting to 'anomaly'."""
    from oseye.core.schema import Rule

    rule = Rule(
        id="r1",
        name="Test",
        severity="high",
        condition_yaml="event.category == 'process'",
    )
    assert rule.rule_type == "anomaly"


def test_schema_rule_surveillance() -> None:
    """schema.Rule accepts 'surveillance'."""
    from oseye.core.schema import Rule

    rule = Rule(
        id="r2",
        name="Audit",
        severity="low",
        condition_yaml="event.category == 'file'",
        rule_type="surveillance",
    )
    assert rule.rule_type == "surveillance"


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------


def test_schema_alert_has_rule_type() -> None:
    """Alert has rule_type field."""
    from datetime import UTC, datetime
    from uuid import uuid4

    from oseye.core.schema import Alert

    alert = Alert(
        alert_id=uuid4(),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        severity="low",
        status="open",
        entity_id="host::proc",
        hostname="host",
        trigger_event_id=uuid4(),
        title="Audit event",
        rule_type="surveillance",
    )
    assert alert.rule_type == "surveillance"


def test_schema_alert_rule_type_defaults_to_anomaly() -> None:
    """Alert.rule_type defaults to 'anomaly'."""
    from datetime import UTC, datetime
    from uuid import uuid4

    from oseye.core.schema import Alert

    alert = Alert(
        alert_id=uuid4(),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        severity="high",
        status="open",
        entity_id="host::proc",
        hostname="host",
        trigger_event_id=uuid4(),
        title="Attack",
    )
    assert alert.rule_type == "anomaly"
