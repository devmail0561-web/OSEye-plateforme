"""Smoke tests: verify all schema models can be instantiated with minimal data."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from oseye.core.schema import (
    AgentInfo,
    Alert,
    AlertNote,
    CaseNote,
    CollectorConfig,
    CustodyEntry,
    Decision,
    EntityProfile,
    EvidenceItem,
    ForensicCase,
    Rule,
    SurveillanceProfile,
    UniversalEvent,
)

NOW = datetime.now(tz=timezone.utc)
UID = uuid4()


def make_event(**kwargs) -> UniversalEvent:
    defaults = dict(
        event_id=UID,
        timestamp_ns=1_000_000_000,
        hostname="test-host",
        agent_id=UID,
        category="process",
        type="exec",
        severity="info",
        collector="ebpf",
        hash_chain="a" * 64,
    )
    defaults.update(kwargs)
    return UniversalEvent(**defaults)


def test_universal_event_minimal():
    event = make_event()
    assert event.hostname == "test-host"
    assert event.category == "process"


def test_universal_event_all_categories():
    for cat in ("file", "process", "network", "user", "device"):
        e = make_event(category=cat)
        assert e.category == cat


def test_universal_event_network_fields():
    e = make_event(
        category="network",
        type="connect",
        src_ip="192.168.1.1",
        src_port=54321,
        dst_ip="8.8.8.8",
        dst_port=443,
        protocol="tcp",
        bytes_sent=1024,
        bytes_recv=2048,
    )
    assert e.dst_ip == "8.8.8.8"


def test_alert_minimal():
    alert = Alert(
        alert_id=uuid4(),
        created_at=NOW,
        updated_at=NOW,
        severity="high",
        status="open",
        entity_id="process:test-host:1234",
        hostname="test-host",
        trigger_event_id=UID,
        title="Test alert",
    )
    assert alert.status == "open"


def test_alert_note():
    note = AlertNote(
        note_id=uuid4(),
        created_at=NOW,
        author="analyst",
        content="Investigating",
    )
    assert note.author == "analyst"


def test_decision_minimal():
    d = Decision(
        decision_id=uuid4(),
        created_at=NOW,
        decision_type="ALERT",
        rule_score=0.8,
        ml_score=0.3,
        ti_score=0.1,
        correlation_depth=1,
        final_score=60.0,
        entity_id="process:test-host:1234",
        policy_version="v1",
        explanation="Rule matched",
        prev_journal_hash="b" * 64,
        journal_hash="c" * 64,
    )
    assert d.decision_type == "ALERT"
    assert d.requires_human is False


def test_decision_all_types():
    types = ["ALERT", "IGNORE", "ESCALATE", "INVESTIGATE",
             "ISOLATE", "REQUEST_HUMAN", "COLLECT_MORE", "NOTIFY"]
    for dt in types:
        d = Decision(
            decision_id=uuid4(),
            created_at=NOW,
            decision_type=dt,
            rule_score=0.0,
            ml_score=0.0,
            ti_score=0.0,
            correlation_depth=0,
            final_score=0.0,
            entity_id="e",
            policy_version="v1",
            explanation="",
            prev_journal_hash="0" * 64,
            journal_hash="1" * 64,
        )
        assert d.decision_type == dt


def test_forensic_case_minimal():
    case = ForensicCase(
        case_id=uuid4(),
        created_at=NOW,
        updated_at=NOW,
        title="Incident 2026-08-05",
        severity="high",
        status="open",
        created_by="analyst",
    )
    assert case.status == "open"
    assert case.custody_log == []


def test_custody_entry():
    entry = CustodyEntry(
        timestamp=NOW,
        operator="analyst",
        action="case_created",
        detail="Initial creation",
        hash="d" * 64,
    )
    assert entry.action == "case_created"


def test_evidence_item():
    item = EvidenceItem(
        evidence_id=uuid4(),
        type="event",
        content=str(uuid4()),
        added_by="analyst",
        added_at=NOW,
        marked_as_evidence_at=NOW,
    )
    assert item.type == "event"


def test_rule_minimal():
    rule = Rule(
        id="rule_shadow_read",
        name="Read /etc/shadow",
        severity="critical",
        condition_yaml='event.resource == "/etc/shadow"',
    )
    assert rule.enabled is True
    assert rule.false_positive_count == 0


def test_entity_profile():
    ep = EntityProfile(
        entity_id="process:test-host:bash",
        entity_type="process",
        hostname="test-host",
    )
    assert ep.risk_score == 0.0
    assert ep.whitelisted is False


def test_surveillance_profile():
    profile = SurveillanceProfile(
        name="workstation",
        version=1,
        collectors={
            "ebpf": CollectorConfig(enabled=True, throttle=1.0),
            "auditd": CollectorConfig(enabled=True, throttle=0.5),
        },
        created_at=NOW,
        updated_at=NOW,
    )
    assert "ebpf" in profile.collectors
    assert profile.collectors["ebpf"].enabled is True


def test_collector_config_defaults():
    cc = CollectorConfig()
    assert cc.enabled is True
    assert cc.throttle == 1.0
    assert cc.params == {}


def test_agent_info():
    ai = AgentInfo(
        agent_id=uuid4(),
        hostname="test-host",
        enrolled_at=NOW,
    )
    assert ai.revoked is False
    assert ai.online is False
