"""Unit tests for OSEye storage layer — SQLite in-memory backend."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from oseye.core.schema import (
    Alert,
    Decision,
    EvidenceItem,
    ForensicCase,
    UniversalEvent,
)
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.cases import SQLCaseRepository
from oseye.storage.repositories.decisions import SQLDecisionRepository
from oseye.storage.repositories.events import SQLEventRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class SimplePagination:
    limit: int
    offset: int


@dataclass
class SimpleEventFilter:
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
    agent_id: UUID | None = None
    incident_chain_id: UUID | None = None


def make_event(**overrides: Any) -> UniversalEvent:
    defaults: dict[str, Any] = {
        "event_id": uuid4(),
        "timestamp_ns": 1_700_000_000_000_000_000,
        "hostname": "test-host",
        "agent_id": uuid4(),
        "category": "process",
        "type": "exec",
        "severity": "low",
        "collector": "auditd",
    }
    defaults.update(overrides)
    return UniversalEvent(**defaults)


def make_alert(**overrides: Any) -> Alert:
    now = datetime.now(tz=UTC)
    defaults: dict[str, Any] = {
        "alert_id": uuid4(),
        "created_at": now,
        "updated_at": now,
        "severity": "medium",
        "status": "open",
        "entity_id": "proc:bash",
        "hostname": "test-host",
        "trigger_event_id": uuid4(),
        "title": "Suspicious exec",
    }
    defaults.update(overrides)
    return Alert(**defaults)


def make_decision(**overrides: Any) -> Decision:
    now = datetime.now(tz=UTC)
    defaults: dict[str, Any] = {
        "decision_id": uuid4(),
        "created_at": now,
        "decision_type": "ALERT",
        "rule_score": 0.8,
        "ml_score": 0.5,
        "ti_score": 0.3,
        "correlation_depth": 1,
        "final_score": 0.7,
        "entity_id": "proc:bash",
        "policy_version": "v1",
        "explanation": "Rule triggered",
        "prev_journal_hash": "0" * 64,
        "journal_hash": "a" * 64,
    }
    defaults.update(overrides)
    return Decision(**defaults)


def make_case(**overrides: Any) -> ForensicCase:
    now = datetime.now(tz=UTC)
    defaults: dict[str, Any] = {
        "case_id": uuid4(),
        "created_at": now,
        "updated_at": now,
        "title": "Test Case",
        "severity": "high",
        "status": "open",
        "created_by": "analyst1",
    }
    defaults.update(overrides)
    return ForensicCase(**defaults)


async def _make_backend() -> SQLiteBackend:
    backend = SQLiteBackend("sqlite+aiosqlite:///:memory:")
    await backend.init()
    return backend


# ---------------------------------------------------------------------------
# Event tests
# ---------------------------------------------------------------------------

async def test_event_insert_and_get() -> None:
    backend = await _make_backend()
    repo = SQLEventRepository(backend.session_factory)
    event = make_event()
    await repo.insert_batch([event])
    fetched = await repo.get(event.event_id)
    assert fetched is not None
    assert fetched.event_id == event.event_id
    assert fetched.hostname == event.hostname
    assert fetched.category == event.category


async def test_event_query_by_category() -> None:
    backend = await _make_backend()
    repo = SQLEventRepository(backend.session_factory)
    agent_id = uuid4()
    e1 = make_event(category="process", agent_id=agent_id)
    e2 = make_event(category="network", agent_id=agent_id)
    e3 = make_event(category="process", agent_id=agent_id)
    await repo.insert_batch([e1, e2, e3])

    filters = SimpleEventFilter(category="process")
    page = await repo.query(filters, SimplePagination(limit=10, offset=0))
    assert page.total == 2
    ids = {item.event_id for item in page.items}
    assert e1.event_id in ids
    assert e3.event_id in ids
    assert e2.event_id not in ids


async def test_event_pagination() -> None:
    backend = await _make_backend()
    repo = SQLEventRepository(backend.session_factory)
    events = [make_event() for _ in range(5)]
    await repo.insert_batch(events)

    filters = SimpleEventFilter()
    page_a = await repo.query(filters, SimplePagination(limit=3, offset=0))
    page_b = await repo.query(filters, SimplePagination(limit=3, offset=3))

    assert page_a.total == 5
    assert len(page_a.items) == 3
    assert page_b.total == 5
    assert len(page_b.items) == 2


async def test_event_count() -> None:
    backend = await _make_backend()
    repo = SQLEventRepository(backend.session_factory)
    events = [make_event(severity="high") for _ in range(3)]
    events += [make_event(severity="low")]
    await repo.insert_batch(events)
    count = await repo.count(SimpleEventFilter(severity="high"))
    assert count == 3


# ---------------------------------------------------------------------------
# Alert tests
# ---------------------------------------------------------------------------

async def test_alert_create_and_get() -> None:
    backend = await _make_backend()
    repo = SQLAlertRepository(backend.session_factory)
    alert = make_alert()
    await repo.create(alert)
    fetched = await repo.get(alert.alert_id)
    assert fetched is not None
    assert fetched.alert_id == alert.alert_id
    assert fetched.title == alert.title
    assert fetched.status == "open"


async def test_alert_update() -> None:
    backend = await _make_backend()
    repo = SQLAlertRepository(backend.session_factory)
    alert = make_alert()
    await repo.create(alert)
    alert.status = "resolved"  # type: ignore[assignment]
    await repo.update(alert)
    fetched = await repo.get(alert.alert_id)
    assert fetched is not None
    assert fetched.status == "resolved"


async def test_alert_list_and_count() -> None:
    backend = await _make_backend()
    repo = SQLAlertRepository(backend.session_factory)
    for _ in range(3):
        await repo.create(make_alert(status="open"))
    await repo.create(make_alert(status="resolved"))

    page = await repo.list({"status": "open"}, SimplePagination(limit=10, offset=0))
    assert page.total == 3
    count = await repo.count({"status": "open"})
    assert count == 3


# ---------------------------------------------------------------------------
# Decision tests
# ---------------------------------------------------------------------------

async def test_decision_create_and_get() -> None:
    backend = await _make_backend()
    repo = SQLDecisionRepository(backend.session_factory)
    decision = make_decision()
    await repo.create(decision)
    fetched = await repo.get(decision.decision_id)
    assert fetched is not None
    assert fetched.decision_id == decision.decision_id
    assert fetched.decision_type == "ALERT"
    assert fetched.journal_hash == decision.journal_hash


async def test_decision_list_decisions() -> None:
    backend = await _make_backend()
    repo = SQLDecisionRepository(backend.session_factory)
    for _ in range(4):
        await repo.create(make_decision())
    page = await repo.list_decisions({}, SimplePagination(limit=2, offset=0))
    assert page.total == 4
    assert len(page.items) == 2


async def test_decision_get_pending() -> None:
    backend = await _make_backend()
    repo = SQLDecisionRepository(backend.session_factory)
    d_pending = make_decision(requires_human=True, human_decision=None)
    d_approved = make_decision(requires_human=True, human_decision="approved")
    d_normal = make_decision(requires_human=False)
    await repo.create(d_pending)
    await repo.create(d_approved)
    await repo.create(d_normal)
    pending = await repo.get_pending()
    assert len(pending) == 1
    assert pending[0].decision_id == d_pending.decision_id


async def test_decision_immutable_sqlite() -> None:
    """SQLDecisionRepository never issues UPDATE or DELETE on decisions.

    This test verifies the application-layer guarantee: create() only uses
    session.add() (INSERT), and there are no update/delete methods exposed.
    PostgreSQL triggers (SEC-0002) provide the database-layer guarantee.
    """
    backend = await _make_backend()
    repo = SQLDecisionRepository(backend.session_factory)
    decision = make_decision()
    await repo.create(decision)

    # Verify no update/delete methods exist on the repository
    assert not hasattr(repo, "update"), "DecisionRepository must not expose update()"
    assert not hasattr(repo, "delete"), "DecisionRepository must not expose delete()"

    # Verify the record is intact after creation (no accidental mutation)
    fetched = await repo.get(decision.decision_id)
    assert fetched is not None
    assert fetched.journal_hash == decision.journal_hash
    assert fetched.prev_journal_hash == decision.prev_journal_hash


# ---------------------------------------------------------------------------
# Case tests
# ---------------------------------------------------------------------------

async def test_case_create_and_get() -> None:
    backend = await _make_backend()
    repo = SQLCaseRepository(backend.session_factory)
    case = make_case()
    await repo.create(case)
    fetched = await repo.get(case.case_id)
    assert fetched is not None
    assert fetched.case_id == case.case_id
    assert fetched.title == case.title
    assert fetched.status == "open"


async def test_case_create_and_append_custody() -> None:
    backend = await _make_backend()
    repo = SQLCaseRepository(backend.session_factory)
    case = make_case()
    await repo.create(case)

    entry = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "operator": "analyst1",
        "action": "evidence_added",
        "detail": "Added network capture",
        "hash": "b" * 64,
    }
    await repo.append_custody(case.case_id, entry)

    fetched = await repo.get(case.case_id)
    assert fetched is not None
    assert len(fetched.custody_log) == 1
    assert fetched.custody_log[0].operator == "analyst1"
    assert fetched.custody_log[0].action == "evidence_added"


async def test_case_custody_append_multiple() -> None:
    backend = await _make_backend()
    repo = SQLCaseRepository(backend.session_factory)
    case = make_case()
    await repo.create(case)

    for i in range(3):
        await repo.append_custody(
            case.case_id,
            {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "operator": f"op{i}",
                "action": "step",
                "detail": f"step {i}",
                "hash": hex(i)[2:].zfill(64),
            },
        )

    fetched = await repo.get(case.case_id)
    assert fetched is not None
    assert len(fetched.custody_log) == 3


async def test_case_with_evidence() -> None:
    backend = await _make_backend()
    repo = SQLCaseRepository(backend.session_factory)
    now = datetime.now(tz=UTC)
    ev = EvidenceItem(
        evidence_id=uuid4(),
        type="note",
        content="suspicious binary found",
        added_by="analyst1",
        added_at=now,
        marked_as_evidence_at=now,
    )
    case = make_case(evidence=[ev])
    await repo.create(case)
    fetched = await repo.get(case.case_id)
    assert fetched is not None
    assert len(fetched.evidence) == 1
    assert fetched.evidence[0].evidence_id == ev.evidence_id


async def test_case_list() -> None:
    backend = await _make_backend()
    repo = SQLCaseRepository(backend.session_factory)
    for _ in range(3):
        await repo.create(make_case(status="open"))
    await repo.create(make_case(status="resolved"))

    page = await repo.list({"status": "open"}, SimplePagination(limit=10, offset=0))
    assert page.total == 3
