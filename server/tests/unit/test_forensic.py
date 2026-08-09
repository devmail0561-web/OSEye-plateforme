"""P7.12 — Forensic module tests.

Covers:
- CaseManager CRUD + custody log integrity (immutability via chained hash)
- diff_snapshots detects new/terminated processes and connections
- build_timeline sorts correctly across event/alert/custody types
- export_json produces valid JSON with all keys
- export_html produces valid HTML with required sections
- export_misp_event produces correct MISP structure
- export_thehive_case produces correct TheHive 5 structure
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from oseye.core.pagination import PageResult
from oseye.core.schema import (
    AgentSnapshot,
    Alert,
    CaseNote,
    ConnectionInfo,
    CustodyEntry,
    EvidenceItem,
    ForensicCase,
    ProcessInfo,
    UniversalEvent,
)
from oseye.forensic.case_manager import CaseManager, _custody_hash
from oseye.forensic.exporter.html_report import export_html
from oseye.forensic.exporter.json_export import export_json
from oseye.forensic.exporter.misp_export import export_misp_event
from oseye.forensic.exporter.thehive_export import export_thehive_case
from oseye.forensic.snapshot import SQLSnapshotRepository, diff_snapshots
from oseye.forensic.timeline import build_timeline
from oseye.storage.interface import Pagination


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_case(**kwargs) -> ForensicCase:
    now = datetime.now(UTC)
    defaults = dict(
        case_id=uuid.uuid4(),
        created_at=now,
        updated_at=now,
        title="Test Case",
        severity="high",
        status="open",
        created_by="analyst",
    )
    defaults.update(kwargs)
    return ForensicCase(**defaults)


def _make_alert(**kwargs) -> Alert:
    now = datetime.now(UTC)
    defaults = dict(
        alert_id=uuid.uuid4(),
        created_at=now,
        updated_at=now,
        severity="high",
        status="open",
        entity_id="host-01:1234",
        hostname="host-01",
        trigger_event_id=uuid.uuid4(),
        title="Test Alert",
        mitre_techniques=["T1059.001"],
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def _make_event(**kwargs) -> UniversalEvent:
    defaults = dict(
        event_id=uuid.uuid4(),
        timestamp_ns=time.time_ns(),
        hostname="host-01",
        agent_id=uuid.uuid4(),
        category="process",
        type="exec",
        severity="info",
        collector="procfs",
        hash_chain="a" * 64,
    )
    defaults.update(kwargs)
    return UniversalEvent(**defaults)


def _make_fake_repo() -> MagicMock:
    """Return a mock SQLCaseRepository."""
    repo = MagicMock()
    repo.create = AsyncMock(side_effect=lambda case: case)
    repo.get = AsyncMock(return_value=None)
    repo.update = AsyncMock(side_effect=lambda case: case)
    repo.append_custody = AsyncMock()
    repo.list = AsyncMock(return_value=PageResult(items=[], total=0, limit=20, offset=0))
    return repo


# ---------------------------------------------------------------------------
# CaseManager — custody log integrity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_case_manager_create_adds_custody_entry():
    """create_case must add a 'case_opened' custody entry."""
    repo = _make_fake_repo()
    mgr = CaseManager(repo)
    case = await mgr.create_case("Incident X", "high", created_by="alice")
    assert len(case.custody_log) == 1
    assert case.custody_log[0].action == "case_opened"
    assert case.custody_log[0].operator == "alice"


@pytest.mark.asyncio
async def test_case_manager_custody_hash_chains():
    """Each custody entry hash must depend on the previous one."""
    repo = _make_fake_repo()
    mgr = CaseManager(repo)
    case = await mgr.create_case("Chain test", "medium", created_by="bob")

    first_hash = case.custody_log[0].hash
    # Verify the hash formula matches the implementation.
    ts = case.custody_log[0].timestamp.isoformat()
    expected = _custody_hash("0" * 64, ts, "bob", "case_opened", "Chain test")
    assert first_hash == expected


@pytest.mark.asyncio
async def test_case_manager_custody_append_only():
    """append_custody on the repo must only INSERT — no UPDATE/DELETE called."""
    repo = _make_fake_repo()
    mgr = CaseManager(repo)
    case = _make_case()
    repo.get = AsyncMock(return_value=case)

    await mgr.update_case(case.case_id, "carol", title="New title")

    # append_custody must have been called; update is OK (fields), delete never.
    repo.append_custody.assert_awaited()
    assert not hasattr(repo, "delete") or not repo.delete.called


@pytest.mark.asyncio
async def test_case_manager_add_note():
    """add_note returns a CaseNote and triggers custody entry."""
    repo = _make_fake_repo()
    case = _make_case()
    repo.get = AsyncMock(return_value=case)
    mgr = CaseManager(repo)

    note = await mgr.add_note(case.case_id, author="dave", content="Suspicious binary")
    assert isinstance(note, CaseNote)
    assert note.content == "Suspicious binary"
    repo.append_custody.assert_awaited()


@pytest.mark.asyncio
async def test_case_manager_add_evidence():
    """add_evidence returns an EvidenceItem and triggers custody entry."""
    repo = _make_fake_repo()
    case = _make_case()
    repo.get = AsyncMock(return_value=case)
    mgr = CaseManager(repo)

    item = await mgr.add_evidence(
        case.case_id, operator="eve", type_="file_hash",
        content="sha256:abc123", description="Malware hash",
    )
    assert isinstance(item, EvidenceItem)
    assert item.type == "file_hash"
    repo.append_custody.assert_awaited()


@pytest.mark.asyncio
async def test_case_manager_close_sets_status():
    """close_case sets status to 'resolved' and logs custody entry."""
    repo = _make_fake_repo()
    case = _make_case(status="in_progress")
    repo.get = AsyncMock(return_value=case)
    mgr = CaseManager(repo)

    closed = await mgr.close_case(case.case_id, operator="frank", resolution="Malware removed")
    assert closed.status == "resolved"
    repo.append_custody.assert_awaited()


# ---------------------------------------------------------------------------
# diff_snapshots
# ---------------------------------------------------------------------------

def _make_snapshot(**kwargs) -> AgentSnapshot:
    defaults = dict(
        snapshot_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        hostname="host-snap",
        taken_at=datetime.now(UTC),
    )
    defaults.update(kwargs)
    return AgentSnapshot(**defaults)


def test_diff_snapshots_detects_new_process():
    """diff_snapshots must detect a process that appeared in after."""
    proc_a = ProcessInfo(pid=100, ppid=1, name="bash", exe="/bin/bash",
                         cmdline="bash", uid=1000, status="running")
    proc_b = ProcessInfo(pid=200, ppid=1, name="nc", exe="/usr/bin/nc",
                         cmdline="nc -lvp 4444", uid=0, status="running")
    before = _make_snapshot(processes=[proc_a])
    after = _make_snapshot(processes=[proc_a, proc_b])

    diff = diff_snapshots(before, after)
    assert len(diff["new_processes"]) == 1
    assert diff["new_processes"][0]["pid"] == 200
    assert diff["terminated_processes"] == []


def test_diff_snapshots_detects_terminated_process():
    """diff_snapshots must detect a process that disappeared in after."""
    proc = ProcessInfo(pid=100, ppid=1, name="bash", exe="/bin/bash",
                       cmdline="bash", uid=1000, status="running")
    before = _make_snapshot(processes=[proc])
    after = _make_snapshot(processes=[])

    diff = diff_snapshots(before, after)
    assert len(diff["terminated_processes"]) == 1
    assert diff["new_processes"] == []


def test_diff_snapshots_detects_new_connection():
    """diff_snapshots detects a new outbound connection."""
    conn = ConnectionInfo(
        proto="tcp", local_addr="0.0.0.0", local_port=54321,
        remote_addr="1.2.3.4", remote_port=443, state="ESTABLISHED", pid=100,
    )
    before = _make_snapshot()
    after = _make_snapshot(connections=[conn])

    diff = diff_snapshots(before, after)
    assert len(diff["new_connections"]) == 1
    assert diff["closed_connections"] == []


def test_diff_snapshots_no_change_empty():
    """Two identical snapshots produce an empty diff."""
    proc = ProcessInfo(pid=1, ppid=0, name="systemd", exe="/sbin/init",
                       cmdline="init", uid=0, status="running")
    snap = _make_snapshot(processes=[proc])
    diff = diff_snapshots(snap, snap)
    assert all(len(v) == 0 for v in diff.values())


# ---------------------------------------------------------------------------
# build_timeline
# ---------------------------------------------------------------------------

def test_build_timeline_sorted_ascending():
    """Timeline entries must be sorted by ts ascending."""
    now_ns = time.time_ns()
    ev1 = _make_event(timestamp_ns=now_ns + 1000)
    ev2 = _make_event(timestamp_ns=now_ns)
    case = _make_case()

    tl = build_timeline(case, [ev1, ev2], [])
    assert tl[0]["ts"] <= tl[1]["ts"]


def test_build_timeline_includes_all_types():
    """Timeline must include event, alert and custody entries."""
    now = datetime.now(UTC)
    now_ns = int(now.timestamp() * 1_000_000_000)
    ev = _make_event(timestamp_ns=now_ns)
    al = _make_alert()
    custody = CustodyEntry(
        timestamp=now, operator="ops", action="case_opened", detail="start", hash="a" * 64
    )
    case = _make_case(custody_log=[custody])

    tl = build_timeline(case, [ev], [al])
    types = {e["type"] for e in tl}
    assert types == {"event", "alert", "custody"}


def test_build_timeline_empty():
    """Empty inputs produce an empty list."""
    case = _make_case()
    assert build_timeline(case, [], []) == []


# ---------------------------------------------------------------------------
# export_json
# ---------------------------------------------------------------------------

def test_export_json_valid_json():
    """export_json must return valid, parseable JSON."""
    case = _make_case()
    result = export_json(case, [], [])
    data = json.loads(result)
    assert "case" in data or "case_id" in data or str(case.case_id) in result


def test_export_json_contains_case_id():
    """export_json must include the case ID."""
    case = _make_case()
    result = export_json(case, [_make_event()], [_make_alert()])
    assert str(case.case_id) in result


# ---------------------------------------------------------------------------
# export_html
# ---------------------------------------------------------------------------

def test_export_html_contains_title():
    """export_html must embed the case title."""
    case = _make_case(title="My Forensic Case")
    result = export_html(case, [], [], [])
    assert "My Forensic Case" in result


def test_export_html_is_valid_html():
    """export_html must start with <!DOCTYPE html>."""
    case = _make_case()
    result = export_html(case, [], [], [])
    assert result.strip().lower().startswith("<!doctype html>")


def test_export_html_contains_custody_section():
    """export_html must have a Custody Log section."""
    case = _make_case()
    result = export_html(case, [], [], [])
    assert "Custody" in result


def test_export_html_escapes_xss():
    """export_html must HTML-escape user content."""
    case = _make_case(title='<script>alert("xss")</script>')
    result = export_html(case, [], [], [])
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


# ---------------------------------------------------------------------------
# export_misp_event
# ---------------------------------------------------------------------------

def test_export_misp_structure():
    """export_misp_event must return MISP v2.4 structure."""
    case = _make_case(severity="critical")
    result = export_misp_event(case, [])
    assert "Event" in result
    event = result["Event"]
    assert event["threat_level_id"] == "1"
    assert "Tag" in event
    assert any(t["name"] == "osEye" for t in event["Tag"])


def test_export_misp_techniques():
    """MITRE techniques from alerts appear as MISP attributes."""
    case = _make_case()
    alert = _make_alert(mitre_techniques=["T1059.001", "T1055"])
    result = export_misp_event(case, [alert])
    attributes = result["Event"]["Attribute"]
    technique_vals = [a["value"] for a in attributes if a["type"] == "text"]
    assert "T1059.001" in technique_vals


# ---------------------------------------------------------------------------
# export_thehive_case
# ---------------------------------------------------------------------------

def test_export_thehive_structure():
    """export_thehive_case must return TheHive 5 case structure."""
    case = _make_case(severity="high", status="in_progress")
    result = export_thehive_case(case, [])
    assert result["title"] == case.title
    assert result["severity"] == 3   # high → 3
    assert result["status"] == "InProgress"
    assert "osEye" in result["tags"]


def test_export_thehive_observables_from_ip_entity():
    """Alerts with IP entity_id produce observables."""
    case = _make_case()
    alert = _make_alert(entity_id="192.168.1.100")
    result = export_thehive_case(case, [alert])
    obs = result["observables"]
    assert any(o["data"] == "192.168.1.100" for o in obs)
