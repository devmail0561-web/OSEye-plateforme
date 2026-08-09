"""Unit tests for Phase 4 M26 — Correlation Engine.

Covers: SameHostLinker, CorrelationEngine, SQLIncidentRepository (SQLite :memory:).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.core.schema import Alert, Incident, IncidentEvent
from oseye.correlation.engine import CorrelationEngine
from oseye.correlation.linkers.same_host import SameHostLinker
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.repositories.incidents import SQLIncidentRepository

# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def make_alert(**overrides: Any) -> Alert:
    now = datetime.now(tz=UTC)
    defaults: dict[str, Any] = {
        "alert_id": uuid4(),
        "created_at": now,
        "updated_at": now,
        "severity": "medium",
        "status": "open",
        "entity_id": "proc:bash",
        "hostname": "server-01",
        "trigger_event_id": uuid4(),
        "title": "Suspicious network activity",
    }
    defaults.update(overrides)
    return Alert(**defaults)


def make_incident(hostname: str = "server-01", severity: str = "medium") -> Incident:
    now = datetime.now(tz=UTC)
    return Incident(
        hostname=hostname,
        severity=severity,  # type: ignore[arg-type]
        alert_ids=[],
        timeline=[],
        alert_count=0,
    )


# ---------------------------------------------------------------------------
# SQLite :memory: fixture — mirrors tests/unit/test_storage.py pattern
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def backend() -> SQLiteBackend:  # type: ignore[return]
    b = SQLiteBackend("sqlite+aiosqlite:///:memory:")
    await b.init()
    yield b
    await b.close()


@pytest_asyncio.fixture
async def incident_repo(backend: SQLiteBackend) -> SQLIncidentRepository:
    return SQLIncidentRepository(backend.session_factory)


# ---------------------------------------------------------------------------
# 1–3. SameHostLinker
# ---------------------------------------------------------------------------


async def test_same_host_linker_low_severity_returns_none() -> None:
    """SameHostLinker.match with severity='low' returns None without querying the repo."""
    linker = SameHostLinker(timeframe_seconds=300)
    mock_repo = AsyncMock(spec=SQLIncidentRepository)

    alert = make_alert(severity="low")
    result = await linker.match(alert, mock_repo)

    assert result is None
    mock_repo.find_open_for_host.assert_not_called()


async def test_same_host_linker_no_open_incident_returns_none() -> None:
    """SameHostLinker.match returns None when find_open_for_host returns None."""
    linker = SameHostLinker(timeframe_seconds=300)
    mock_repo = AsyncMock(spec=SQLIncidentRepository)
    mock_repo.find_open_for_host.return_value = None

    alert = make_alert(severity="high")
    result = await linker.match(alert, mock_repo)

    assert result is None
    mock_repo.find_open_for_host.assert_awaited_once()


async def test_same_host_linker_returns_existing_incident() -> None:
    """SameHostLinker.match returns the incident from find_open_for_host."""
    linker = SameHostLinker(timeframe_seconds=300)
    existing = make_incident()

    mock_repo = AsyncMock(spec=SQLIncidentRepository)
    mock_repo.find_open_for_host.return_value = existing

    alert = make_alert(severity="high")
    result = await linker.match(alert, mock_repo)

    assert result is existing
    mock_repo.find_open_for_host.assert_awaited_once()


# ---------------------------------------------------------------------------
# 4–6. CorrelationEngine
# ---------------------------------------------------------------------------


async def test_engine_below_min_severity_returns_none() -> None:
    """CorrelationEngine.process_alert returns None if alert is below min_severity."""
    mock_repo = AsyncMock(spec=SQLIncidentRepository)
    engine = CorrelationEngine(
        linkers=[SameHostLinker()],
        incident_repo=mock_repo,
        min_severity="medium",
    )
    alert = make_alert(severity="low")
    result = await engine.process_alert(alert)

    assert result is None
    mock_repo.create.assert_not_called()
    mock_repo.add_alert.assert_not_called()


async def test_engine_no_match_creates_new_incident() -> None:
    """CorrelationEngine.process_alert creates a new incident when no candidate exists."""
    mock_repo = AsyncMock(spec=SQLIncidentRepository)
    mock_linker = AsyncMock(spec=SameHostLinker)
    mock_linker.name = "same_host_timeframe"
    mock_linker._timeframe = 300
    # No open incidents for this host
    mock_repo.find_open_incidents_for_host.return_value = []

    engine = CorrelationEngine(linkers=[mock_linker], incident_repo=mock_repo, min_severity="medium")

    created_incident: Incident | None = None

    async def _capture_create(inc: Incident) -> Incident:
        nonlocal created_incident
        created_incident = inc
        return inc

    mock_repo.create.side_effect = _capture_create

    alert = make_alert(severity="high")
    result = await engine.process_alert(alert)

    assert result is not None
    mock_repo.create.assert_awaited_once()
    mock_repo.add_alert.assert_not_called()
    assert result.hostname == alert.hostname
    assert result.severity == alert.severity
    assert alert.alert_id in result.alert_ids


async def test_engine_match_adds_alert_and_updates_incident() -> None:
    """CorrelationEngine.process_alert appends alert to best-scoring existing incident."""
    existing = make_incident(severity="medium")

    mock_repo = AsyncMock(spec=SQLIncidentRepository)
    mock_linker = AsyncMock(spec=SameHostLinker)
    mock_linker.name = "same_host_timeframe"
    mock_linker._timeframe = 300
    # Repo returns the existing incident as a candidate
    mock_repo.find_open_incidents_for_host.return_value = [existing]
    # Linker scores it as a match
    mock_linker.score.return_value = 0.5
    mock_linker.max_severity.side_effect = (
        lambda cur, new: new if {"low": 0, "medium": 1, "high": 2, "critical": 3}[new]
        > {"low": 0, "medium": 1, "high": 2, "critical": 3}[cur] else cur
    )

    engine = CorrelationEngine(linkers=[mock_linker], incident_repo=mock_repo, min_severity="medium")

    alert = make_alert(severity="high", mitre_techniques=["T1055"])
    result = await engine.process_alert(alert)

    assert result is existing
    mock_repo.add_alert.assert_awaited_once()
    mock_repo.update.assert_awaited_once()
    mock_repo.create.assert_not_called()
    assert result.severity == "high"
    assert "T1055" in result.mitre_tactics


# ---------------------------------------------------------------------------
# 7–9. SQLIncidentRepository — SQLite :memory:
# ---------------------------------------------------------------------------


async def test_incident_repo_create_and_get_roundtrip(incident_repo: SQLIncidentRepository) -> None:
    """create() followed by get() returns an equivalent incident."""
    now = datetime.now(tz=UTC)
    alert_id = uuid4()
    event = IncidentEvent(
        alert_id=alert_id,
        timestamp=now,
        severity="medium",
        title="Alert A",
        hostname="server-01",
        mitre_techniques=["T1059"],
    )
    incident = Incident(
        hostname="server-01",
        severity="medium",
        alert_ids=[alert_id],
        timeline=[event],
        alert_count=1,
    )

    await incident_repo.create(incident)
    fetched = await incident_repo.get(incident.incident_id)

    assert fetched is not None
    assert fetched.incident_id == incident.incident_id
    assert fetched.hostname == "server-01"
    assert fetched.severity == "medium"
    assert len(fetched.timeline) == 1
    assert fetched.timeline[0].alert_id == alert_id
    assert "T1059" in fetched.timeline[0].mitre_techniques


async def test_incident_repo_find_open_for_host_found(incident_repo: SQLIncidentRepository) -> None:
    """find_open_for_host returns an open incident created within the timeframe."""
    now = datetime.now(tz=UTC)
    incident = Incident(
        hostname="server-02",
        severity="high",
        alert_ids=[],
        timeline=[],
        alert_count=0,
    )
    await incident_repo.create(incident)

    # Look for incidents created in last 10 minutes — should find the one just created
    since = now - timedelta(minutes=10)
    result = await incident_repo.find_open_for_host("server-02", since)

    assert result is not None
    assert result.incident_id == incident.incident_id
    assert result.hostname == "server-02"


async def test_incident_repo_find_open_for_host_too_old(incident_repo: SQLIncidentRepository) -> None:
    """find_open_for_host returns None when all matching incidents are older than `since`."""
    now = datetime.now(tz=UTC)
    incident = Incident(
        hostname="server-03",
        severity="medium",
        alert_ids=[],
        timeline=[],
        alert_count=0,
    )
    await incident_repo.create(incident)

    since = now + timedelta(minutes=1)
    result = await incident_repo.find_open_for_host("server-03", since)

    assert result is None


# ---------------------------------------------------------------------------
# Corrections — nouveaux tests
# ---------------------------------------------------------------------------


# --- correction 1 : score-based linker ---

async def test_same_host_linker_score_same_host_no_mitre() -> None:
    """score() returns BASE_SCORE when host matches but no MITRE overlap."""
    linker = SameHostLinker(timeframe_seconds=300)
    alert = make_alert(severity="high", hostname="server-01")
    incident = make_incident(hostname="server-01", severity="medium")

    score = await linker.score(alert, incident)
    assert score == pytest.approx(0.5)


async def test_same_host_linker_score_with_mitre_overlap() -> None:
    """score() is > 0.5 when MITRE techniques overlap."""
    from oseye.core.schema import Incident
    linker = SameHostLinker(timeframe_seconds=300)
    alert = make_alert(severity="high", hostname="server-01", mitre_techniques=["T1059", "T1055"])

    now = datetime.now(tz=UTC)
    incident = Incident(
        hostname="server-01",
        severity="medium",
        mitre_tactics=["T1059"],
        alert_count=1,
    )
    score = await linker.score(alert, incident)
    assert score > 0.5


async def test_same_host_linker_score_different_host_zero() -> None:
    """score() returns 0 when hostnames differ."""
    linker = SameHostLinker(timeframe_seconds=300)
    alert = make_alert(severity="high", hostname="server-A")
    incident = make_incident(hostname="server-B")
    score = await linker.score(alert, incident)
    assert score == pytest.approx(0.0)


async def test_same_host_linker_score_low_severity_zero() -> None:
    """score() returns 0 for low severity alerts."""
    linker = SameHostLinker(timeframe_seconds=300)
    alert = make_alert(severity="low")
    incident = make_incident()
    score = await linker.score(alert, incident)
    assert score == pytest.approx(0.0)


async def test_same_host_linker_score_old_incident_zero() -> None:
    """score() returns 0 when incident is outside the timeframe."""
    from oseye.core.schema import Incident
    linker = SameHostLinker(timeframe_seconds=60)
    alert = make_alert(severity="high", hostname="server-01")
    old_time = datetime.now(tz=UTC) - timedelta(seconds=120)
    incident = Incident(
        hostname="server-01",
        severity="medium",
        created_at=old_time,
        updated_at=old_time,
        alert_count=0,
    )
    score = await linker.score(alert, incident)
    assert score == pytest.approx(0.0)


# --- correction 1 : best-score selection among multiple candidates ---

async def test_engine_selects_highest_scoring_incident() -> None:
    """CorrelationEngine picks the incident with the highest score."""
    inc_low = make_incident(severity="medium")
    inc_high = make_incident(severity="high")

    mock_repo = AsyncMock(spec=SQLIncidentRepository)
    mock_repo.find_open_incidents_for_host.return_value = [inc_low, inc_high]

    mock_linker = AsyncMock(spec=SameHostLinker)
    mock_linker.name = "same_host_timeframe"
    mock_linker._timeframe = 300
    # inc_low scores 0.5, inc_high scores 0.9
    mock_linker.score.side_effect = [0.5, 0.9]
    mock_linker.max_severity.return_value = "high"

    engine = CorrelationEngine(linkers=[mock_linker], incident_repo=mock_repo, min_severity="medium")
    alert = make_alert(severity="high")
    result = await engine.process_alert(alert)

    assert result is inc_high


# --- correction 2 : incidents multiples par host (repo) ---

async def test_repo_find_open_incidents_for_host_multiple(incident_repo: SQLIncidentRepository) -> None:
    """find_open_incidents_for_host returns all matching open incidents."""
    for _ in range(3):
        await incident_repo.create(make_incident(hostname="multi-host"))

    now = datetime.now(tz=UTC)
    results = await incident_repo.find_open_incidents_for_host("multi-host", now - timedelta(hours=1))
    assert len(results) == 3


async def test_repo_find_open_incidents_for_host_excludes_other_hosts(
    incident_repo: SQLIncidentRepository,
) -> None:
    await incident_repo.create(make_incident(hostname="host-A"))
    await incident_repo.create(make_incident(hostname="host-B"))

    now = datetime.now(tz=UTC)
    results = await incident_repo.find_open_incidents_for_host("host-A", now - timedelta(hours=1))
    assert all(i.hostname == "host-A" for i in results)


# --- correction 3 : auto-close ---

async def test_engine_requires_at_least_one_linker() -> None:
    """CorrelationEngine raises ValueError when linkers=[]."""
    mock_repo = AsyncMock(spec=SQLIncidentRepository)
    with pytest.raises(ValueError, match="linker"):
        CorrelationEngine(linkers=[], incident_repo=mock_repo)


async def test_close_stale_incidents(incident_repo: SQLIncidentRepository) -> None:
    """close_stale_incidents() closes incidents not updated since cutoff."""
    from oseye.core.schema import Incident
    old_time = datetime.now(tz=UTC) - timedelta(hours=2)
    stale = Incident(
        hostname="stale-host", severity="low",
        created_at=old_time, updated_at=old_time,
        alert_count=0,
    )
    fresh = make_incident(hostname="fresh-host")
    await incident_repo.create(stale)
    await incident_repo.create(fresh)

    engine = CorrelationEngine(
        linkers=[SameHostLinker()],
        incident_repo=incident_repo,
        auto_close_after_seconds=3600,
    )
    closed = await engine.close_stale_incidents()
    assert closed == 1

    reloaded = await incident_repo.get(stale.incident_id)
    assert reloaded is not None
    assert reloaded.status == "resolved"

    reloaded_fresh = await incident_repo.get(fresh.incident_id)
    assert reloaded_fresh is not None
    assert reloaded_fresh.status == "open"


async def test_close_stale_disabled_when_zero(incident_repo: SQLIncidentRepository) -> None:
    """close_stale_incidents() is a no-op when auto_close_after_seconds=0."""
    engine = CorrelationEngine(
        linkers=[SameHostLinker()],
        incident_repo=incident_repo,
        auto_close_after_seconds=0,
    )
    count = await engine.close_stale_incidents()
    assert count == 0


async def test_repo_close_stale(incident_repo: SQLIncidentRepository) -> None:
    """SQLIncidentRepository.close_stale() updates status to resolved."""
    old_time = datetime.now(tz=UTC) - timedelta(hours=3)
    inc = Incident(
        hostname="old-host", severity="low",
        created_at=old_time, updated_at=old_time,
        alert_count=0,
    )
    await incident_repo.create(inc)

    cutoff = datetime.now(tz=UTC) - timedelta(hours=1)
    count = await incident_repo.close_stale(cutoff)
    assert count >= 1

    reloaded = await incident_repo.get(inc.incident_id)
    assert reloaded is not None
    assert reloaded.status == "resolved"
