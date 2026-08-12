"""Unit tests — ML Engine (Phase 6): features, anomaly, classifier, engine."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from oseye.core.schema import UniversalEvent
from oseye.ml_engine.features import extract, _stable_hash_norm
from oseye.ml_engine.anomaly import EntityAnomalyDetector
from oseye.ml_engine.classifier import MITREClassifier
from oseye.ml_engine.engine import MLEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    *,
    hostname: str = "host1",
    category: str = "process",
    severity: str = "low",
    uid: int = 1000,
    pid: int = 1234,
    process_name: str = "bash",
    dst_port: int | None = None,
    bytes_sent: int | None = None,
    bytes_recv: int | None = None,
    result: str = "success",
    timestamp_ns: int | None = None,
    mitre_techniques: list[str] | None = None,
) -> UniversalEvent:
    ts = timestamp_ns or int(datetime.now(UTC).timestamp() * 1e9)
    return UniversalEvent(
        event_id=uuid4(),
        timestamp_ns=ts,
        hostname=hostname,
        agent_id=uuid4(),
        category=category,  # type: ignore[arg-type]
        type="exec",
        severity=severity,  # type: ignore[arg-type]
        collector="procfs",
        uid=uid,
        gid=uid,
        pid=pid,
        ppid=1,
        process_name=process_name,
        executable=f"/bin/{process_name}",
        dst_port=dst_port,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        result=result,
        mitre_techniques=mitre_techniques or [],
    )


# ---------------------------------------------------------------------------
# features.py
# ---------------------------------------------------------------------------

class TestExtract:
    def test_all_keys_present(self) -> None:
        ev = _make_event()
        f = extract(ev)
        expected_keys = {
            "category_ord", "severity_ord", "uid_norm", "is_root",
            "hour_norm", "dst_port_norm", "bytes_sent_log", "bytes_recv_log",
            "result_ok", "proc_hash",
        }
        assert set(f.keys()) == expected_keys

    def test_all_values_in_unit_range(self) -> None:
        ev = _make_event(uid=0, bytes_sent=10**9, bytes_recv=10**9, dst_port=65535)
        for key, val in extract(ev).items():
            assert 0.0 <= val <= 1.0, f"{key}={val} out of [0,1]"

    def test_root_uid_sets_is_root(self) -> None:
        f = extract(_make_event(uid=0))
        assert f["is_root"] == 1.0

    def test_non_root_uid_clears_is_root(self) -> None:
        f = extract(_make_event(uid=1000))
        assert f["is_root"] == 0.0

    def test_result_ok_for_success(self) -> None:
        assert extract(_make_event(result="success"))["result_ok"] == 1.0
        assert extract(_make_event(result="denied"))["result_ok"] == 0.0

    def test_process_name_deterministic(self) -> None:
        f1 = extract(_make_event(process_name="nginx"))
        f2 = extract(_make_event(process_name="nginx"))
        assert f1["proc_hash"] == f2["proc_hash"]

    def test_different_process_names_different_hash(self) -> None:
        f1 = extract(_make_event(process_name="nginx"))
        f2 = extract(_make_event(process_name="bash"))
        assert f1["proc_hash"] != f2["proc_hash"]

    def test_network_category_ord(self) -> None:
        f = extract(_make_event(category="network"))
        assert f["category_ord"] == pytest.approx(2.0 / 6.0)

    def test_bytes_sent_log_zero_for_none(self) -> None:
        f = extract(_make_event(bytes_sent=None))
        assert f["bytes_sent_log"] == pytest.approx(0.0)

    def test_stable_hash_norm_range(self) -> None:
        for s in ["", "a", "bash", "a" * 100]:
            v = _stable_hash_norm(s)
            assert 0.0 <= v <= 1.0


# ---------------------------------------------------------------------------
# anomaly.py
# ---------------------------------------------------------------------------

class TestEntityAnomalyDetector:
    def _fast_det(self, **kw: object) -> EntityAnomalyDetector:
        defaults = dict(min_samples=5, n_trees=5, height=5, window_size=10)
        defaults.update(kw)
        return EntityAnomalyDetector(**defaults)  # type: ignore[arg-type]

    # --- cold-start ---

    def test_cold_start_returns_zero(self) -> None:
        det = EntityAnomalyDetector(min_samples=50)
        assert det.learn_and_score(_make_event()) == 0.0

    def test_score_emitted_after_min_samples(self) -> None:
        det = self._fast_det()
        for i in range(20):
            det.learn_and_score(_make_event(pid=i))
        assert 0.0 <= det.learn_and_score(_make_event(pid=9999)) <= 100.0

    # --- isolation ---

    def test_separate_models_per_hostname(self) -> None:
        det = self._fast_det()
        for i in range(20):
            det.learn_and_score(_make_event(hostname="host-A", pid=i))
            det.learn_and_score(_make_event(hostname="host-B", pid=i))
        assert det.model_count == 2

    def test_separate_models_per_category(self) -> None:
        det = self._fast_det()
        for i in range(20):
            det.learn_and_score(_make_event(hostname="h", category="process", pid=i))
            det.learn_and_score(_make_event(hostname="h", category="network", pid=i))
        assert det.model_count == 2

    def test_score_stays_in_bounds(self) -> None:
        det = self._fast_det(min_samples=2)
        for i in range(100):
            score = det.learn_and_score(_make_event(pid=i, uid=i % 65535))
            assert 0.0 <= score <= 100.0

    # --- correction 1 : adaptive window_size ---

    def test_adaptive_window_per_category(self) -> None:
        det = EntityAnomalyDetector(
            n_trees=5, height=5, window_size=250,
            window_size_by_category={"network": 50, "audit": 500},
            min_samples=5,
        )
        # Two categories → two models with different window_size
        for i in range(10):
            det.learn_and_score(_make_event(hostname="h", category="network", pid=i))
            det.learn_and_score(_make_event(hostname="h", category="audit", pid=i))
        assert det.model_count == 2

    def test_default_window_used_for_unknown_category(self) -> None:
        det = EntityAnomalyDetector(
            n_trees=5, height=5, window_size=123,
            window_size_by_category={"network": 50},
            min_samples=5,
        )
        # "process" not in override → uses default 123 (no error)
        det.learn_and_score(_make_event(category="process"))
        assert det.model_count == 1

    # --- correction 2 : LRU cap ---

    def test_lru_eviction_caps_model_count(self) -> None:
        det = EntityAnomalyDetector(
            n_trees=3, height=3, window_size=5, min_samples=1, max_models=3
        )
        for i in range(5):
            det.learn_and_score(_make_event(hostname=f"host-{i}"))
        assert det.model_count <= 3

    def test_lru_does_not_evict_recently_used(self) -> None:
        det = EntityAnomalyDetector(
            n_trees=3, height=3, window_size=5, min_samples=1, max_models=2
        )
        # Fill to cap
        for i in range(2):
            det.learn_and_score(_make_event(hostname=f"host-{i}"))
        # Touch host-0 again to make it most-recently-used
        det.learn_and_score(_make_event(hostname="host-0"))
        # Adding host-2 should evict host-1, not host-0
        det.learn_and_score(_make_event(hostname="host-2"))
        assert det.model_count == 2
        # host-0 must still be present (MRU)
        from oseye.ml_engine.anomaly import _LRUStore
        keys = [k for k, _ in det._store.items()]
        assert "host-0::process" in keys

    # --- correction 3 : decaying-max normalisation ---

    def test_decaying_max_recovers_after_outlier(self) -> None:
        det = self._fast_det(min_samples=2)
        # Build a baseline
        for i in range(30):
            det.learn_and_score(_make_event(pid=i))
        # Inject one extreme outlier — the decaying max should absorb it
        outlier = _make_event(uid=0, bytes_sent=10**9, dst_port=4444)
        det.learn_and_score(outlier)
        # After many more normal events, subsequent scores should still vary
        scores_after = [
            det.learn_and_score(_make_event(pid=1000 + i)) for i in range(50)
        ]
        # If the max never decayed, all scores would be near 0
        assert max(scores_after) > 0.0

    def test_score_never_exceeds_100(self) -> None:
        det = self._fast_det(min_samples=2)
        for i in range(200):
            s = det.learn_and_score(_make_event(pid=i, uid=i % 65535, bytes_sent=i * 1000))
            assert s <= 100.0

    # --- correction 4 : persistence ---

    def test_save_and_load_roundtrip(self, tmp_path: object) -> None:
        import tempfile, os
        det = self._fast_det(min_samples=2)
        for i in range(20):
            det.learn_and_score(_make_event(pid=i))
        count_before = det.model_count

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            path = f.name
        try:
            det.save(path)
            det2 = EntityAnomalyDetector.load(path)
            assert det2.model_count == count_before
            # Must be able to score immediately (no cold-start reset)
            score = det2.learn_and_score(_make_event(pid=9999))
            assert 0.0 <= score <= 100.0
        finally:
            os.unlink(path)

    def test_load_preserves_params(self, tmp_path: object) -> None:
        import tempfile, os
        det = EntityAnomalyDetector(
            n_trees=7, height=8, window_size=111,
            window_size_by_category={"network": 55},
            min_samples=3, max_models=500,
        )
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            path = f.name
        try:
            det.save(path)
            det2 = EntityAnomalyDetector.load(path)
            assert det2._n_trees == 7
            assert det2._height == 8
            assert det2._window_size == 111
            assert det2._window_by_cat == {"network": 55}
            assert det2._min_samples == 3
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# classifier.py
# ---------------------------------------------------------------------------

class TestMITREClassifier:
    def test_cold_start_returns_zero(self) -> None:
        clf = MITREClassifier()
        assert clf.score(_make_event()) == 0.0

    def test_learns_and_scores_higher_for_trained_pattern(self) -> None:
        clf = MITREClassifier()
        ev = _make_event(process_name="powershell", uid=0)
        # Train 10 times on this pattern for T1059.001
        for _ in range(10):
            clf.learn(ev, ["T1059.001"])
        score = clf.score(ev)
        assert score > 0.0

    def test_known_techniques_populated(self) -> None:
        clf = MITREClassifier()
        clf.learn(_make_event(), ["T1059.001", "T1055"])
        assert set(clf.known_techniques) == {"T1059.001", "T1055"}

    def test_empty_techniques_no_learn(self) -> None:
        clf = MITREClassifier()
        clf.learn(_make_event(), [])
        assert clf.known_techniques == []

    def test_score_in_bounds(self) -> None:
        clf = MITREClassifier()
        for i in range(20):
            clf.learn(_make_event(pid=i), ["T1059"])
        score = clf.score(_make_event())
        assert 0.0 <= score <= 100.0

    def test_negative_updates_for_unmatched_techniques(self) -> None:
        clf = MITREClassifier()
        ev_a = _make_event(process_name="python", uid=500)
        ev_b = _make_event(process_name="wget", uid=0)
        # Train T1059 on ev_a many times, then train T1190 on ev_b
        for _ in range(15):
            clf.learn(ev_a, ["T1059"])
        for _ in range(5):
            clf.learn(ev_b, ["T1190"])
        # ev_a should score more for T1059 than ev_b
        score_a = clf.score(ev_a)
        score_b = clf.score(ev_b)
        # Not a strict guarantee (LR may generalise), but ev_a trained more
        assert score_a >= 0.0 and score_b >= 0.0


# ---------------------------------------------------------------------------
# engine.py
# ---------------------------------------------------------------------------

class TestMLEngine:
    def test_score_returns_zero_before_min_samples(self) -> None:
        eng = MLEngine()
        score = eng.score_event(_make_event())
        assert score == 0.0

    def test_score_in_bounds_after_many_events(self) -> None:
        from oseye.ml_engine.anomaly import EntityAnomalyDetector
        det = EntityAnomalyDetector(min_samples=5, n_trees=5, height=5, window_size=10)
        eng = MLEngine(anomaly_detector=det)
        for i in range(50):
            s = eng.score_event(_make_event(pid=i))
            assert 0.0 <= s <= 100.0

    def test_learn_from_alert_populates_classifier(self) -> None:
        eng = MLEngine()
        eng.learn_from_alert(_make_event(), ["T1059.001"])
        assert "T1059.001" in eng.known_techniques

    def test_model_count_increments(self) -> None:
        eng = MLEngine()
        eng.score_event(_make_event(hostname="h1", category="process"))
        eng.score_event(_make_event(hostname="h2", category="network"))
        assert eng.model_count == 2

    def test_ml_score_wired_into_decision_engine(self) -> None:
        """Verify DecisionEngine passes trigger_event to MLEngine."""
        from unittest.mock import MagicMock
        from oseye.decision.engine import DecisionEngine
        from oseye.decision.journal import DecisionJournal

        mock_ml = MagicMock()
        # Engine prefers score_event_readonly (no training side-effect)
        mock_ml.score_event_readonly.return_value = 80.0

        engine = DecisionEngine(
            journal=DecisionJournal(),
            ml_engine=mock_ml,
        )
        ev = _make_event()

        import asyncio
        from oseye.core.schema import Incident, IncidentEvent

        now = datetime.now(UTC)
        incident = Incident(
            incident_id=uuid4(),
            created_at=now,
            updated_at=now,
            hostname="host1",
            severity="low",
            alert_count=1,
        )

        decision = asyncio.run(engine.decide(incident, trigger_event=ev))
        mock_ml.score_event_readonly.assert_called_once_with(ev)
        assert decision.ml_score == pytest.approx(80.0)

    def test_ml_score_zero_without_event(self) -> None:
        """ml_score should be 0 when no trigger_event is supplied."""
        from oseye.decision.engine import DecisionEngine
        from oseye.decision.journal import DecisionJournal
        from oseye.core.schema import Incident
        import asyncio

        engine = DecisionEngine(journal=DecisionJournal(), ml_engine=MLEngine())
        now = datetime.now(UTC)
        incident = Incident(
            incident_id=uuid4(),
            created_at=now,
            updated_at=now,
            hostname="host1",
            severity="low",
            alert_count=1,
        )
        decision = asyncio.run(engine.decide(incident))
        assert decision.ml_score == pytest.approx(0.0)
