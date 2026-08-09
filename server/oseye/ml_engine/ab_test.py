"""ML A/B test framework — parallel scoring of champion and challenger models.

Design
------
An A/B test runs two MLEngine instances side by side:
  - ``champion``: the production model (always used for real decisions).
  - ``challenger``: the candidate under evaluation.

For every event both models are scored. The challenger score is *observed*
but never forwarded to the decision pipeline — the champion remains
authoritative.  After enough events, ``ABTestSession.report()`` surfaces:
  - mean / p95 score difference
  - disagreement rate (champion vs challenger differ by > threshold)
  - relative score improvement (positive = challenger is more sensitive)

Typical lifecycle
-----------------
1. Train champion for several hours on prod traffic.
2. Create a challenger with new hyper-parameters.
3. Wrap both in ``ABTestSession`` and pass it to MLWorker
   (``ml_worker.py`` checks ``worker.ab_session`` if set).
4. After N_MIN_EVENTS, call ``session.report()`` to decide promotion.
5. Call ``session.promote()`` to swap challenger → champion in place.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import TYPE_CHECKING

from oseye.ml_engine.anomaly import EntityAnomalyDetector
from oseye.ml_engine.classifier import MITREClassifier
from oseye.ml_engine.engine import MLEngine

if TYPE_CHECKING:
    from oseye.core.schema import UniversalEvent

_N_MIN_EVENTS = 1_000
_DISAGREE_THRESHOLD = 20.0  # score difference considered a disagreement


@dataclass
class ABTestReport:
    """Summary statistics produced by an A/B test session."""

    n_events: int
    champion_mean: float
    challenger_mean: float
    mean_delta: float              # challenger_mean - champion_mean
    p95_delta: float               # p95 of abs(challenger - champion)
    disagreement_rate: float       # fraction of events where |delta| > threshold
    relative_improvement: float    # (challenger_mean - champion_mean) / max(champion_mean, 1)
    ready: bool                    # True when n_events >= N_MIN_EVENTS


class ABTestSession:
    """Runs champion and challenger in parallel and collects comparison metrics.

    Parameters
    ----------
    champion:    Current production MLEngine.
    challenger:  Candidate MLEngine to evaluate.
    n_min_events: Minimum events before the report is considered reliable.
    disagree_threshold: Score gap (0-100) that counts as a disagreement.
    """

    def __init__(
        self,
        champion: MLEngine,
        challenger: MLEngine,
        n_min_events: int = _N_MIN_EVENTS,
        disagree_threshold: float = _DISAGREE_THRESHOLD,
    ) -> None:
        self._champion = champion
        self._challenger = challenger
        self._n_min = n_min_events
        self._threshold = disagree_threshold
        self._champion_scores: list[float] = []
        self._challenger_scores: list[float] = []
        self._deltas: list[float] = []

    def score_event(self, event: UniversalEvent) -> float:
        """Score event with both models. Returns champion score (authoritative).

        The challenger score is recorded internally for comparison only.
        """
        champ_score = self._champion.score_event(event)
        chal_score = self._challenger.score_event(event)

        self._champion_scores.append(champ_score)
        self._challenger_scores.append(chal_score)
        self._deltas.append(abs(chal_score - champ_score))

        return champ_score

    def report(self) -> ABTestReport:
        """Return a comparison report. Reliable once n_events >= n_min_events."""
        n = len(self._deltas)
        if n == 0:
            return ABTestReport(
                n_events=0,
                champion_mean=0.0,
                challenger_mean=0.0,
                mean_delta=0.0,
                p95_delta=0.0,
                disagreement_rate=0.0,
                relative_improvement=0.0,
                ready=False,
            )

        champ_mean = statistics.mean(self._champion_scores)
        chal_mean = statistics.mean(self._challenger_scores)
        mean_delta = chal_mean - champ_mean
        sorted_deltas = sorted(self._deltas)
        p95_idx = max(0, int(n * 0.95) - 1)
        p95_delta = sorted_deltas[p95_idx]
        disagree_count = sum(1 for d in self._deltas if d > self._threshold)
        disagree_rate = disagree_count / n
        relative_improvement = mean_delta / max(champ_mean, 1.0)

        return ABTestReport(
            n_events=n,
            champion_mean=round(champ_mean, 3),
            challenger_mean=round(chal_mean, 3),
            mean_delta=round(mean_delta, 3),
            p95_delta=round(p95_delta, 3),
            disagreement_rate=round(disagree_rate, 4),
            relative_improvement=round(relative_improvement, 4),
            ready=n >= self._n_min,
        )

    def promote(self) -> MLEngine:
        """Swap challenger into the champion slot and return the new champion.

        The caller is responsible for replacing the MLEngine reference used by
        MLWorker and DecisionWorker.  Accumulated A/B stats are reset.
        """
        self._champion = self._challenger
        self._challenger = _clone_champion(self._champion)
        self._champion_scores.clear()
        self._challenger_scores.clear()
        self._deltas.clear()
        return self._champion

    @property
    def champion(self) -> MLEngine:
        return self._champion

    @property
    def challenger(self) -> MLEngine:
        return self._challenger

    @property
    def n_events(self) -> int:
        return len(self._deltas)


def _clone_champion(_engine: MLEngine) -> MLEngine:
    """Return a fresh MLEngine.

    Used as the default challenger after a promotion — it starts cold and
    will diverge as traffic flows in.
    """
    return MLEngine(
        anomaly_detector=EntityAnomalyDetector(),
        classifier=MITREClassifier(),
    )
