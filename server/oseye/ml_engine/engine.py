"""ML Engine façade — combines anomaly detection and MITRE classification.

ml_score formula:
    ml_score = 0.7 × anomaly_score + 0.3 × classifier_score

Rationale for 70/30 split:
  - The anomaly detector fires on any deviation from the entity's baseline,
    regardless of whether the pattern matches a known technique — it catches
    novel/unknown threats. It deserves the higher weight.
  - The MITRE classifier is a recall-oriented signal: it fires strongly only
    when the event pattern closely resembles past confirmed technique hits.
    It is authoritative when it fires but silent during cold-start, so the
    lower weight prevents it from dominating early in deployment.

Usage:
    engine = MLEngine()

    # On every inbound normalised event (rule_worker / storage_writer):
    ml_score = engine.score_event(event)             # [0, 100]

    # After a rule fires and produces an alert with MITRE techniques:
    engine.learn_from_alert(trigger_event, alert.mitre_techniques)
"""

from __future__ import annotations

import os
import pickle
from pathlib import Path

from oseye.core.schema import UniversalEvent
from oseye.ml_engine.anomaly import EntityAnomalyDetector
from oseye.ml_engine.classifier import MITREClassifier

_W_ANOMALY = 0.7
_W_CLASSIFIER = 0.3


class MLEngine:
    """Stateful ML engine — one instance per server process (singleton via DI).

    The engine is not async — both HST and LR are CPU-bound with microsecond
    latency, so no async wrapper is needed.
    """

    def __init__(
        self,
        anomaly_detector: EntityAnomalyDetector | None = None,
        classifier: MITREClassifier | None = None,
    ) -> None:
        self._anomaly = anomaly_detector or EntityAnomalyDetector()
        self._classifier = classifier or MITREClassifier()

    def score_event(self, event: UniversalEvent) -> float:
        """Score an event and update the anomaly model. Returns [0, 100].

        Call this for every event that passes normalisation, regardless of
        whether a rule fires — the anomaly model needs benign traffic to build
        a reliable baseline.
        """
        anomaly = self._anomaly.learn_and_score(event)
        classifier = self._classifier.score(event)
        return _W_ANOMALY * anomaly + _W_CLASSIFIER * classifier

    def learn_from_alert(
        self,
        trigger_event: UniversalEvent,
        mitre_techniques: list[str],
    ) -> None:
        """Update the MITRE classifier with a confirmed rule-triggered alert.

        Should be called after a rule fires and the alert is persisted, so the
        classifier learns from confirmed positives only.
        """
        self._classifier.learn(trigger_event, mitre_techniques)

    def save_checkpoint(self, path: str | Path) -> None:
        """Persist anomaly detector + MITRE classifier state to *path*.

        Both are written atomically: anomaly via its own atomic save(),
        classifier via a companion .classifier.pkl file with the same
        tmp-then-replace pattern.
        """
        path = Path(path)
        self._anomaly.save(path)
        clf_path = path.with_suffix(".classifier.pkl")
        clf_tmp = clf_path.with_suffix(".pkl.tmp")
        try:
            with open(clf_tmp, "wb") as fh:
                pickle.dump(self._classifier, fh, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(clf_tmp, clf_path)
        except Exception:
            clf_tmp.unlink(missing_ok=True)
            raise

    def load_checkpoint(self, path: str | Path) -> None:
        """Restore anomaly detector + MITRE classifier from a checkpoint."""
        path = Path(path)
        self._anomaly = EntityAnomalyDetector.load(path)
        clf_path = path.with_suffix(".classifier.pkl")
        if clf_path.exists():
            with open(clf_path, "rb") as fh:
                self._classifier = pickle.load(fh)  # noqa: S301  # trusted local file

    @property
    def model_count(self) -> int:
        """Number of per-entity anomaly models currently in memory."""
        return self._anomaly.model_count

    @property
    def known_techniques(self) -> list[str]:
        return self._classifier.known_techniques
