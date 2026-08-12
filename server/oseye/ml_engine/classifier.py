"""MITRE ATT&CK technique classifier — online multi-label logistic regression.

Why online logistic regression for MITRE classification?
  - Labels come from confirmed rule matches (alert.mitre_techniques), so the
    model is trained on real positives as they accumulate — no offline dataset
    required.
  - Each technique is a binary classifier: "does this event pattern resemble
    a past hit for T1059.001?" River's LogisticRegression updates on every
    sample with a configurable learning rate.
  - Multi-label: one LR model per technique; they share feature extraction.

Score semantics: the classifier score [0, 100] reflects the *maximum* predicted
probability across all known techniques for the given feature vector. When no
technique has been trained yet, the score is 0 (cold-start safe).

Training: call `learn(event, techniques)` with the event that triggered an alert
and the matched MITRE technique list. The engine calls this after a rule fires.
"""

from __future__ import annotations

from collections import OrderedDict

from river.linear_model import LogisticRegression
from river.optim import Adam

from oseye.core.schema import UniversalEvent
from oseye.ml_engine.features import extract

_LEARNING_RATE = 0.01

# ML-R-02: hard cap on number of per-technique models to prevent unbounded memory
# growth when the MITRE technique space is large or when noisy rules create many
# unique technique strings.  LRU eviction: the least-recently-used model is
# dropped when the cap is reached.
_MAX_MODELS = 500


class MITREClassifier:
    """Per-technique online logistic regression.

    Parameters
    ----------
    learning_rate: Adam optimiser learning rate.
    """

    def __init__(self, learning_rate: float = _LEARNING_RATE) -> None:
        self._lr = learning_rate
        self._models: OrderedDict[str, LogisticRegression] = OrderedDict()

    def _get_or_create(self, technique: str) -> LogisticRegression:
        if technique not in self._models:
            # ML-R-02: evict LRU entry before adding when at capacity.
            if len(self._models) >= _MAX_MODELS:
                self._models.popitem(last=False)
            self._models[technique] = LogisticRegression(
                optimizer=Adam(lr=self._lr),
                intercept_lr=self._lr,
            )
        else:
            # Move to end to mark as most-recently-used.
            self._models.move_to_end(technique)
        return self._models[technique]

    def learn(self, event: UniversalEvent, techniques: list[str]) -> None:
        """Train all technique classifiers on this confirmed-positive event.

        Also trains a negative update for techniques that were NOT matched, to
        keep false-positive rates low as technique coverage grows.
        """
        if not techniques:
            return

        features = extract(event)
        technique_set = set(techniques)

        # Positive update for matched techniques.
        for tech in technique_set:
            model = self._get_or_create(tech)
            model.learn_one(features, True)

        # Negative update for already-known techniques that did NOT fire.
        for tech, model in self._models.items():
            if tech not in technique_set:
                model.learn_one(features, False)

    def score(self, event: UniversalEvent) -> float:
        """Return the max predicted probability [0, 100] across all techniques.

        Returns 0.0 if no technique model has been trained yet.
        """
        if not self._models:
            return 0.0

        features = extract(event)
        max_prob = 0.0
        for model in self._models.values():
            prob: float = model.predict_proba_one(features).get(True, 0.0)  # type: ignore[no-untyped-call]
            if prob > max_prob:
                max_prob = prob

        return max_prob * 100.0

    def negative_feedback(
        self, event: UniversalEvent, techniques: list[str] | None = None
    ) -> None:
        """Apply a negative (false-positive) update to technique models.

        ML-R-06: called when an alert is marked as a false positive.
        If *techniques* is provided, only those specific technique models are
        updated (avoids poisoning unrelated classifiers). Falls back to updating
        all models when techniques is None or empty.
        """
        if not self._models:
            return
        features = extract(event)
        if techniques:
            target_models = [
                self._models[t] for t in techniques if t in self._models
            ]
        else:
            target_models = list(self._models.values())
        for model in target_models:
            model.learn_one(features, False)  # type: ignore[no-untyped-call]

    @property
    def known_techniques(self) -> list[str]:
        return list(self._models.keys())
