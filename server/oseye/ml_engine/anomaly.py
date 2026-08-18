"""Per-entity behavioural baseline using Half-Space Trees (online anomaly detection).

Why Half-Space Trees over Isolation Forest?
  - Online learning: each event updates the model in O(n_trees × depth) — no batch.
  - Memory-bounded: tree structure is fixed at init; no data buffer grows.
  - Per-entity models: each (hostname, category) pair gets its own HST.

Four corrections vs initial version
------------------------------------

1. Adaptive window_size (per category)
   250 events = 2s for nginx, 3 days for a cron job.  High-volume categories
   (network) need a smaller window for fast drift detection; low-volume ones
   (audit) need a larger one to accumulate enough observations.
   Pass `window_size_by_category` to override per category.

2. Bounded memory (LRU eviction)
   Without a cap, one model per (hostname × category) means unbounded growth on
   large fleets.  `max_models` enforces a hard ceiling; the least-recently-used
   model is evicted when the store is full.

3. Decaying-max normalisation
   The original `raw / max_seen` was fragile: one extreme outlier inflates max_seen
   and compresses every subsequent score toward 0, hiding real anomalies.
   Fix: the running max now decays by _MAX_DECAY per event, so it recovers from an
   outlier within ~1 000 events without requiring a separate EMA accumulator.

4. Persistence (pickle)
   All model states survive a server restart via save() / load().  Without this,
   every restart resets all baselines to cold-start — creating a detection gap.

Drift limitation (by design)
   A patient attacker who shifts behaviour gradually will slowly normalise the
   baseline.  This is the fundamental limit of unsupervised online detection.
   The rule engine (deterministic, human-curated) is the backstop for known TTPs.

Cold-start: fewer than `min_samples` events → score 0 (model not yet reliable).
"""

from __future__ import annotations

import hashlib
import hmac
import pickle
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from river.anomaly import HalfSpaceTrees

from oseye.core.schema import UniversalEvent
from oseye.ml_engine.features import extract


# ML-R-03: MAC helpers accept the key as an explicit parameter — no module-level
# secret.  The key is managed by MLEngine and passed in on every save/load call.
def _compute_mac(path: Path, key: bytes) -> bytes:
    data = path.read_bytes()
    return hmac.new(key, data, hashlib.sha256).digest()


def _write_mac(path: Path, key: bytes) -> None:
    path.with_suffix(path.suffix + ".mac").write_bytes(_compute_mac(path, key))


def _verify_mac(path: str | Path, key: bytes) -> None:
    path = Path(path)
    mac_path = path.with_suffix(path.suffix + ".mac")
    if not mac_path.exists():
        raise ValueError(f"checkpoint: MAC file missing for {path}")
    expected = mac_path.read_bytes()
    actual = _compute_mac(path, key)
    if not hmac.compare_digest(expected, actual):
        raise ValueError(
            f"checkpoint: MAC mismatch for {path} — file may be tampered"
        )


_DEFAULT_N_TREES = 10
_DEFAULT_HEIGHT = 8
_DEFAULT_WINDOW = 250
_MIN_SAMPLES = 50
_MAX_MODELS = 10_000

# Per-event decay on the running max.
# After 1 000 events the max has decayed to ~37% of its peak value:
#   (1 - 0.001)^1000 ≈ 0.37
# This lets genuine anomalies score highly again after one extreme outlier.
_MAX_DECAY = 0.001


@dataclass
class _ModelState:
    model: HalfSpaceTrees
    count: int = 0
    decaying_max: float = 0.0


class _LRUStore:
    """OrderedDict-backed LRU store capped at `maxsize` entries."""

    def __init__(self, maxsize: int) -> None:
        self._cache: OrderedDict[str, _ModelState] = OrderedDict()
        self._maxsize = maxsize

    def get(self, key: str) -> _ModelState | None:
        if key not in self._cache:
            return None
        self._cache.move_to_end(key)
        return self._cache[key]

    def put(self, key: str, state: _ModelState) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self._maxsize:
                self._cache.popitem(last=False)
        self._cache[key] = state

    def __len__(self) -> int:
        return len(self._cache)

    def items(self) -> list[tuple[str, _ModelState]]:
        return list(self._cache.items())

    @property
    def maxsize(self) -> int:
        return self._maxsize


class EntityAnomalyDetector:
    """Maintains one HalfSpaceTrees model per (hostname, category) pair.

    Parameters
    ----------
    n_trees:
        Number of trees per model. More trees → more stable scores, higher CPU.
        Below 10: noisy. Above 50: diminishing returns. Default 25.
    height:
        Tree depth. Creates 2^height partitions per tree.
        Too low (< 8): zones too coarse, misses fine-grained anomalies.
        Too high (> 20): zones too fine, almost everything looks anomalous.
        Default 15 → 32 768 partitions, suits a 10-feature vector.
    window_size:
        Default HST sliding-window size (number of events the model "remembers").
        Smaller → adapts faster to drift, but also to slow attacks.
        Larger → more stable baseline, slower drift adaptation.
        Default 250. Override per category with `window_size_by_category`.
    window_size_by_category:
        Per-category window_size overrides.  Example:
          {"network": 100, "audit": 500}
        Use smaller values for high-volume categories (network, process) and
        larger values for low-volume ones (audit, device).
    min_samples:
        Events required before the model emits a non-zero score.
        Default 50 — enough for an initial baseline without a long blind period.
    max_models:
        LRU cap. Evicts the least-recently-seen model when the store is full.
        Default 10 000 — handles fleets of ~1 400 machines × 7 categories.
    """

    def __init__(
        self,
        n_trees: int = _DEFAULT_N_TREES,
        height: int = _DEFAULT_HEIGHT,
        window_size: int = _DEFAULT_WINDOW,
        window_size_by_category: dict[str, int] | None = None,
        min_samples: int = _MIN_SAMPLES,
        max_models: int = _MAX_MODELS,
    ) -> None:
        self._n_trees = n_trees
        self._height = height
        self._window_size = window_size
        self._window_by_cat: dict[str, int] = window_size_by_category or {}
        self._min_samples = min_samples
        self._store = _LRUStore(max_models)

    def _window_for(self, category: str) -> int:
        return self._window_by_cat.get(category, self._window_size)

    def _get_or_create(self, key: str, category: str) -> _ModelState:
        state = self._store.get(key)
        if state is None:
            # ML-03: derive a deterministic but entity-unique seed from the key so
            # that each (hostname, category) model has a distinct random partition,
            # making adversarial poisoning across entities much harder than seed=42.
            entity_seed = int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2 ** 31)
            model = HalfSpaceTrees(
                n_trees=self._n_trees,
                height=self._height,
                window_size=self._window_for(category),
                seed=entity_seed,
            )
            state = _ModelState(model=model)
            self._store.put(key, state)
        return state

    def learn_and_score(self, event: UniversalEvent) -> float:
        """Update the model with *event* and return an anomaly score in [0, 100].

        Returns 0.0 during cold-start (< min_samples seen for this entity).
        """
        key = f"{event.hostname}::{event.category}"
        state = self._get_or_create(key, event.category)
        features = extract(event)

        raw: float = state.model.score_one(features)  # type: ignore[no-untyped-call]
        state.model.learn_one(features)  # type: ignore[no-untyped-call]
        state.count += 1

        if state.count < self._min_samples:
            return 0.0

        # Decaying-max normalisation.
        state.decaying_max = max(state.decaying_max * (1.0 - _MAX_DECAY), raw)
        if state.decaying_max == 0.0:
            return 0.0
        return float(min(raw / state.decaying_max, 1.0) * 100.0)

    def score_only(self, entity_id: str, features: dict) -> float:
        """Score *features* for *entity_id* without updating the model (read-only).

        ML-R-01: used by MLEngine.score_event_readonly() so that the Decision
        Engine path does not double-train a model that MLWorker already updated.

        Returns 0.0 during cold-start (< min_samples seen) or if the entity
        has no model yet.
        """
        state = self._store.get(entity_id)
        if state is None or state.count < self._min_samples:
            return 0.0
        raw: float = state.model.score_one(features)  # type: ignore[no-untyped-call]
        if state.decaying_max == 0.0:
            return 0.0
        return float(min(raw / state.decaying_max, 1.0) * 100.0)

    def save(self, path: str | Path, hmac_key: bytes | None = None) -> None:
        """Persist the full detector state to *path* via pickle.

        Write is atomic: data goes to a tmp file alongside *path* then
        os.replace() swaps it in, so a crash mid-write never corrupts the
        existing checkpoint.

        Parameters
        ----------
        hmac_key:
            Optional secret key used to sign the checkpoint file with
            HMAC-SHA256 (ML-R-03). When ``None``, no MAC file is written.
        """
        import os

        path = Path(path)
        payload = {
            "n_trees": self._n_trees,
            "height": self._height,
            "window_size": self._window_size,
            "window_by_cat": self._window_by_cat,
            "min_samples": self._min_samples,
            "max_models": self._store.maxsize,
            "states": self._store.items(),
        }
        tmp = path.with_suffix(".pkl.tmp")
        try:
            with open(tmp, "wb") as fh:
                pickle.dump(payload, fh, protocol=pickle.HIGHEST_PROTOCOL)
            if hmac_key is not None:
                # ML-04: write MAC on the tmp file BEFORE the atomic rename so
                # that the final .pkl always has a companion .mac in place.
                # A crash between os.replace calls would leave the old .pkl with
                # its valid .mac, which is safe (old checkpoint, correct MAC).
                _write_mac(tmp, hmac_key)  # creates tmp.mac alongside tmp
                mac_tmp = Path(str(tmp) + ".mac")
                os.replace(tmp, path)
                os.replace(mac_tmp, Path(str(path) + ".mac"))
            else:
                os.replace(tmp, path)
        except Exception:
            tmp.unlink(missing_ok=True)
            Path(str(tmp) + ".mac").unlink(missing_ok=True)
            raise

    @classmethod
    def load(cls, path: str | Path, hmac_key: bytes | None = None) -> EntityAnomalyDetector:
        """Restore a detector from a pickle file written by :meth:`save`.

        Call on startup before the first event arrives to skip cold-start.

        Parameters
        ----------
        hmac_key:
            Optional secret key used to verify the checkpoint MAC (ML-R-03).
            When ``None``, MAC verification is skipped.
        """
        if hmac_key is not None:
            _verify_mac(path, hmac_key)
        with open(path, "rb") as fh:
            payload = pickle.load(fh)  # noqa: S301

        det = cls(
            n_trees=payload["n_trees"],
            height=payload["height"],
            window_size=payload["window_size"],
            window_size_by_category=payload["window_by_cat"],
            min_samples=payload["min_samples"],
            max_models=payload["max_models"],
        )
        for key, state in payload["states"]:
            det._store.put(key, state)
        return det

    @property
    def model_count(self) -> int:
        return len(self._store)
