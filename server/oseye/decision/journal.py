"""Decision Journal — append-only hash chain (BLAKE3).

Each entry hashes its content + the previous hash to form a tamper-evident chain.
The genesis entry uses a zero hash as prev_hash.
"""

from __future__ import annotations

import json
import re
from collections import deque
from typing import TYPE_CHECKING

import blake3

if TYPE_CHECKING:
    from oseye.core.schema import Decision

_GENESIS_HASH = "0" * 64


class DecisionJournal:
    """Maintains a running BLAKE3 hash chain over committed decisions.

    Not thread-safe — access must be serialised by the caller (e.g., asyncio
    single event-loop, or an asyncio.Lock).

    Parameters
    ----------
    last_hash:  Seed the chain from a known hash (used on server restart to
                resume from the last persisted decision).  Defaults to the
                genesis zero-hash for a fresh chain.
    """

    def __init__(self, last_hash: str = _GENESIS_HASH) -> None:
        self._last_hash: str = last_hash
        # D-06: keep a rolling history of prev hashes so rollback() can validate
        # that the caller holds a genuine prev_hash from a recent commit().
        self._commit_history: deque[str] = deque(maxlen=20)

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def commit(self, decision_fields: dict[str, object]) -> tuple[str, str]:
        """Compute (prev_journal_hash, journal_hash) for a new decision.

        *decision_fields* should contain the stable, deterministic fields that
        define the decision (excluding journal hashes themselves).

        Returns the pair ``(prev_hash, new_hash)``.  The caller MUST persist
        the decision successfully before treating the chain as advanced; use
        :meth:`rollback` to undo on persist failure.
        """
        prev = self._last_hash
        payload = json.dumps(decision_fields, sort_keys=True, default=str).encode()
        new_hash = blake3.blake3(prev.encode() + payload).hexdigest()
        self._last_hash = new_hash
        # D-06: record prev so rollback() can confirm it is a genuine chain point
        self._commit_history.append(prev)
        return prev, new_hash

    _HASH_RE = re.compile(r"[0-9a-f]{64}")

    def rollback(self, prev_hash: str) -> None:
        """Revert _last_hash to *prev_hash* after a failed persist.

        Must be called with the ``prev_hash`` returned by the matching
        :meth:`commit` call while the journal lock is still held (or
        re-acquired).
        """
        if not self._HASH_RE.fullmatch(prev_hash):
            raise ValueError(f"Invalid prev_hash format: {prev_hash!r}")
        # D-06: reject a rollback to a hash that was never recorded by commit()
        # (allows the genesis hash as a valid starting point on a fresh chain).
        if prev_hash not in self._commit_history and prev_hash != _GENESIS_HASH:
            raise ValueError(
                f"rollback refused: prev_hash not found in recent journal history: {prev_hash!r}"
            )
        self._last_hash = prev_hash

    def verify_chain(
        self, decisions: list[Decision], start_hash: str | None = None
    ) -> list[int]:
        """Return the list of indices where the chain is broken.

        An empty list means the chain is intact.

        Parameters
        ----------
        start_hash:
            D-05: seed the verification from a known hash instead of the hardcoded
            genesis.  When *decisions* comes from the DB, pass the first entry's
            ``prev_journal_hash`` (or the genesis hash for the very first entry)
            so partial-chain verification is correct.  Defaults to the genesis hash.
        """
        broken: list[int] = []
        prev = start_hash if start_hash is not None else _GENESIS_HASH

        for i, decision in enumerate(decisions):
            if decision.prev_journal_hash != prev:
                broken.append(i)
            fields = _decision_to_fields(decision)
            payload = json.dumps(fields, sort_keys=True, default=str).encode()
            expected = blake3.blake3(prev.encode() + payload).hexdigest()
            if decision.journal_hash != expected:
                broken.append(i)
            prev = decision.journal_hash

        return broken


def _decision_to_fields(decision: Decision) -> dict[str, object]:
    """Stable dict representation used for hashing (no journal fields)."""
    return {
        "decision_id": str(decision.decision_id),
        "created_at": decision.created_at.isoformat(),
        "decision_type": decision.decision_type,
        "rule_score": decision.rule_score,
        "ml_score": decision.ml_score,
        "ti_score": decision.ti_score,
        "correlation_depth": decision.correlation_depth,
        "final_score": decision.final_score,
        "entity_id": decision.entity_id,
        "trigger_alert_id": (
            str(decision.trigger_alert_id) if decision.trigger_alert_id else None
        ),
        "incident_chain_id": (
            str(decision.incident_chain_id) if decision.incident_chain_id else None
        ),
        "policy_version": decision.policy_version,
        "explanation": decision.explanation,
    }
