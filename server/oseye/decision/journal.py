"""Decision Journal — append-only hash chain (BLAKE3).

Each entry hashes its content + the previous hash to form a tamper-evident chain.
The genesis entry uses a zero hash as prev_hash.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import blake3

if TYPE_CHECKING:
    from oseye.core.schema import Decision

_GENESIS_HASH = "0" * 64


class DecisionJournal:
    """Maintains a running BLAKE3 hash chain over committed decisions.

    Not thread-safe — access must be serialised by the caller (e.g., asyncio
    single event-loop, or an asyncio.Lock).
    """

    def __init__(self) -> None:
        self._last_hash: str = _GENESIS_HASH

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def commit(self, decision_fields: dict[str, object]) -> tuple[str, str]:
        """Compute (prev_journal_hash, journal_hash) for a new decision.

        *decision_fields* should contain the stable, deterministic fields that
        define the decision (excluding journal hashes themselves).

        Returns the pair ``(prev_hash, new_hash)`` that must be stored on the
        Decision object before persisting.
        """
        prev = self._last_hash
        payload = json.dumps(decision_fields, sort_keys=True, default=str).encode()
        new_hash = blake3.blake3(prev.encode() + payload).hexdigest()
        self._last_hash = new_hash
        return prev, new_hash

    def verify_chain(self, decisions: list[Decision]) -> list[int]:
        """Return the list of indices where the chain is broken.

        An empty list means the chain is intact.
        """
        broken: list[int] = []
        prev = _GENESIS_HASH

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
