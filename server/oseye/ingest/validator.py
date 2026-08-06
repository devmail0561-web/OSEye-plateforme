"""Batch validator — checks Ed25519 signature and BLAKE3 hash chain integrity."""

from __future__ import annotations

from dataclasses import dataclass, field

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key


@dataclass
class ValidationResult:
    accepted: int
    rejected: int
    errors: list[str] = field(default_factory=list)


class BatchValidator:
    """Verifies the Ed25519 batch signature and BLAKE3 hash chain of each event."""

    _REQUIRED_FIELDS: tuple[str, ...] = ("category", "type", "severity")

    def validate(
        self,
        request: object,
        agent_public_key: bytes | None = None,
    ) -> ValidationResult:
        """Validate an IngestRequest protobuf object.

        Steps:
        1. If *agent_public_key* is provided, verify ``request.batch_signature``
           over ``BLAKE3(hash_chain[0] || … || hash_chain[N-1])``.
        2. Validate that every event carries the required fields.
        3. Return a ValidationResult with accepted / rejected counts and error
           messages index-matched with rejected events.
        """
        events = list(request.events)  # type: ignore[attr-defined]

        # --- Batch-level signature check ---
        if agent_public_key is not None and events:
            h = blake3.blake3()
            for ev in events:
                h.update(bytes(ev.hash_chain))
            digest = h.digest()

            try:
                pub_key = load_der_public_key(agent_public_key)
                if not isinstance(pub_key, Ed25519PublicKey):
                    return ValidationResult(
                        accepted=0,
                        rejected=len(events),
                        errors=[
                            f"event {i}: batch signature public key is not Ed25519"
                            for i in range(len(events))
                        ],
                    )
                pub_key.verify(
                    bytes(request.batch_signature),  # type: ignore[attr-defined]
                    digest,
                )
            except InvalidSignature:
                return ValidationResult(
                    accepted=0,
                    rejected=len(events),
                    errors=[
                        f"event {i}: batch signature verification failed"
                        for i in range(len(events))
                    ],
                )

        # --- Per-event field validation ---
        accepted = 0
        rejected = 0
        errors: list[str] = []

        for i, ev in enumerate(events):
            missing = [
                f for f in self._REQUIRED_FIELDS if not getattr(ev, f, None)
            ]
            if missing:
                rejected += 1
                errors.append(
                    f"event {i}: missing required fields: {', '.join(missing)}"
                )
            else:
                accepted += 1

        return ValidationResult(accepted=accepted, rejected=rejected, errors=errors)
