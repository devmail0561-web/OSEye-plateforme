"""Protobuf ↔ Pydantic bridge — converts UniversalEventPB to UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.secret_masker import mask


def pb_to_event(pb: Any, agent_id_override: str | None = None) -> UniversalEvent:
    """Map a UniversalEventPB protobuf message to a UniversalEvent Pydantic model.

    Parameters
    ----------
    pb:
        A ``UniversalEventPB`` protobuf instance.
    agent_id_override:
        When provided (the CN extracted from the mTLS client certificate),
        this value replaces ``pb.agent_id`` to enforce SEC-PREV-001.
    """
    # --- event_id ---
    raw_event_id = bytes(pb.event_id)
    if len(raw_event_id) == 16:
        event_id = uuid.UUID(bytes=raw_event_id)
    elif raw_event_id:
        # Attempt hex / string fallback
        try:
            event_id = uuid.UUID(raw_event_id.decode("utf-8", errors="replace"))
        except (ValueError, AttributeError):
            event_id = uuid.uuid4()
    else:
        event_id = uuid.uuid4()

    # --- agent_id (SEC-PREV-001: CN overrides pb.agent_id) ---
    if agent_id_override is not None:
        try:
            agent_id = uuid.UUID(agent_id_override)
        except ValueError:
            # CN is not a UUID — use a deterministic UUID-5 derived from the CN
            agent_id = uuid.uuid5(uuid.NAMESPACE_DNS, agent_id_override)
    else:
        raw_agent_id = bytes(pb.agent_id)
        if len(raw_agent_id) == 16:
            agent_id = uuid.UUID(bytes=raw_agent_id)
        elif raw_agent_id:
            try:
                agent_id = uuid.UUID(raw_agent_id.decode("utf-8", errors="replace"))
            except (ValueError, AttributeError):
                agent_id = uuid.uuid4()
        else:
            agent_id = uuid.uuid4()

    # --- extra_json ---
    extra: dict[str, object] = {}
    raw_extra = bytes(pb.extra_json)
    if raw_extra:
        try:
            parsed = json.loads(raw_extra.decode("utf-8"))
            if isinstance(parsed, dict):
                extra = parsed
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # --- hash_chain / signature (stored as hex strings in Pydantic model) ---
    hash_chain_bytes = bytes(pb.hash_chain)
    hash_chain_str = hash_chain_bytes.hex() if hash_chain_bytes else ""

    signature_bytes = bytes(pb.signature)
    signature_str = signature_bytes.hex() if signature_bytes else None

    # --- optional int fields (0 → None for port/bytes fields) ---
    src_port = pb.src_port if pb.src_port != 0 else None
    dst_port = pb.dst_port if pb.dst_port != 0 else None
    bytes_sent = pb.bytes_sent if pb.bytes_sent != 0 else None
    bytes_recv = pb.bytes_recv if pb.bytes_recv != 0 else None
    session_id = pb.session_id if pb.session_id != 0 else None

    return UniversalEvent(
        event_id=event_id,
        timestamp_ns=pb.timestamp_ns,
        hostname=pb.hostname,
        agent_id=agent_id,
        category=pb.category,
        type=pb.type,
        severity=pb.severity,
        collector=pb.collector,
        os=pb.os if pb.os else "linux",
        uid=pb.uid,
        gid=pb.gid,
        pid=pb.pid,
        ppid=pb.ppid,
        process_name=pb.process_name,
        executable=pb.executable,
        cmdline=mask(pb.cmdline),
        cwd=pb.cwd,
        session_id=session_id,
        resource=pb.resource,
        result=pb.result if pb.result else "success",
        file_hash_before=pb.file_hash_before if pb.file_hash_before else None,
        file_hash_after=pb.file_hash_after if pb.file_hash_after else None,
        src_ip=pb.src_ip if pb.src_ip else None,
        src_port=src_port,
        dst_ip=pb.dst_ip if pb.dst_ip else None,
        dst_port=dst_port,
        protocol=pb.protocol if pb.protocol else None,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        hash_chain=hash_chain_str,
        signature=signature_str,
        extra=extra,
    )
