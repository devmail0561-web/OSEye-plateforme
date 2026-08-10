"""Netlink adapter — converts a raw netlink JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts


def _split_addr(addr: str) -> tuple[str, int]:
    """Split ip:port or [ipv6]:port into (ip, port). F16 fix: strip [] from bare IPv6."""
    if not addr:
        return "", 0
    if addr.startswith("["):
        end = addr.rfind("]:")
        if end != -1:
            return addr[1:end], _parse_port(addr[end + 2:])
        # Bare IPv6 in brackets without port: strip the brackets.
        if addr.endswith("]"):
            return addr[1:-1], 0
        return addr, 0
    idx = addr.rfind(":")
    if idx == -1:
        return addr, 0
    return addr[:idx], _parse_port(addr[idx + 1:])


def _parse_port(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


class NetlinkAdapter:
    """Convertit un payload JSON netlink -> UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse raw_json and return a normalised UniversalEvent.

        Splits local_addr/remote_addr into separate ip and port fields.
        timestamp_ns uses the agent-side value when present (H10 fix).
        """
        data: dict[str, Any] = json.loads(raw_json)
        src_ip, src_port = _split_addr(str(data.get("local_addr", "")))
        dst_ip, dst_port = _split_addr(str(data.get("remote_addr", "")))

        # BUG-010: use None instead of empty string for absent IP fields so that
        # downstream components can distinguish "no address" from "address=''".
        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="network",
            type=str(data.get("event", "")),
            severity="info",
            collector="netlink",
            os="linux",
            src_ip=src_ip if src_ip else None,
            src_port=src_port if src_port else None,
            dst_ip=dst_ip if dst_ip else None,
            dst_port=dst_port if dst_port else None,
            protocol=str(data.get("proto", "")) or None,
        )
