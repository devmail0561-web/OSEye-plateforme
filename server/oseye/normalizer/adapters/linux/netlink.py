"""Netlink adapter — converts a raw netlink JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent


def _split_addr(addr: str) -> tuple[str, int]:
    """Split an ``ip:port`` (or ``[ipv6]:port``) string into (ip, port)."""
    if not addr:
        return "", 0
    if addr.startswith("["):
        # IPv6 literal: [::1]:port
        end = addr.rfind("]:")
        if end != -1:
            ip = addr[1:end]
            port = addr[end + 2 :]
        else:
            return addr, 0
    else:
        idx = addr.rfind(":")
        if idx == -1:
            return addr, 0
        ip = addr[:idx]
        port = addr[idx + 1 :]
    try:
        return ip, int(port)
    except ValueError:
        return ip, 0


class NetlinkAdapter:
    """Convertit un payload JSON netlink → UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse *raw_json* and return a normalised :class:`UniversalEvent`.

        * ``category`` = ``"network"``
        * ``type``     = ``payload["event"]`` (``new`` | ``closed``)
        * ``src_ip``/``src_port`` parsed from ``local_addr`` (``ip:port``)
        * ``dst_ip``/``dst_port`` parsed from ``remote_addr``
        """
        data: dict[str, Any] = json.loads(raw_json)

        src_ip, src_port = _split_addr(str(data.get("local_addr", "")))
        dst_ip, dst_port = _split_addr(str(data.get("remote_addr", "")))

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="network",
            type=str(data.get("event", "")),
            severity="info",
            collector="netlink",
            os="linux",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=str(data.get("proto", "")),
        )
