"""eBPF adapter — converts a raw eBPF JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Literal

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import safe_int
from oseye.normalizer.secret_masker import mask

# Mapping: event_type → (category, normalised_type)
_EVENT_MAP: dict[
    str,
    tuple[Literal["file", "process", "network", "user", "device"], str],
] = {
    "execve": ("process", "exec"),
    "open": ("file", "open"),
    "openat": ("file", "open"),
    "connect": ("network", "connect"),
    "unlink": ("file", "delete"),
    "unlinkat": ("file", "delete"),
}


class EBPFAdapter:
    """Convertit un payload JSON eBPF → UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse *raw_json* and return a normalised :class:`UniversalEvent`.

        Routing by ``event_type`` field:

        * ``execve``         → category=``"process"``, type=``"exec"``
        * ``openat``/``open``→ category=``"file"``, type=``"open"``
        * ``connect``        → category=``"network"``, type=``"connect"``
        * ``unlink``/``unlinkat`` → category=``"file"``, type=``"delete"``

        For ``connect`` events, ``dst_ip`` and ``dst_port`` are extracted
        from the payload when present.
        For ``openat``/``open`` events, ``executable`` and ``resource`` are
        taken from ``filename`` (the file being opened).
        """
        data: dict[str, Any] = json.loads(raw_json)

        event_type_raw = str(data.get("event_type", "")).lower()

        if event_type_raw in _EVENT_MAP:
            category, event_type = _EVENT_MAP[event_type_raw]
        else:
            category = "process"
            event_type = event_type_raw

        # cmdline: prefer 'args' list joined, fall back to 'cmdline' string
        raw_args = data.get("args")
        if isinstance(raw_args, list):
            cmdline_str = " ".join(str(a) for a in raw_args)
        else:
            cmdline_str = str(data.get("cmdline", ""))
        cmdline = mask(cmdline_str)

        # executable: prefer "filename" (path of the file involved), fall back to "exe"
        executable = str(data.get("filename") or data.get("exe", ""))

        # resource: for file-open and exec events use the filename field
        if event_type_raw in ("open", "openat", "execve"):
            resource = str(data.get("filename", ""))
        else:
            resource = str(data.get("resource", ""))

        # Network fields — only dst_ip/dst_port are meaningful for connect events
        # src_ip/src_port are not emitted by the eBPF Go collector; do not read them
        dst_ip: str | None = None
        dst_port: int | None = None

        if category == "network":
            raw_dst_ip = data.get("dst_ip")
            if raw_dst_ip is not None:
                dst_ip = str(raw_dst_ip)

            raw_dst_port = data.get("dst_port")
            if raw_dst_port is not None:
                dst_port = safe_int(raw_dst_port) or None

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category=category,
            type=event_type,
            severity="info",
            collector="ebpf",
            os="linux",
            pid=safe_int(data.get("pid")),
            ppid=safe_int(data.get("ppid")),
            uid=safe_int(data.get("uid")),
            gid=safe_int(data.get("gid")),
            process_name=str(data.get("comm", "")),
            executable=executable,
            resource=resource,
            cmdline=cmdline,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
