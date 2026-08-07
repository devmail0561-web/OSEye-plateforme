"""Auditd adapter — converts a raw auditd JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Literal

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import safe_int
from oseye.normalizer.secret_masker import mask

# Mapping: syscall name → (category, event_type)
_SYSCALL_MAP: dict[
    str,
    tuple[Literal["file", "process", "network", "user", "device"], str],
] = {
    "execve": ("process", "exec"),
    "open": ("file", "open"),
    "openat": ("file", "open"),
    "connect": ("network", "connect"),
}


class AuditdAdapter:
    """Convertit un payload JSON auditd → UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse *raw_json* and return a normalised :class:`UniversalEvent`.

        Routing by ``type`` field:

        * ``SYSCALL execve``       → category=``"process"``, type=``"exec"``
        * ``SYSCALL open/openat``  → category=``"file"``, type=``"open"``
        * ``SYSCALL connect``      → category=``"network"``, type=``"connect"``
        * Other syscalls           → category=``"process"``, type=*syscall_name*

        severity is always ``"info"``.
        """
        data: dict[str, Any] = json.loads(raw_json)

        record_type = str(data.get("type", "")).upper()
        syscall = str(data.get("syscall", "")).lower()

        if record_type == "SYSCALL" and syscall in _SYSCALL_MAP:
            category, event_type = _SYSCALL_MAP[syscall]
        else:
            category = "process"
            event_type = syscall if syscall else record_type.lower()

        cmdline = mask(str(data.get("cmdline", "")))
        exe = str(data.get("exe", ""))
        comm = str(data.get("comm", ""))

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category=category,
            type=event_type,
            severity="info",
            collector="auditd",
            os="linux",
            pid=safe_int(data.get("pid")),
            ppid=safe_int(data.get("ppid")),
            uid=safe_int(data.get("uid")),
            gid=safe_int(data.get("gid")),
            process_name=comm,
            executable=exe,
            cmdline=cmdline,
        )
