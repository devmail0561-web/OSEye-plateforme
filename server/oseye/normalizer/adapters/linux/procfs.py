"""Procfs adapter — converts a raw procfs JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.secret_masker import mask


class ProcfsAdapter:
    """Convertit un payload JSON procfs → UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse *raw_json* and return a normalised :class:`UniversalEvent`.

        * ``category`` = ``"process"``
        * ``type``     = ``"snapshot"``  (procfs produces periodic snapshots)
        * ``severity`` = ``"info"``
        * ``collector``= ``"procfs"``

        Mapped fields: pid, ppid, uid, gid, process_name (← name),
        executable (← exe), cmdline.
        """
        data: dict[str, Any] = json.loads(raw_json)

        cmdline = mask(str(data.get("cmdline", "")))

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="process",
            type="snapshot",
            severity="info",
            collector="procfs",
            os="linux",
            pid=int(data.get("pid", 0)),
            ppid=int(data.get("ppid", 0)),
            uid=int(data.get("uid", 0)),
            gid=int(data.get("gid", 0)),
            process_name=str(data.get("name", "")),
            executable=str(data.get("exe", "")),
            cmdline=cmdline,
        )
