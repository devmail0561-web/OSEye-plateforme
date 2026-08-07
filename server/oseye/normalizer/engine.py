"""Normalizer engine — routes RawEvent payloads to the correct adapter."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import Any

from oseye.bus.interface import EventBus
from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux.auditd import AuditdAdapter
from oseye.normalizer.adapters.linux.ebpf import EBPFAdapter
from oseye.normalizer.adapters.linux.fanotify import FanotifyAdapter
from oseye.normalizer.adapters.linux.inotify import InotifyAdapter
from oseye.normalizer.adapters.linux.journald import JournaldAdapter
from oseye.normalizer.adapters.linux.netlink import NetlinkAdapter
from oseye.normalizer.adapters.linux.procfs import ProcfsAdapter
from oseye.normalizer.adapters.linux.syslog import SyslogAdapter
from oseye.normalizer.adapters.linux.udev import UdevAdapter

logger = logging.getLogger(__name__)


class NormalizerEngine:
    """Dispatche les RawEvent vers le bon adapter selon (os, collector).

    Les ``UniversalEvent`` normalisés sont publiés sur le topic
    ``"events:normalized"`` du bus.
    """

    def __init__(self, bus: EventBus, hostname: str) -> None:
        self._bus = bus
        self._hostname = hostname
        # Registry: (os_name, source) → normalize callable
        self._adapters: dict[tuple[str, str], Callable[..., Any]] = {}

        # Register Linux adapters by default
        self.register_adapter("linux", "procfs", ProcfsAdapter())
        self.register_adapter("linux", "auditd", AuditdAdapter())
        self.register_adapter("linux", "ebpf", EBPFAdapter())
        self.register_adapter("linux", "fanotify", FanotifyAdapter())
        self.register_adapter("linux", "inotify", InotifyAdapter())
        self.register_adapter("linux", "netlink", NetlinkAdapter())
        self.register_adapter("linux", "journald", JournaldAdapter())
        self.register_adapter("linux", "syslog", SyslogAdapter())
        self.register_adapter("linux", "udev", UdevAdapter())

    def register_adapter(self, os_name: str, source: str, adapter: object) -> None:
        """Enregistre *adapter* pour la paire (*os_name*, *source*)."""
        self._adapters[(os_name.lower(), source.lower())] = getattr(adapter, "normalize")

    async def process(
        self,
        raw_payload: bytes,
        source: str,
        os_name: str,
        agent_id: str,
    ) -> UniversalEvent | None:
        """Normalise *raw_payload* et le publie sur ``events:normalized``.

        Returns the normalised :class:`UniversalEvent`, or ``None`` when no
        adapter is registered for the given (*os_name*, *source*) pair or when
        any error occurs during normalisation.
        """
        key = (os_name.lower(), source.lower())
        adapter = self._adapters.get(key)

        if adapter is None:
            logger.warning(
                "No adapter registered for os=%r source=%r — payload discarded",
                os_name,
                source,
            )
            return None

        # H8/F10 fix: validate agent_id as UUID once here, before dispatching.
        try:
            parsed_agent_id = str(uuid.UUID(agent_id))
        except (ValueError, AttributeError):
            logger.error(
                "Invalid agent_id %r for source=%r — payload discarded",
                agent_id,
                source,
            )
            return None

        # C1/F12 fix: catch all adapter exceptions so one bad payload cannot
        # crash the normalizer coroutine or drop subsequent valid events.
        try:
            event: UniversalEvent = adapter(raw_payload, self._hostname, parsed_agent_id)
        except Exception:
            logger.exception(
                "Adapter error for os=%r source=%r — payload discarded",
                os_name,
                source,
            )
            return None

        try:
            await self._bus.publish("events:normalized", event.model_dump_json().encode())
        except Exception:
            logger.exception("Bus publish failed for event_id=%s", event.event_id)
            # Return the event even if publish failed — normalisation succeeded.

        return event
