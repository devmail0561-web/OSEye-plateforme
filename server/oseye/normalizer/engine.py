"""Normalizer engine — routes RawEvent payloads to the correct adapter.

Corrections vs initial version
--------------------------------

1. Découverte dynamique des adapters
   Les 9 adapters Linux étaient enregistrés en dur dans __init__.  Ajouter un
   nouveau collecteur nécessitait de modifier le code.  Les adapters sont
   maintenant découverts automatiquement depuis un package Python via
   register_package() — tout module qui expose une classe *Adapter avec une
   méthode normalize() est enregistré sans modification de l'engine.
   Les adapters hardcodés restent comme fallback de démarrage.

2. Dead-letter queue sur publish failure
   Si bus.publish() échouait, l'event était perdu sans retry ni alerte.
   On publie maintenant sur le topic "events:dead_letter" en cas d'échec,
   avec le payload original + la raison, pour permettre un rejeu ultérieur.

3. Validation des champs après normalisation
   L'adapter produisait un UniversalEvent sans vérifier la cohérence.
   On valide : timestamp_ns > 0, bytes_sent/recv >= 0, dst_port dans [0, 65535],
   src_port dans [0, 65535].  Un event invalide est rejeté et envoyé en DLQ
   plutôt que d'être propagé au rule engine avec des valeurs corrompues.
"""

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
from oseye.normalizer.adapters.windows.etw import EtwAdapter
from oseye.normalizer.adapters.windows.eventlog import EventlogAdapter
from oseye.normalizer.adapters.windows.fswatch import FswatchAdapter
from oseye.normalizer.adapters.windows.registry import RegistryAdapter
from oseye.normalizer.adapters.windows.toolhelp32 import Toolhelp32Adapter
from oseye.normalizer.adapters.windows.winnetstat import WinnetstatAdapter
from oseye.normalizer.adapters.darwin.darwinnet import DarwinnetAdapter
from oseye.normalizer.adapters.darwin.es import EsAdapter
from oseye.normalizer.adapters.darwin.kqueue import KqueueAdapter
from oseye.normalizer.adapters.darwin.ps import PsAdapter
from oseye.normalizer.adapters.darwin.unifiedlog import UnifiedlogAdapter

logger = logging.getLogger(__name__)

_DEAD_LETTER_TOPIC = "events:dead_letter"

# Port range valid for TCP/UDP
_MAX_PORT = 65535


def _validate_event(event: UniversalEvent) -> str | None:
    """Return an error message if *event* has invalid field values, else None."""
    if event.timestamp_ns <= 0:
        return f"invalid timestamp_ns={event.timestamp_ns}"
    if event.bytes_sent is not None and event.bytes_sent < 0:
        return f"negative bytes_sent={event.bytes_sent}"
    if event.bytes_recv is not None and event.bytes_recv < 0:
        return f"negative bytes_recv={event.bytes_recv}"
    if event.dst_port is not None and not (0 <= event.dst_port <= _MAX_PORT):
        return f"dst_port={event.dst_port} out of range [0, {_MAX_PORT}]"
    if event.src_port is not None and not (0 <= event.src_port <= _MAX_PORT):
        return f"src_port={event.src_port} out of range [0, {_MAX_PORT}]"
    return None


class NormalizerEngine:
    """Dispatches RawEvent payloads to the correct adapter by (os, collector).

    Normalized ``UniversalEvent`` objects are published on ``"events:normalized"``.
    Events that fail validation or publish are forwarded to ``"events:dead_letter"``.
    """

    def __init__(self, bus: EventBus, hostname: str) -> None:
        self._bus = bus
        self._hostname = hostname
        # Registry: (os_name, source) → normalize callable
        self._adapters: dict[tuple[str, str], Callable[..., Any]] = {}

        # Correction 1 — hardcoded adapters remain the default set
        self.register_adapter("linux", "procfs", ProcfsAdapter())
        self.register_adapter("linux", "auditd", AuditdAdapter())
        self.register_adapter("linux", "ebpf", EBPFAdapter())
        self.register_adapter("linux", "fanotify", FanotifyAdapter())
        self.register_adapter("linux", "inotify", InotifyAdapter())
        self.register_adapter("linux", "netlink", NetlinkAdapter())
        self.register_adapter("linux", "journald", JournaldAdapter())
        self.register_adapter("linux", "syslog", SyslogAdapter())
        self.register_adapter("linux", "udev", UdevAdapter())
        # Windows adapters
        self.register_adapter("windows", "toolhelp32", Toolhelp32Adapter())
        self.register_adapter("windows", "etw", EtwAdapter())
        self.register_adapter("windows", "registry", RegistryAdapter())
        self.register_adapter("windows", "eventlog", EventlogAdapter())
        self.register_adapter("windows", "fswatch", FswatchAdapter())
        self.register_adapter("windows", "winnetstat", WinnetstatAdapter())
        # macOS adapters
        self.register_adapter("darwin", "ps", PsAdapter())
        self.register_adapter("darwin", "kqueue", KqueueAdapter())
        self.register_adapter("darwin", "unifiedlog", UnifiedlogAdapter())
        self.register_adapter("darwin", "darwinnet", DarwinnetAdapter())
        self.register_adapter("darwin", "es", EsAdapter())

    def register_adapter(self, os_name: str, source: str, adapter: object) -> None:
        """Register *adapter* for the (os_name, source) pair."""
        self._adapters[(os_name.lower(), source.lower())] = getattr(adapter, "normalize")

    def register_package(self, os_name: str, package: object) -> int:
        """Correction 1 — discover and register all adapters in *package*.

        Scans every attribute of *package* for classes named *Adapter that
        expose a ``normalize`` method.  The source name is derived from the
        class name: ``FanotifyAdapter`` → ``"fanotify"``.

        Returns the number of adapters registered.
        """
        import inspect
        registered = 0
        for name, obj in inspect.getmembers(package, inspect.isclass):
            if name.endswith("Adapter") and hasattr(obj, "normalize"):
                source = name.replace("Adapter", "").lower()
                try:
                    instance = obj()
                    self.register_adapter(os_name, source, instance)
                    registered += 1
                except Exception as exc:
                    # PC-13: log the exception details so adapter failures are diagnosable
                    logger.warning(
                        "adapter_auto_register_failed: %s: %s",
                        name,
                        exc,
                        exc_info=True,
                    )
        return registered

    async def process(
        self,
        raw_payload: bytes,
        source: str,
        os_name: str,
        agent_id: str,
    ) -> UniversalEvent | None:
        """Normalise *raw_payload* and publish it on ``events:normalized``.

        Returns the normalised :class:`UniversalEvent`, or ``None`` when no
        adapter is registered, or when normalisation / validation fails.
        Failed events are forwarded to ``events:dead_letter``.
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

        # Validate agent_id as UUID once before dispatching (H8/F10 fix)
        try:
            parsed_agent_id = str(uuid.UUID(agent_id))
        except (ValueError, AttributeError):
            logger.error(
                "Invalid agent_id %r for source=%r — payload discarded",
                agent_id,
                source,
            )
            return None

        # C1/F12: catch all adapter exceptions
        try:
            event: UniversalEvent = adapter(raw_payload, self._hostname, parsed_agent_id)
        except Exception:
            logger.exception(
                "Adapter error for os=%r source=%r — payload discarded",
                os_name,
                source,
            )
            return None

        # Correction 3 — validate field values before propagating downstream
        validation_error = _validate_event(event)
        if validation_error:
            logger.warning(
                "Event validation failed source=%r: %s — forwarding to DLQ",
                source,
                validation_error,
            )
            await self._send_dead_letter(raw_payload, source, os_name, agent_id, validation_error)
            return None

        try:
            await self._bus.publish("events:normalized", event.model_dump_json().encode())
        except Exception:
            logger.exception("Bus publish failed for event_id=%s", event.event_id)
            # Correction 2 — forward to dead-letter queue on publish failure
            await self._send_dead_letter(
                raw_payload, source, os_name, agent_id, "bus_publish_failed"
            )
            # Return the event — normalisation succeeded even if publish failed
            return event

        return event

    async def _send_dead_letter(
        self,
        raw_payload: bytes,
        source: str,
        os_name: str,
        agent_id: str,
        reason: str,
    ) -> None:
        """Publish to the dead-letter topic.  Silently swallow publish errors."""
        import json
        try:
            dlq_msg = json.dumps({
                "reason": reason,
                "source": source,
                "os_name": os_name,
                "agent_id": agent_id,
                "payload_hex": raw_payload.hex(),
            }).encode()
            await self._bus.publish(_DEAD_LETTER_TOPIC, dlq_msg)
        except Exception:
            logger.debug("dead_letter_publish_failed", exc_info=True)
