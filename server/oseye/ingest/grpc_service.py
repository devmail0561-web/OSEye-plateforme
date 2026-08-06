"""gRPC AgentService servicer implementation."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import grpc
from cryptography.x509 import load_der_x509_certificate
from cryptography.x509.oid import NameOID

from oseye.bus.interface import EventBus
from oseye.core.observability import get_logger
from oseye.ingest.normalizer_bridge import pb_to_event
from oseye.ingest.validator import BatchValidator

if TYPE_CHECKING:
    pass

# Lazy imports — gen/ is auto-generated and has no type stubs.
# Imported at module level to avoid repeated dynamic imports in hot paths.
try:
    from server.gen import event_pb2 as _pb2
    from server.gen import event_pb2_grpc as _pb2_grpc
except ImportError:  # pragma: no cover — only missing in isolated unit tests
    _pb2 = None  # type: ignore[assignment,unused-ignore]
    _pb2_grpc = None  # type: ignore[assignment,unused-ignore]

_logger = get_logger(__name__)


def _extract_cn_from_context(context: grpc.ServicerContext) -> str | None:
    """Extract the Common Name from the mTLS client certificate.

    Implements SEC-PREV-001: agent_id MUST come from the cert CN, never from
    the request payload.
    """
    peer_identities = context.peer_identities()
    if not peer_identities:
        return None
    try:
        cert = load_der_x509_certificate(list(peer_identities)[0])
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            return None
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        _logger.warning("mtls_cn_parse_failed", error=str(exc))
        return None


def _require_cn(context: grpc.ServicerContext) -> str | None:
    """Return the CN or abort the RPC with UNAUTHENTICATED.

    SEC-PREV-001: any stream that cannot verify the caller's identity via the
    mTLS certificate CN is immediately terminated.  The caller's agent_id from
    the request payload is never trusted as a fallback.
    """
    cn = _extract_cn_from_context(context)
    if cn is None:
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "mTLS client certificate CN required")
    return cn


class AgentServiceServicer:
    """gRPC servicer that receives event batches from agents.

    SEC-PREV-001: agent_id is always taken from the CN of the client certificate
    via ``_require_cn``, never from ``request.agent_id``.
    """

    def __init__(self, bus: EventBus, validator: BatchValidator) -> None:
        self._bus = bus
        self._validator = validator

    # ------------------------------------------------------------------
    # IngestEvents — client-streaming RPC
    # ------------------------------------------------------------------

    def IngestEvents(  # noqa: N802
        self,
        request_iterator: Iterator[Any],
        context: grpc.ServicerContext,
    ) -> Any:
        """Receive a stream of IngestRequest batches from a single agent."""
        cn = _require_cn(context)
        if cn is None:
            return  # aborted above

        total_accepted = 0
        total_rejected = 0
        all_errors: list[str] = []

        loop: asyncio.AbstractEventLoop | None
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

        for request in request_iterator:
            result = self._validator.validate(request)
            total_accepted += result.accepted
            total_rejected += result.rejected
            all_errors.extend(result.errors)

            for event_index, pb_event in enumerate(request.events):
                is_rejected = any(
                    err.startswith(f"event {event_index}:") for err in result.errors
                )
                if is_rejected:
                    continue

                event = pb_to_event(pb_event, agent_id_override=cn)
                payload = event.model_dump_json().encode("utf-8")
                # pb_to_event already normalises the event — publish directly
                # to events:normalized so the storage writer can persist it
                # without a second normalisation pass.
                normalized_topic = "events:normalized"
                if loop is not None and loop.is_running():
                    asyncio.ensure_future(
                        self._bus.publish(normalized_topic, payload), loop=loop
                    )
                else:
                    try:
                        asyncio.run(self._bus.publish(normalized_topic, payload))
                    except RuntimeError:
                        _logger.error("bus_publish_failed", topic=normalized_topic)

            _logger.info(
                "batch_ingested",
                cn=cn,
                accepted=result.accepted,
                rejected=result.rejected,
            )

        if _pb2 is None:  # pragma: no cover
            return None

        return _pb2.IngestResponse(
            accepted=total_accepted,
            rejected=total_rejected,
            errors=all_errors,
        )

    # ------------------------------------------------------------------
    # ReceivePolicy — server-streaming RPC
    # ------------------------------------------------------------------

    def ReceivePolicy(  # noqa: N802
        self,
        request: Any,
        context: grpc.ServicerContext,
    ) -> Iterator[Any]:
        """Stream SurveillanceProfilePB updates to the agent.

        SEC-PREV-001: aborts with UNAUTHENTICATED if no mTLS CN is present.
        """
        cn = _require_cn(context)
        if cn is None:
            return  # aborted above

        topic = f"policy:push:{cn}"
        _logger.info("policy_stream_opened", agent_id=cn, topic=topic)

        async def _collect() -> list[bytes]:
            sub = await self._bus.subscribe(topic)
            msgs: list[bytes] = []
            async with asyncio.timeout(30.0):
                async for msg in sub:
                    msgs.append(msg)
                    break
            return msgs

        while context.is_active() is not False:
            try:
                msgs = asyncio.run(_collect())
            except TimeoutError:
                continue
            except Exception as exc:  # noqa: BLE001
                _logger.error("policy_stream_error", error=str(exc))
                break

            if _pb2 is None:  # pragma: no cover
                break

            for raw in msgs:
                try:
                    data = json.loads(raw)
                    profile = _pb2.SurveillanceProfilePB(
                        name=data.get("name", ""),
                        description=data.get("description", ""),
                        version=data.get("version", 1),
                        config_json=json.dumps(data.get("config", {})).encode("utf-8"),
                    )
                    yield profile
                except Exception as exc:  # noqa: BLE001
                    _logger.error("policy_deserialize_error", error=str(exc))

    # ------------------------------------------------------------------
    # StreamCommands — server-streaming RPC
    # ------------------------------------------------------------------

    def StreamCommands(  # noqa: N802
        self,
        request: Any,
        context: grpc.ServicerContext,
    ) -> Iterator[Any]:
        """Stream AgentCommand messages to the agent.

        SEC-PREV-001: aborts with UNAUTHENTICATED if no mTLS CN is present.
        """
        cn = _require_cn(context)
        if cn is None:
            return  # aborted above

        topic = f"commands:{cn}"
        _logger.info("commands_stream_opened", agent_id=cn, topic=topic)

        async def _collect() -> list[bytes]:
            sub = await self._bus.subscribe(topic)
            msgs: list[bytes] = []
            async with asyncio.timeout(30.0):
                async for msg in sub:
                    msgs.append(msg)
                    break
            return msgs

        while context.is_active() is not False:
            try:
                msgs = asyncio.run(_collect())
            except TimeoutError:
                continue
            except Exception as exc:  # noqa: BLE001
                _logger.error("commands_stream_error", error=str(exc))
                break

            if _pb2 is None:  # pragma: no cover
                break

            for raw in msgs:
                try:
                    data = json.loads(raw)
                    cmd = _pb2.AgentCommand(
                        command_type=data.get("command_type", ""),
                        payload_json=json.dumps(data.get("payload", {})).encode("utf-8"),
                    )
                    yield cmd
                except Exception as exc:  # noqa: BLE001
                    _logger.error("command_deserialize_error", error=str(exc))


def register_servicer(servicer: AgentServiceServicer, server: Any) -> None:
    """Register the servicer with a gRPC server instance."""
    if _pb2_grpc is None:  # pragma: no cover
        raise RuntimeError("server.gen not available — run scripts/generate_proto.sh")
    _pb2_grpc.add_AgentServiceServicer_to_server(
        servicer, server
    )
