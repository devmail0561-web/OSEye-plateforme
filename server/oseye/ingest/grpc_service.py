"""gRPC AgentService servicer implementation."""

from __future__ import annotations

import asyncio
import json
import queue as _queue
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

    gRPC Python's ``peer_identities()`` returns the client certificate CN values
    directly as UTF-8–encoded bytes, not full DER-encoded certificates.  We
    decode the first identity and return it as a string.
    """
    peer_identities = context.peer_identities()
    if not peer_identities:
        return None
    try:
        raw = list(peer_identities)[0]
        # Try direct UTF-8 decode first (gRPC Python native behaviour).
        if isinstance(raw, (bytes, bytearray)):
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                pass
            # Fallback: attempt DER certificate parse (some grpc builds return full cert).
            cert = load_der_x509_certificate(raw)
            attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not attrs:
                return None
            value = attrs[0].value
            return value if isinstance(value, str) else value.decode("utf-8", errors="replace")
        return str(raw)
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

    def __init__(
        self,
        bus: EventBus,
        validator: BatchValidator,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._bus = bus
        self._validator = validator
        self._loop = loop

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

        for request in request_iterator:
            result = self._validator.validate(request)
            total_accepted += result.accepted
            total_rejected += result.rejected
            # [MEDIUM-4] cap accumulated errors to avoid unbounded growth
            if len(all_errors) < 1000:
                all_errors.extend(result.errors[:10])

            # [HIGH-1] build rejected-index set once — O(M) — instead of O(N×M)
            rejected_indices: set[int] = set()
            for err in result.errors:
                if not err.startswith("event "):
                    continue
                parts = err.split(" ")
                if len(parts) < 2:
                    continue
                try:
                    rejected_indices.add(int(parts[1].rstrip(":")))
                except ValueError:
                    pass

            normalized_topic = "events:normalized"
            for event_index, pb_event in enumerate(request.events):
                is_rejected = event_index in rejected_indices
                if is_rejected:
                    continue

                event = pb_to_event(pb_event, agent_id_override=cn)
                payload = event.model_dump_json().encode("utf-8")
                # pb_to_event already normalises the event — publish directly
                # to events:normalized so the storage writer can persist it
                # without a second normalisation pass.
                # [HIGH-2] publish safely regardless of calling context:
                # - from a running event loop (tests/async): use ensure_future
                # - from a sync gRPC thread with a known loop: run_coroutine_threadsafe
                # - fallback: asyncio.run (creates a temporary loop)
                coro = self._bus.publish(normalized_topic, payload)
                try:
                    running_loop = asyncio.get_running_loop()
                    asyncio.ensure_future(coro, loop=running_loop)
                except RuntimeError:
                    # No running loop — we are in a sync thread
                    loop = self._loop
                    if loop is not None and loop.is_running():
                        asyncio.run_coroutine_threadsafe(coro, loop)
                    else:
                        try:
                            asyncio.run(coro)
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

        # [HIGH-3] Use a stdlib queue.Queue to bridge the asyncio bus subscriber
        # (running on self._loop) to this synchronous gRPC generator thread.
        # Avoids creating a new event loop per iteration via asyncio.run().
        msg_queue: _queue.Queue[bytes | None] = _queue.Queue()

        async def _subscriber() -> None:
            try:
                sub = await self._bus.subscribe(topic)
                async for msg in sub:
                    msg_queue.put(msg)
                    if context.is_active() is False:
                        break
            except Exception as exc:  # noqa: BLE001
                _logger.error("policy_stream_error", error=str(exc))
            finally:
                msg_queue.put(None)  # sentinel — signals end of stream

        if self._loop is not None and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(_subscriber(), self._loop)
        else:
            _logger.error("policy_stream_no_loop", agent_id=cn)
            return

        if _pb2 is None:  # pragma: no cover
            return

        while context.is_active() is not False:
            try:
                raw = msg_queue.get(timeout=1.0)
            except _queue.Empty:
                continue
            if raw is None:
                break
            try:
                # [MEDIUM-5] pass config_json raw bytes — avoid double json round-trip
                data = json.loads(raw)
                config_raw: bytes = (
                    raw
                    if set(data.keys()) == {"config"}
                    else json.dumps(data.get("config", {})).encode("utf-8")
                )
                profile = _pb2.SurveillanceProfilePB(
                    name=data.get("name", ""),
                    description=data.get("description", ""),
                    version=data.get("version", 1),
                    config_json=config_raw,
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

        # [HIGH-3] Same queue bridge pattern as ReceivePolicy — no asyncio.run() per iteration.
        cmd_queue: _queue.Queue[bytes | None] = _queue.Queue()

        async def _subscriber() -> None:
            try:
                sub = await self._bus.subscribe(topic)
                async for msg in sub:
                    cmd_queue.put(msg)
                    if context.is_active() is False:
                        break
            except Exception as exc:  # noqa: BLE001
                _logger.error("commands_stream_error", error=str(exc))
            finally:
                cmd_queue.put(None)  # sentinel

        if self._loop is not None and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(_subscriber(), self._loop)
        else:
            _logger.error("commands_stream_no_loop", agent_id=cn)
            return

        if _pb2 is None:  # pragma: no cover
            return

        while context.is_active() is not False:
            try:
                raw = cmd_queue.get(timeout=1.0)
            except _queue.Empty:
                continue
            if raw is None:
                break
            try:
                # [MEDIUM-5] parse only once; pass payload_json bytes directly
                data = json.loads(raw)
                payload_raw: bytes = json.dumps(data.get("payload", {})).encode("utf-8")
                cmd = _pb2.AgentCommand(
                    command_type=data.get("command_type", ""),
                    payload_json=payload_raw,
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
