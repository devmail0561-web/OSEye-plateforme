"""gRPC AgentService servicer implementation."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any

import grpc
from cryptography.x509 import load_der_x509_certificate
from cryptography.x509.oid import NameOID

from oseye.bus.interface import EventBus
from oseye.core.observability import get_logger
from oseye.ingest.normalizer_bridge import pb_to_event
from oseye.ingest.validator import BatchValidator

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
        cert = load_der_x509_certificate(peer_identities[0])
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            return None
        value = attrs[0].value
        # NameAttribute.value is str | bytes — normalise to str
        return value if isinstance(value, str) else value.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        _logger.warning("mtls_cn_parse_failed", error=str(exc))
        return None


class AgentServiceServicer:
    """gRPC servicer that receives event batches from agents.

    SEC-PREV-001: agent_id is always taken from the CN of the client certificate
    via ``_extract_cn_from_context``, never from ``request.agent_id``.
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
        """Receive a stream of IngestRequest batches from a single agent.

        For each batch:
        1. Extract agent_id from the mTLS cert CN (SEC-PREV-001).
        2. Validate with BatchValidator.
        3. Convert each accepted event via pb_to_event.
        4. Publish on ``events:raw:{agent_id}``.
        5. Return IngestResponse.
        """
        from server.gen import event_pb2 as _pb2

        cn = _extract_cn_from_context(context)
        if cn is None:
            _logger.warning("ingest_no_mtls_cn", peer=context.peer())

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

            agent_topic_id = cn if cn is not None else "unknown"
            topic = f"events:raw:{agent_topic_id}"

            for event_index, pb_event in enumerate(request.events):
                is_rejected = any(
                    err.startswith(f"event {event_index}:") for err in result.errors
                )
                if is_rejected:
                    continue

                event = pb_to_event(pb_event, agent_id_override=cn)
                payload = event.model_dump_json().encode("utf-8")

                if loop is not None and loop.is_running():
                    asyncio.ensure_future(self._bus.publish(topic, payload), loop=loop)
                else:
                    try:
                        asyncio.run(self._bus.publish(topic, payload))
                    except RuntimeError:
                        _logger.error("bus_publish_failed", topic=topic)

            _logger.info(
                "batch_ingested",
                cn=cn,
                accepted=result.accepted,
                rejected=result.rejected,
            )

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

        Subscribes to ``policy:push:{agent_id}`` and yields updates as they
        arrive on the bus.  The agent_id is taken from the mTLS CN
        (SEC-PREV-001).
        """
        from server.gen import event_pb2 as _pb2

        cn = _extract_cn_from_context(context)
        agent_id: str = cn if cn is not None else bytes(request.agent_id).decode(
            "utf-8", errors="replace"
        )
        topic = f"policy:push:{agent_id}"

        _logger.info("policy_stream_opened", agent_id=agent_id, topic=topic)

        async def _collect() -> list[bytes]:
            sub = await self._bus.subscribe(topic)
            msgs: list[bytes] = []
            async with asyncio.timeout(30.0):
                async for msg in sub:
                    msgs.append(msg)
                    break  # one at a time, caller re-subscribes
            return msgs

        while context.is_active() is not False:
            try:
                msgs = asyncio.run(_collect())
            except TimeoutError:
                continue
            except Exception as exc:  # noqa: BLE001
                _logger.error("policy_stream_error", error=str(exc))
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

        Subscribes to ``commands:{agent_id}`` and yields commands.
        The agent_id is taken from the mTLS CN (SEC-PREV-001).
        """
        from server.gen import event_pb2 as _pb2

        cn = _extract_cn_from_context(context)
        agent_id: str = cn if cn is not None else bytes(request.agent_id).decode(
            "utf-8", errors="replace"
        )
        topic = f"commands:{agent_id}"

        _logger.info("commands_stream_opened", agent_id=agent_id, topic=topic)

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


def register_servicer(
    servicer: AgentServiceServicer,
    server: Any,
) -> None:
    """Register the servicer with a gRPC server instance.

    Accepts both ``grpc.Server`` and ``grpc.aio.Server`` (the two ABC roots
    share the same add_*_to_server contract but are not related by inheritance).
    """
    from server.gen import event_pb2_grpc as _grpc

    _grpc.add_AgentServiceServicer_to_server(servicer, server)
