"""gRPC AgentService servicer implementation."""

from __future__ import annotations

import asyncio
import json
import queue as _queue
import re
import threading
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
    from gen import event_pb2 as _pb2
    from gen import event_pb2_grpc as _pb2_grpc
except ImportError:
    try:
        from server.gen import event_pb2 as _pb2  # type: ignore[no-redef]
        from server.gen import event_pb2_grpc as _pb2_grpc  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover — only missing in isolated unit tests
        _pb2 = None  # type: ignore[assignment,unused-ignore]
        _pb2_grpc = None  # type: ignore[assignment,unused-ignore]

_logger = get_logger(__name__)


def _on_db_fut_error(f) -> None:  # noqa: ANN001
    if f.exception():
        _logger.error("agent_db_update_failed", error=str(f.exception()))


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


_CN_RE = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")


def _require_cn(
    context: grpc.ServicerContext,
    blocked_cns: set[str] | None = None,
    blocked_lock: threading.Lock | None = None,
) -> str | None:
    """Return the CN or abort the RPC with UNAUTHENTICATED / PERMISSION_DENIED.

    SEC-PREV-001: agent_id MUST come from the cert CN, never from the payload.
    PC-02: CN is validated against a strict pattern to prevent injection into
    Redis topic names (commands:{cn}).
    Revoked agents are rejected with PERMISSION_DENIED.
    """
    cn = _extract_cn_from_context(context)
    if cn is None:
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "mTLS client certificate CN required")
        return None
    if not _CN_RE.match(cn):
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid client certificate format")
        return None
    if blocked_cns is not None and blocked_lock is not None:
        with blocked_lock:
            if cn in blocked_cns:
                # PC-16: use a generic message to avoid leaking the CN in error responses
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "Agent certificate is revoked")
                return None
    return cn


class AgentServiceServicer:
    """gRPC servicer that receives event batches from agents.

    SEC-PREV-001: agent_id is always taken from the CN of the client certificate
    via ``_require_cn``, never from ``request.agent_id``.

    BUG-004: Ed25519 public-key verification is performed when the agent's key
    is registered in ``_agent_keys``.  When no key is registered for a CN, the
    verification step is skipped with a WARNING rather than silently passing.
    Keys can be pre-loaded via ``register_agent_key(cn, der_public_key_bytes)``.
    """

    def __init__(
        self,
        bus: EventBus,
        validator: BatchValidator,
        loop: asyncio.AbstractEventLoop | None = None,
        agent_keys: dict[str, bytes] | None = None,
        agent_repo: Any | None = None,
        *,
        require_agent_keys: bool = False,
        policy_engine: Any | None = None,
    ) -> None:
        self._bus = bus
        self._validator = validator
        self._loop = loop
        self._agent_repo = agent_repo
        self._require_agent_keys = require_agent_keys
        self._policy_engine = policy_engine
        # Registry of agent CN → DER-encoded Ed25519 public key bytes.
        # Populated via register_agent_key() or passed at construction time.
        # Protected by _agent_keys_lock for concurrent access from gRPC threads.
        self._agent_keys: dict[str, bytes] = dict(agent_keys) if agent_keys else {}
        self._agent_keys_lock = threading.Lock()

        # Set of revoked agent CNs. Checked in _require_cn before any RPC.
        # Persisted in DB; reloaded at startup via block_agent().
        self._blocked_cns: set[str] = set()
        self._blocked_lock = threading.Lock()

        # Set of CNs with an active IngestEvents stream (for backpressure).
        self._active_cns: set[str] = set()
        self._active_cns_lock = threading.Lock()

        # Latest collector health snapshot per agent CN.
        # Populated from synthetic "collector_health" events sent by agents every 30s.
        self._collector_healths: dict[str, list[dict[str, Any]]] = {}
        self._collector_healths_lock = threading.Lock()

        # Pending ping requests: command_id → asyncio.Event to signal on reply.
        self._pending_pings: dict[str, asyncio.Event] = {}
        self._pending_pings_lock = threading.Lock()

    @property
    def active_cns(self) -> frozenset[str]:
        """Snapshot of CNs with an active IngestEvents stream."""
        with self._active_cns_lock:
            return frozenset(self._active_cns)

    def register_agent_key(self, cn: str, der_public_key: bytes) -> None:
        """Register the DER-encoded Ed25519 public key for agent *cn*."""
        with self._agent_keys_lock:
            self._agent_keys[cn] = der_public_key

    def _get_agent_key(self, cn: str) -> bytes | None:
        with self._agent_keys_lock:
            return self._agent_keys.get(cn)

    def _publish_agent_disconnected(self, cn: str, reason: str) -> None:
        """Publish an agent:disconnected event on the bus (fire-and-forget)."""
        if self._loop is None or not self._loop.is_running():
            return
        payload = json.dumps({"agent_cn": cn, "reason": reason}).encode()
        asyncio.run_coroutine_threadsafe(
            self._bus.publish("agent:disconnected", payload),
            self._loop,
        ).add_done_callback(_on_db_fut_error)

    def register_ping(self, command_id: str, event: asyncio.Event) -> None:
        """Register a pending ping so ReportActions can signal it on reply."""
        with self._pending_pings_lock:
            self._pending_pings[command_id] = event

    def unregister_ping(self, command_id: str) -> None:
        """Remove a pending ping entry (called after timeout or reply)."""
        with self._pending_pings_lock:
            self._pending_pings.pop(command_id, None)

    async def startup(self) -> None:
        """Call once before the gRPC server starts accepting connections.

        Resets all agents to online=False so stale flags from a previous crash
        are cleared (AG-R-07).
        """
        if self._agent_repo is not None:
            await self._agent_repo.reset_all_offline()
            _logger.info("agents_reset_offline_on_startup")

    def block_agent(self, cn: str) -> None:
        """Add *cn* to the blocklist — takes effect immediately on the next RPC."""
        with self._blocked_lock:
            self._blocked_cns.add(cn)

    def unblock_agent(self, cn: str) -> None:
        """Remove *cn* from the blocklist."""
        with self._blocked_lock:
            self._blocked_cns.discard(cn)

    def get_collector_healths(self, cn: str) -> list[dict[str, Any]]:
        """Return the latest collector health snapshot for agent *cn*."""
        with self._collector_healths_lock:
            return list(self._collector_healths.get(cn, []))

    @property
    def policy_engine(self) -> Any | None:
        """Return the currently attached policy engine (may be None)."""
        return self._policy_engine

    @policy_engine.setter
    def policy_engine(self, engine: Any | None) -> None:
        """Attach or replace the policy engine at runtime."""
        self._policy_engine = engine

    # ------------------------------------------------------------------
    # IngestEvents — client-streaming RPC
    # ------------------------------------------------------------------

    def IngestEvents(  # noqa: N802
        self,
        request_iterator: Iterator[Any],
        context: grpc.ServicerContext,
    ) -> Any:
        """Receive a stream of IngestRequest batches from a single agent."""
        cn = _require_cn(context, self._blocked_cns, self._blocked_lock)
        if cn is None:
            return  # aborted above

        # Track agent connection — discard in finally to cover all exit paths
        # (normal end-of-stream, context.abort(), exception).
        with self._active_cns_lock:
            self._active_cns.add(cn)
        _disconnect_reason: str | None = None
        try:
            if self._agent_repo is not None and self._loop is not None:
                _peer = context.peer() or ""
                if _peer.startswith("ipv4:"):
                    _ip = _peer.split(":")[1]
                elif _peer.startswith("ipv6:["):
                    # Format: ipv6:[::1]:PORT — extract address between brackets.
                    _ip = _peer[6:_peer.rfind("]")]
                else:
                    _ip = None
                _fut = asyncio.run_coroutine_threadsafe(
                    self._agent_repo.upsert(cn=cn, online=True, ip_address=_ip),
                    self._loop,
                )
                _fut.add_done_callback(_on_db_fut_error)

            total_accepted = 0
            total_rejected = 0
            all_errors: list[str] = []

            # Resolve once per connection — cn is fixed for the stream lifetime.
            agent_public_key = self._get_agent_key(cn)
            if agent_public_key is None:
                _logger.warning("agent_key_not_registered", cn=cn)

            # Determine dispatch mode once — the calling context (sync gRPC
            # thread vs async event loop) does not change per request or event.
            try:
                _running_loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
                _use_task = True
            except RuntimeError:
                _running_loop = None
                _use_task = False

            normalized_topic = "events:normalized"

            def _on_task_error(t: asyncio.Task) -> None:  # noqa: ANN001
                if not t.cancelled() and t.exception() is not None:
                    _logger.error(
                        "bus_publish_failed",
                        topic=normalized_topic,
                        error=str(t.exception()),
                    )

            def _on_future_error(f: Any) -> None:
                if f.exception() is not None:
                    _logger.error(
                        "bus_publish_failed",
                        topic=normalized_topic,
                        error=str(f.exception()),
                    )

            for request in request_iterator:
                if agent_public_key is None and self._require_agent_keys:
                    context.abort(
                        grpc.StatusCode.UNAUTHENTICATED,
                        f"No Ed25519 public key registered for agent {cn!r}",
                    )
                    return
                result = self._validator.validate(request, agent_public_key=agent_public_key)
                total_accepted += result.accepted
                total_rejected += result.rejected
                # [AUDIT] cap accumulated errors to at most 1000 total
                all_errors.extend(result.errors[:max(0, 1000 - len(all_errors))])

                # [AUDIT] use rejected_indices from ValidationResult directly
                rejected_indices = result.rejected_indices

                # Collect valid payloads for this batch, then publish in one shot.
                batch_payloads: list[bytes] = []
                for event_index, pb_event in enumerate(request.events):
                    if event_index in rejected_indices:
                        continue
                    # Intercept collector health snapshots — store locally, skip bus publish.
                    if pb_event.category == "agent_health" and pb_event.extra_json:
                        try:
                            healths_raw = json.loads(pb_event.extra_json)
                            healths = [
                                {"name": k, **v} if isinstance(v, dict) else {"name": k}
                                for k, v in healths_raw.items()
                            ]
                            with self._collector_healths_lock:
                                self._collector_healths[cn] = healths
                        except Exception:  # noqa: BLE001
                            pass
                        continue
                    event = pb_to_event(pb_event, agent_id_override=cn)
                    batch_payloads.append(event.model_dump_json().encode("utf-8"))

                if batch_payloads:
                    coro = self._bus.publish_batch(normalized_topic, batch_payloads)
                    if _use_task and _running_loop is not None:
                        _running_loop.create_task(coro).add_done_callback(_on_task_error)
                    else:
                        loop = self._loop
                        if loop is not None and loop.is_running():
                            asyncio.run_coroutine_threadsafe(coro, loop).add_done_callback(
                                _on_future_error
                            )
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
                # AG-R-04: refresh last_seen on every successfully processed batch.
                if self._agent_repo is not None and self._loop is not None:
                    _fut = asyncio.run_coroutine_threadsafe(
                        self._agent_repo.update_last_seen(cn),
                        self._loop,
                    )
                    _fut.add_done_callback(_on_db_fut_error)

            if _pb2 is None:  # pragma: no cover
                return None

            # Mark agent offline when stream ends (clean EOF — no error reason)
            if self._agent_repo is not None and self._loop is not None:
                _fut = asyncio.run_coroutine_threadsafe(
                    self._agent_repo.set_offline(cn, reason="EOF"),
                    self._loop,
                )
                _fut.add_done_callback(_on_db_fut_error)
            _disconnect_reason = "EOF"
            self._publish_agent_disconnected(cn, "EOF")

            return _pb2.IngestResponse(
                accepted=total_accepted,
                rejected=total_rejected,
                errors=all_errors,
            )
        except grpc.RpcError as _grpc_exc:
            _code = _grpc_exc.code().name if hasattr(_grpc_exc, "code") else "UNKNOWN"
            _disconnect_reason = _code
            _logger.warning("agent_stream_error", cn=cn, grpc_code=_code)
            if self._agent_repo is not None and self._loop is not None:
                _fut = asyncio.run_coroutine_threadsafe(
                    self._agent_repo.set_offline(cn, reason=_code),
                    self._loop,
                )
                _fut.add_done_callback(_on_db_fut_error)
            self._publish_agent_disconnected(cn, _code)
            raise
        except Exception as _exc:
            _reason = type(_exc).__name__
            _disconnect_reason = _reason
            _logger.warning("agent_stream_exception", cn=cn, reason=_reason)
            if self._agent_repo is not None and self._loop is not None:
                _fut = asyncio.run_coroutine_threadsafe(
                    self._agent_repo.set_offline(cn, reason=_reason),
                    self._loop,
                )
                _fut.add_done_callback(_on_db_fut_error)
            self._publish_agent_disconnected(cn, _reason)
            raise
        finally:
            with self._active_cns_lock:
                self._active_cns.discard(cn)
            _ = _disconnect_reason  # consumed above

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
        cn = _require_cn(context, self._blocked_cns, self._blocked_lock)
        if cn is None:
            return  # aborted above

        topic = f"policy:push:{cn}"
        _logger.info("policy_stream_opened", agent_id=cn, topic=topic)

        # _SyncServicerContext has no is_active()/cancelled() — use add_callback + Event.
        _cancelled = threading.Event()
        context.add_callback(_cancelled.set)

        # [HIGH-3] Use a stdlib queue.Queue to bridge the asyncio bus subscriber
        # (running on self._loop) to this synchronous gRPC generator thread.
        # Avoids creating a new event loop per iteration via asyncio.run().
        msg_queue: _queue.Queue[bytes | None] = _queue.Queue()

        async def _subscriber() -> None:
            try:
                sub = await self._bus.subscribe(topic)
                async for msg in sub:
                    msg_queue.put(msg)
                    if _cancelled.is_set():
                        break
            except Exception as exc:  # noqa: BLE001
                _logger.error("policy_stream_error", error=str(exc))
            finally:
                msg_queue.put(None)  # sentinel — signals end of stream

        if self._loop is not None and self._loop.is_running():
            _policy_fut = asyncio.run_coroutine_threadsafe(_subscriber(), self._loop)
        else:
            _logger.error("policy_stream_no_loop", agent_id=cn)
            return

        # Re-sync: push the current profile immediately on (re)connection so
        # a newly-joined server (LB failover) does not leave the agent on a
        # stale profile.
        if self._policy_engine is not None:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._policy_engine.push_default_to_agent(cn),
                    self._loop,
                ).add_done_callback(
                    lambda f: _logger.warning(
                        "profile_resync_failed", cn=cn, error=str(f.exception())
                    )
                    if f.exception()
                    else None
                )
                _logger.info("profile_resync_triggered", cn=cn)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("profile_resync_error", cn=cn, error=str(exc))

        if _pb2 is None:  # pragma: no cover
            return

        try:
            while not _cancelled.is_set():
                try:
                    raw = msg_queue.get(timeout=1.0)
                except _queue.Empty:
                    continue
                if raw is None:
                    break
                try:
                    data = json.loads(raw)
                    config_raw: bytes = json.dumps(data).encode("utf-8")
                    profile = _pb2.SurveillanceProfilePB(
                        name=data.get("name", ""),
                        description=data.get("description", ""),
                        version=data.get("version", 1),
                        config_json=config_raw,
                    )
                    yield profile
                except Exception as exc:  # noqa: BLE001
                    _logger.error("policy_deserialize_error", error=str(exc))
        finally:
            _policy_fut.cancel()

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
        cn = _require_cn(context, self._blocked_cns, self._blocked_lock)
        if cn is None:
            return  # aborted above

        topic = f"commands:{cn}"
        _logger.info("commands_stream_opened", agent_id=cn, topic=topic)

        # _SyncServicerContext has no is_active()/cancelled() — use add_callback + Event.
        _cancelled = threading.Event()
        context.add_callback(_cancelled.set)

        # [HIGH-3] Same queue bridge pattern as ReceivePolicy — no asyncio.run() per iteration.
        cmd_queue: _queue.Queue[bytes | None] = _queue.Queue()

        async def _subscriber() -> None:
            try:
                sub = await self._bus.subscribe(topic)
                async for msg in sub:
                    cmd_queue.put(msg)
                    if _cancelled.is_set():
                        break
            except Exception as exc:  # noqa: BLE001
                _logger.error("commands_stream_error", error=str(exc))
            finally:
                cmd_queue.put(None)  # sentinel

        if self._loop is not None and self._loop.is_running():
            _cmd_fut = asyncio.run_coroutine_threadsafe(_subscriber(), self._loop)
        else:
            _logger.error("commands_stream_no_loop", agent_id=cn)
            return

        if _pb2 is None:  # pragma: no cover
            return

        try:
            while not _cancelled.is_set():
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
                        command_id=data.get("command_id", ""),
                        command_type=data.get("command_type", ""),
                        payload_json=payload_raw,
                    )
                    yield cmd
                except Exception as exc:  # noqa: BLE001
                    _logger.error("command_deserialize_error", error=str(exc))
        finally:
            _cmd_fut.cancel()

    # ------------------------------------------------------------------
    # ReportActions — client-streaming RPC
    # ------------------------------------------------------------------

    def ReportActions(  # noqa: N802
        self,
        request_iterator: Iterator[Any],
        context: grpc.ServicerContext,
    ) -> Any:
        """Receive action execution reports from the agent.

        CIA — Disponibilité : reports are stored in response_actions so the
        admin can see the status of every action even if they were offline.
        CIA — Intégrité    : CN from the mTLS cert is verified; an agent can
        only report on commands that were issued to it.
        """
        cn = _require_cn(context, self._blocked_cns, self._blocked_lock)
        if cn is None:
            return  # aborted above

        accepted = 0
        repo = getattr(self, "_response_actions_repo", None)

        for report in request_iterator:
            command_id = report.command_id
            status     = report.status
            error      = report.error

            _logger.info(
                "action_report_received",
                cn=cn,
                command_id=command_id,
                status=status,
            )

            # Signal any waiting ping request for this command_id.
            with self._pending_pings_lock:
                ping_event = self._pending_pings.get(command_id)
            if ping_event is not None and self._loop is not None:
                self._loop.call_soon_threadsafe(ping_event.set)

            if repo is not None and self._loop is not None:
                # AG-R-01: IDOR guard — verify the command was issued to this agent.
                try:
                    command = asyncio.run_coroutine_threadsafe(
                        repo.get(command_id), self._loop
                    ).result(timeout=2.0)
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "action_report_fetch_error",
                        command_id=command_id,
                        error=str(exc),
                    )
                    continue

                if command is None:
                    _logger.warning(
                        "action_report_unknown_command",
                        command_id=command_id,
                        cn=cn,
                    )
                    continue

                if command.agent_cn != cn:
                    _logger.warning(
                        "grpc_report_actions_idor_attempt",
                        command_id=command_id,
                        claimed_cn=cn,
                        actual_cn=command.agent_cn,
                    )
                    continue  # ignorer silencieusement

                if status == "executed":
                    fut = asyncio.run_coroutine_threadsafe(
                        repo.mark_executed(command_id), self._loop
                    )
                elif status == "failed":
                    fut = asyncio.run_coroutine_threadsafe(
                        repo.mark_failed(command_id, error), self._loop
                    )
                elif status == "rolled_back":
                    fut = asyncio.run_coroutine_threadsafe(
                        repo.atomic_mark_rolled_back(command_id), self._loop
                    )
                else:
                    fut = None
                if fut is not None:
                    try:
                        fut.result(timeout=2.0)
                    except Exception as exc:  # noqa: BLE001
                        _logger.warning(
                            "action_report_db_error",
                            command_id=command_id,
                            error=str(exc),
                        )
            accepted += 1

        if _pb2 is None:  # pragma: no cover
            return None
        return _pb2.ActionReportResponse(accepted=accepted)


def register_servicer(servicer: AgentServiceServicer, server: Any) -> None:
    """Register the servicer with a gRPC server instance."""
    if _pb2_grpc is None:  # pragma: no cover
        raise RuntimeError("server.gen not available — run scripts/generate_proto.sh")
    _pb2_grpc.add_AgentServiceServicer_to_server(
        servicer, server
    )
