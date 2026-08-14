"""OSEye server entrypoint.

Starts the FastAPI application with uvicorn and launches background workers
(storage writer, normalizer, rule engine, threat intel, correlation) via the
lifespan context manager.
"""

from __future__ import annotations

import asyncio
import os
import socket
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path

import httpx
import redis.asyncio as aioredis
import uvicorn
from oseye_sdk.ipc import IPCServer

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.bus.factory import create_bus
from oseye.config import Settings
from oseye.core.observability import get_logger
from oseye.correlation.engine import CorrelationEngine
from oseye.correlation.linkers.same_host import SameHostLinker
from oseye.decision.action_executor import ActionExecutor
from oseye.decision.engine import DecisionEngine, PolicyOverrides
from oseye.decision.human_queue import HumanApprovalQueue
from oseye.decision.journal import DecisionJournal
from oseye.forensic.case_manager import CaseManager
from oseye.ingest.server import create_grpc_server
from oseye.ml_engine.engine import MLEngine
from oseye.normalizer.engine import NormalizerEngine
from oseye.plugin.manager import PluginManager
from oseye.plugin.verifier import PluginVerifier
from oseye.policy.engine import PolicyEngine
from oseye.policy.rule_signer import RuleSigner
from oseye.rule_engine import RuleEngine
from oseye.storage.backends.factory import create_backend
from oseye.storage.repositories.agents import SQLAgentRepository
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.api_keys import SQLApiKeyRepository
from oseye.storage.repositories.blocked_agents import SQLBlockedAgentsRepository
from oseye.storage.repositories.cases import SQLCaseRepository
from oseye.storage.repositories.decisions import SQLDecisionRepository
from oseye.storage.repositories.events import SQLEventRepository
from oseye.storage.repositories.incidents import SQLIncidentRepository
from oseye.storage.repositories.response_actions import SQLResponseActionsRepository
from oseye.storage.repositories.rule_versions import SQLRuleVersionRepository
from oseye.threat_intel.cache import MemoryTICache, RedisTICache
from oseye.threat_intel.client import ThreatIntelClient
from oseye.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from oseye.threat_intel.providers.misp import MISPProvider
from oseye.threat_intel.providers.virustotal import VirusTotalProvider
from oseye.workers.correlation_worker import CorrelationWorker
from oseye.workers.decision_worker import DecisionWorker
from oseye.workers.ml_worker import MLWorker
from oseye.workers.notify_worker import NotificationWorker
from oseye.workers.rule_worker import RuleWorker
from oseye.workers.storage_writer import StorageWriter
from oseye.workers.ti_worker import TIWorker

_RULES_ROOT = Path(__file__).parent.parent.parent / "rules"

_logger = get_logger(__name__)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def _build_lifespan(settings: Settings):  # type: ignore[no-untyped-def]
    """Return a lifespan context manager that boots workers on startup."""

    @asynccontextmanager
    async def lifespan(app: object) -> AsyncGenerator[None, None]:  # noqa: ARG001
        # ML-R-03: Guard HMAC key at startup — warn when missing or insecure default.
        hmac_key_env = os.environ.get("OSEYE_CHECKPOINT_HMAC_KEY", "")
        if not hmac_key_env or hmac_key_env == "dev-insecure-key":
            if os.environ.get("OSEYE_INSECURE", "").lower() != "true":
                _logger.warning(
                    "OSEYE_CHECKPOINT_HMAC_KEY not set or uses insecure default — "
                    "set OSEYE_INSECURE=true to allow in dev"
                )

        bus = create_bus(settings)
        backend = create_backend(settings)
        await backend.init()
        repo = SQLEventRepository(backend.session_factory)
        alert_repo = SQLAlertRepository(backend.session_factory)

        normalizer = NormalizerEngine(bus=bus, hostname=socket.gethostname())
        writer = StorageWriter(
            bus=bus,
            repo=repo,
            flush_interval_ms=settings.batch_flush_interval_ms,
            batch_max_size=settings.batch_max_size,
        )
        rule_engine = RuleEngine(rules_root=_RULES_ROOT, hot_reload=True)

        # ML Engine must be instantiated before RuleWorker (it is injected there
        # and also into DecisionEngine further below).
        ml_engine = MLEngine()

        rule_worker = RuleWorker(
            bus=bus,
            alert_repo=alert_repo,
            rules_root=_RULES_ROOT,
            hot_reload=False,  # engine already hot-reloads
            ml_engine=ml_engine,
        )

        stop = asyncio.Event()

        # ------------------------------------------------------------------
        # Phase 4 — Threat Intelligence
        # ------------------------------------------------------------------

        # Shared HTTP client for all TI providers (single connection pool)
        http_client = httpx.AsyncClient(timeout=settings.ti_lookup_timeout_seconds)

        from oseye.threat_intel.cache import TICache
        from oseye.threat_intel.providers.base import ThreatIntelProvider

        ti_providers: list[ThreatIntelProvider] = []
        if settings.abuseipdb_api_key:
            ti_providers.append(
                AbuseIPDBProvider(
                    api_key=settings.abuseipdb_api_key,
                    http_client=http_client,
                    fail_max=settings.ti_breaker_fail_max,
                    reset_timeout=settings.ti_breaker_reset_timeout,
                )
            )
        if settings.virustotal_api_key:
            ti_providers.append(
                VirusTotalProvider(
                    api_key=settings.virustotal_api_key,
                    http_client=http_client,
                    fail_max=settings.ti_breaker_fail_max,
                    reset_timeout=settings.ti_breaker_reset_timeout,
                )
            )
        if settings.misp_url:
            ti_providers.append(
                MISPProvider(misp_url=settings.misp_url, api_key=settings.misp_api_key)
            )

        ti_cache: TICache
        if settings.redis_url:
            _redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)
            ti_cache = RedisTICache(
                redis_client=_redis_client,
                default_ttl=settings.ti_cache_ttl_seconds,
            )
        else:
            ti_cache = MemoryTICache(default_ttl=settings.ti_cache_ttl_seconds)

        ti_client = ThreatIntelClient(
            providers=ti_providers,
            cache=ti_cache,
            cache_ttl=settings.ti_cache_ttl_seconds,
            timeout=settings.ti_lookup_timeout_seconds,
        )

        # ------------------------------------------------------------------
        # Phase 4 — Correlation Engine
        # ------------------------------------------------------------------

        incident_repo = SQLIncidentRepository(backend.session_factory)
        linker = SameHostLinker(timeframe_seconds=settings.correlation_window_seconds)
        correlation_engine = CorrelationEngine(
            linkers=[linker],
            incident_repo=incident_repo,
            min_severity=settings.correlation_min_severity,
        )

        # ------------------------------------------------------------------
        # ML Worker — ml_engine is already initialised above
        # ------------------------------------------------------------------

        ml_worker = MLWorker(
            bus=bus,
            engine=ml_engine,
            checkpoint_path=Path(settings.ml_checkpoint_path),
            checkpoint_interval_s=settings.ml_checkpoint_interval_s,
            event_repo=repo,
        )

        # ------------------------------------------------------------------
        # Phase 5 — Decision Engine
        # ------------------------------------------------------------------

        decision_repo = SQLDecisionRepository(backend.session_factory)
        case_repo = SQLCaseRepository(backend.session_factory)
        case_manager = CaseManager(case_repo=case_repo)
        # F-02: restore last journal hash from DB so the chain survives restarts.
        _last_hash = await decision_repo.get_last_journal_hash()
        journal = DecisionJournal(last_hash=_last_hash) if _last_hash else DecisionJournal()
        decision_engine = DecisionEngine(
            journal=journal,
            policy_overrides=PolicyOverrides(),
            human_timeout_secs=settings.decision_human_timeout_secs,
            policy_version=settings.decision_policy_version,
            ml_engine=ml_engine,
            weight_rule=settings.decision_weight_rule,
            weight_ml=settings.decision_weight_ml,
            weight_ti=settings.decision_weight_ti,
            weight_depth=settings.decision_weight_depth,
        )
        action_executor = ActionExecutor(bus=bus)
        human_queue = HumanApprovalQueue(
            decision_repo=decision_repo,
            poll_interval=settings.decision_human_poll_interval,
            action_executor=action_executor,
            alert_repo=alert_repo,
        )

        # ------------------------------------------------------------------
        # Policy Engine — charge les profils YAML et les pousse aux agents
        # ------------------------------------------------------------------

        rule_signer = RuleSigner(private_key_path=settings.rule_signing_key_path)
        policy_engine = PolicyEngine(
            bus=bus,
            default_profile=settings.default_surveillance_profile,
            rule_signer=rule_signer,
        )
        await policy_engine.load_profiles()
        _agent_ids_for_policy = await repo.get_distinct_agent_ids()
        policy_engine.seed_known_agents(_agent_ids_for_policy)
        _logger.info(
            "policy_engine_ready",
            profiles=len(policy_engine.list_profiles()),
            known_agents=len(_agent_ids_for_policy),
        )

        # ------------------------------------------------------------------
        # Plugin system — IPC socket + PluginManager
        # ------------------------------------------------------------------

        ipc_server = IPCServer(socket_path=settings.plugin_ipc_socket)
        await ipc_server.start()
        _logger.info("plugin_ipc_server_started", socket=settings.plugin_ipc_socket)

        _plugin_verifier: PluginVerifier | None = None
        _plugin_keys_dir = Path(settings.plugin_keys_dir)
        if _plugin_keys_dir.is_dir():
            _plugin_verifier = PluginVerifier(keys_dir=_plugin_keys_dir)
            _logger.info("plugin_verifier_ready", keys_dir=str(_plugin_keys_dir))
        else:
            _logger.warning(
                "plugin_keys_dir_missing",
                path=str(_plugin_keys_dir),
                note="plugin signature verification disabled",
            )

        plugin_manager = PluginManager(
            plugins_dir=Path(settings.plugins_dir),
            ipc_socket=settings.plugin_ipc_socket,
            verifier=_plugin_verifier,
            require_signature=settings.plugin_require_signature,
        )
        if settings.plugin_require_signature:
            _logger.info("plugin_signature_required", keys_dir=settings.plugin_keys_dir)
        else:
            _logger.warning(
                "plugin_signature_not_required",
                note="Set OSEYE_PLUGIN_REQUIRE_SIGNATURE=true in production",
            )
        _logger.info(
            "plugin_manager_ready",
            plugins_dir=settings.plugins_dir,
            discovered=len(plugin_manager.list()),
        )

        # ------------------------------------------------------------------
        # Workers
        # ------------------------------------------------------------------

        ti_worker = TIWorker(
            bus=bus,
            ti_client=ti_client,
            alert_repo=alert_repo,
            stop_event=stop,
        )
        correlation_worker = CorrelationWorker(
            bus=bus,
            engine=correlation_engine,
            alert_repo=alert_repo,
            stop_event=stop,
        )
        decision_worker = DecisionWorker(
            bus=bus,
            engine=decision_engine,
            decision_repo=decision_repo,
            incident_repo=incident_repo,
            alert_repo=alert_repo,
            action_executor=action_executor,
            event_repo=repo,
            stop_event=stop,
        )

        # NE-R-01: NotificationWorker consumes notifications:pending so that
        # messages published by ActionExecutor._emit_notification are not dropped.
        notify_worker = NotificationWorker(bus=bus, stop_event=stop)

        async def _normalizer_loop() -> None:
            async for topic, message in await bus.subscribe_pattern("events:raw:*"):
                parts = topic.split(":")
                agent_id = parts[2] if len(parts) >= 3 else "unknown"
                await normalizer.process(
                    raw_payload=message,
                    source="procfs",
                    os_name="linux",
                    agent_id=agent_id,
                )
                if stop.is_set():
                    break

        # gRPC server — mTLS enforced (raises if certs missing and not dev mode)
        grpc_server, grpc_servicer = await create_grpc_server(settings, bus)

        # Load Ed25519 public keys for agent batch-signature verification
        _keys_dir = Path(settings.agent_keys_dir)
        if _keys_dir.is_dir():
            for pub_file in sorted(_keys_dir.glob("*.pub")):
                cn = pub_file.stem
                grpc_servicer.register_agent_key(cn, pub_file.read_bytes())
                _logger.info("agent_key_loaded", cn=cn)
        else:
            _logger.warning("agent_keys_dir_missing", path=str(_keys_dir))

        # Agent tracking repository
        agent_repo = SQLAgentRepository(backend.session_factory)
        grpc_servicer._agent_repo = agent_repo  # noqa: SLF001

        # Load persisted agent blocklist so revocations survive restarts
        blocked_agents_repo = SQLBlockedAgentsRepository(backend.session_factory)
        _blocked_cns = await blocked_agents_repo.list_blocked()
        for _cn in _blocked_cns:
            grpc_servicer.block_agent(_cn)
        if _blocked_cns:
            _logger.info("blocked_agents_loaded", count=len(_blocked_cns))

        await grpc_server.start()
        _logger.info("grpc_server_started", port=settings.grpc_port)

        tasks = [
            asyncio.create_task(_normalizer_loop(), name="normalizer"),
            asyncio.create_task(writer.run(stop_event=stop), name="storage_writer"),
            asyncio.create_task(rule_worker.run(stop_event=stop), name="rule_worker"),
            asyncio.create_task(ti_worker.run(), name="ti_worker"),
            asyncio.create_task(correlation_worker.run(), name="correlation_worker"),
            asyncio.create_task(decision_worker.run(), name="decision_worker"),
            asyncio.create_task(human_queue.run(), name="human_queue"),
            asyncio.create_task(ml_worker.run(), name="ml_worker"),
            asyncio.create_task(notify_worker.run(), name="notify_worker"),
        ]
        _logger.info("workers_started", count=len(tasks))

        # Expose shared state to API routers
        from oseye.enrollment_store import EnrollmentStore
        app.state.enrollment_store = EnrollmentStore(settings)  # type: ignore[attr-defined]

        app.state.jwt_handler = JWTHandler(  # type: ignore[attr-defined]
            private_key_path=settings.jwt_private_key_path,
            public_key_path=settings.jwt_public_key_path,
            expire_minutes=settings.jwt_access_token_expire_minutes,
        )
        app.state.event_repo = repo  # type: ignore[attr-defined]
        app.state.alert_repo = alert_repo  # type: ignore[attr-defined]
        app.state.rule_engine = rule_engine  # type: ignore[attr-defined]
        app.state.api_key_repo = SQLApiKeyRepository(backend.session_factory)  # type: ignore[attr-defined]
        app.state.rule_version_repo = SQLRuleVersionRepository(backend.session_factory)  # type: ignore[attr-defined]
        app.state.ti_client = ti_client  # type: ignore[attr-defined]
        app.state.incident_repo = incident_repo  # type: ignore[attr-defined]
        app.state.decision_repo = decision_repo  # type: ignore[attr-defined]
        app.state.human_queue = human_queue  # type: ignore[attr-defined]
        app.state.case_manager = case_manager  # type: ignore[attr-defined]
        app.state.grpc_servicer = grpc_servicer  # type: ignore[attr-defined]
        app.state.agent_repo = agent_repo  # type: ignore[attr-defined]
        app.state.action_executor = action_executor  # type: ignore[attr-defined]
        app.state.plugin_manager = plugin_manager  # type: ignore[attr-defined]
        app.state.ml_engine = ml_engine  # type: ignore[attr-defined]
        app.state.policy_engine = policy_engine  # type: ignore[attr-defined]
        app.state.blocked_agents_repo = blocked_agents_repo  # type: ignore[attr-defined]
        response_actions_repo = SQLResponseActionsRepository(backend.session_factory)
        app.state.response_actions_repo = response_actions_repo  # type: ignore[attr-defined]
        # Wire repo into the servicer so ReportActions RPC can persist reports
        grpc_servicer._response_actions_repo = response_actions_repo  # noqa: SLF001

        yield  # server runs here

        stop.set()
        await grpc_server.stop(grace=5)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await ti_client.close()
        await http_client.aclose()
        await ipc_server.stop()
        _logger.info("grpc_server_stopped")
        _logger.info("workers_stopped")

    return lifespan


def main() -> None:
    settings = get_settings()
    lifespan = _build_lifespan(settings)
    app = create_app(settings, lifespan=lifespan)

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
    )


# Expose `app` for `uvicorn oseye.main:app` invocation (Docker CMD).
# Guard prevents double lifespan construction when main() is also called.
if __name__ != "__main__":
    app = create_app(get_settings(), lifespan=_build_lifespan(get_settings()))


if __name__ == "__main__":
    main()
