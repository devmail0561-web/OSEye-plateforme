"""OSEye server entrypoint.

Starts the FastAPI application with uvicorn and launches background workers
(storage writer, normalizer, rule engine, threat intel, correlation) via the
lifespan context manager.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path

import httpx
import redis.asyncio as aioredis
import uvicorn

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
from oseye.ingest.server import create_grpc_server
from oseye.normalizer.engine import NormalizerEngine
from oseye.rule_engine import RuleEngine
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.api_keys import SQLApiKeyRepository
from oseye.storage.repositories.decisions import SQLDecisionRepository
from oseye.storage.repositories.events import SQLEventRepository
from oseye.storage.repositories.incidents import SQLIncidentRepository
from oseye.storage.repositories.rule_versions import SQLRuleVersionRepository
from oseye.threat_intel.cache import MemoryTICache, RedisTICache
from oseye.threat_intel.client import ThreatIntelClient
from oseye.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from oseye.threat_intel.providers.misp import MISPProvider
from oseye.threat_intel.providers.virustotal import VirusTotalProvider
from oseye.workers.correlation_worker import CorrelationWorker
from oseye.workers.decision_worker import DecisionWorker
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
        bus = create_bus(settings)
        backend = SQLiteBackend(settings.db_url)
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
        rule_worker = RuleWorker(
            bus=bus,
            alert_repo=alert_repo,
            rules_root=_RULES_ROOT,
            hot_reload=False,  # engine already hot-reloads
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
        # Phase 5 — Decision Engine
        # ------------------------------------------------------------------

        decision_repo = SQLDecisionRepository(backend.session_factory)
        # F-02: restore last journal hash from DB so the chain survives restarts.
        _last_hash = await decision_repo.get_last_journal_hash()
        journal = DecisionJournal(last_hash=_last_hash) if _last_hash else DecisionJournal()
        decision_engine = DecisionEngine(
            journal=journal,
            policy_overrides=PolicyOverrides(),
            human_timeout_secs=settings.decision_human_timeout_secs,
            policy_version=settings.decision_policy_version,
        )
        action_executor = ActionExecutor(bus=bus)
        human_queue = HumanApprovalQueue(
            decision_repo=decision_repo,
            poll_interval=settings.decision_human_poll_interval,
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
            stop_event=stop,
        )

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

        # gRPC server (mTLS if certs present, insecure otherwise)
        grpc_server = await create_grpc_server(settings, bus)
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
        ]
        _logger.info("workers_started", count=len(tasks))

        # Expose shared state to API routers
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

        yield  # server runs here

        stop.set()
        await grpc_server.stop(grace=5)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await ti_client.close()
        await http_client.aclose()
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
app = create_app(get_settings(), lifespan=_build_lifespan(get_settings()))


if __name__ == "__main__":
    main()
