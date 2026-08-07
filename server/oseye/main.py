"""OSEye server entrypoint.

Starts the FastAPI application with uvicorn and launches background workers
(storage writer, normalizer) via the lifespan context manager.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path

import uvicorn

from oseye.api.app import create_app
from oseye.api.auth.jwt import JWTHandler
from oseye.bus.factory import create_bus
from oseye.config import Settings
from oseye.core.observability import get_logger
from oseye.ingest.server import create_grpc_server
from oseye.normalizer.engine import NormalizerEngine
from oseye.rule_engine import RuleEngine
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.api_keys import SQLApiKeyRepository
from oseye.storage.repositories.events import SQLEventRepository
from oseye.storage.repositories.rule_versions import SQLRuleVersionRepository
from oseye.workers.rule_worker import RuleWorker
from oseye.workers.storage_writer import StorageWriter

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

        yield  # server runs here

        stop.set()
        await grpc_server.stop(grace=5)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
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
