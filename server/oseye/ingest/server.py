"""gRPC server factory — creates and starts the async gRPC server with optional mTLS."""

from __future__ import annotations

import asyncio
import os
from concurrent import futures

import grpc
import grpc.aio

from oseye.bus.interface import EventBus
from oseye.config import Settings
from oseye.core.observability import get_logger
from oseye.ingest.grpc_service import AgentServiceServicer, register_servicer
from oseye.ingest.validator import BatchValidator

_logger = get_logger(__name__)


def _load_tls_credentials(settings: Settings) -> grpc.ServerCredentials | None:
    """Load mTLS credentials if cert files exist; return None for insecure mode."""
    cert_file = settings.tls_cert_file
    key_file = settings.tls_key_file
    ca_file = settings.tls_ca_cert_file

    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        _logger.warning(
            "grpc_tls_certs_missing",
            cert_file=cert_file,
            key_file=key_file,
            mode="insecure",
        )
        return None

    with open(cert_file, "rb") as fh:
        certificate_chain = fh.read()
    with open(key_file, "rb") as fh:
        private_key = fh.read()

    root_ca: bytes | None = None
    if os.path.exists(ca_file):
        with open(ca_file, "rb") as fh:
            root_ca = fh.read()

    return grpc.ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_ca,
        require_client_auth=root_ca is not None,
    )


async def create_grpc_server(settings: Settings, bus: EventBus) -> grpc.aio.Server:
    """Create a gRPC async server with mTLS if certificates are present.

    The server is created and bound but *not yet started* — call
    ``server.start()`` and ``server.wait_for_termination()`` in the
    application entry-point.

    Parameters
    ----------
    settings:
        OSEye Settings instance (reads grpc_port, tls_* paths, etc.).
    bus:
        The EventBus used by the AgentServiceServicer to publish events.
    """
    validator = BatchValidator()
    # SEC-002: pass the running event loop so IngestEvents / ReceivePolicy /
    # StreamCommands can bridge from gRPC's sync threads back to the async bus
    # via run_coroutine_threadsafe instead of the isolated asyncio.run() fallback.
    loop = asyncio.get_event_loop()
    servicer = AgentServiceServicer(bus=bus, validator=validator, loop=loop)

    server = grpc.aio.server(
        futures.ThreadPoolExecutor(max_workers=settings.grpc_max_workers),
    )

    register_servicer(servicer, server)

    credentials = _load_tls_credentials(settings)
    listen_addr = f"[::]:{settings.grpc_port}"

    if credentials is not None:
        server.add_secure_port(listen_addr, credentials)
        _logger.info("grpc_server_mtls", address=listen_addr)
    else:
        server.add_insecure_port(listen_addr)
        _logger.warning("grpc_server_insecure", address=listen_addr)

    return server
