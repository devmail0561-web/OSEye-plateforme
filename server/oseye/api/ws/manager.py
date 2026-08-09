"""WebSocket connection manager — broadcasts normalised events to connected clients."""

from __future__ import annotations

import asyncio
import logging

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections and broadcasts binary messages."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock: asyncio.Lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        """Register an already-accepted WebSocket connection.

        The caller (ws_alerts) is responsible for calling ws.accept() before
        this method — accepting here a second time would raise RuntimeError.
        """
        async with self._lock:
            self._connections.add(ws)
        logger.debug("WebSocket connected — total=%d", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        """Remove a WebSocket from the registry (best-effort close)."""
        async with self._lock:
            self._connections.discard(ws)
        logger.debug("WebSocket disconnected — total=%d", len(self._connections))

    async def broadcast(self, message: bytes) -> None:
        """Send *message* to all connected clients; remove dead connections."""
        dead: list[WebSocket] = []
        async with self._lock:
            clients = list(self._connections)

        for ws in clients:
            try:
                await ws.send_bytes(message)
            except Exception:  # noqa: BLE001
                logger.debug("WebSocket send failed — removing client")
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)
