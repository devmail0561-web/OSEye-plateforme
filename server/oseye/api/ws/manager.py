"""WebSocket connection manager — broadcasts normalised events to connected clients."""

from __future__ import annotations

import asyncio
import logging

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# SEC-WS-001: connection caps to prevent DoS from authenticated users
_MAX_GLOBAL_CONNECTIONS = 500
_MAX_PER_USER_CONNECTIONS = 5


class WebSocketManager:
    """Manages WebSocket connections and broadcasts binary messages."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        # Maps user_sub → set of WebSocket connections for that user
        self._per_user: dict[str, set[WebSocket]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, user_sub: str | None = None) -> None:
        """Register an already-accepted WebSocket connection.

        The caller (ws_alerts) is responsible for calling ws.accept() before
        this method — accepting here a second time would raise RuntimeError.

        SEC-WS-001: rejects with code 4008 if the global cap or per-user cap is exceeded.
        """
        async with self._lock:
            # Global cap check
            if len(self._connections) >= _MAX_GLOBAL_CONNECTIONS:
                logger.warning(
                    "WebSocket global cap reached (%d) — rejecting connection",
                    _MAX_GLOBAL_CONNECTIONS,
                )
                await ws.close(code=4008)
                return

            # Per-user cap check
            if user_sub is not None:
                user_conns = self._per_user.get(user_sub, set())
                if len(user_conns) >= _MAX_PER_USER_CONNECTIONS:
                    logger.warning(
                        "WebSocket per-user cap reached for sub=%s (%d) — rejecting connection",
                        user_sub,
                        _MAX_PER_USER_CONNECTIONS,
                    )
                    await ws.close(code=4008)
                    return
                user_conns.add(ws)
                self._per_user[user_sub] = user_conns

            self._connections.add(ws)
            # Store sub on the websocket state so disconnect() can look it up
            ws.state.user_sub = user_sub

        logger.debug("WebSocket connected — total=%d", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        """Remove a WebSocket from the registry (best-effort close)."""
        async with self._lock:
            self._connections.discard(ws)
            user_sub: str | None = getattr(getattr(ws, "state", None), "user_sub", None)
            if user_sub is not None and user_sub in self._per_user:
                self._per_user[user_sub].discard(ws)
                if not self._per_user[user_sub]:
                    del self._per_user[user_sub]
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
