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

    def __init__(
        self,
        redis_url: str | None = None,
        channel: str = "oseye:ws:default",
    ) -> None:
        self._connections: set[WebSocket] = set()
        # Maps user_sub → set of WebSocket connections for that user
        self._per_user: dict[str, set[WebSocket]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._redis_url = redis_url
        self._channel = channel
        self._subscriber_task: asyncio.Task | None = None

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

    async def start_redis_subscriber(self) -> None:
        """Démarre le subscriber Redis en arrière-plan."""
        if not self._redis_url:
            return
        self._subscriber_task = asyncio.create_task(
            self._redis_subscribe_loop(), name=f"ws-subscriber-{self._channel}"
        )

    async def stop_redis_subscriber(self) -> None:
        """Arrête le subscriber Redis."""
        if self._subscriber_task:
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except asyncio.CancelledError:
                pass

    async def _redis_subscribe_loop(self) -> None:
        """Écoute le channel Redis et broadcast localement."""
        import redis.asyncio as _redis  # noqa: PLC0415

        while True:
            try:
                async with _redis.from_url(self._redis_url) as rc:
                    async with rc.pubsub() as ps:
                        await ps.subscribe(self._channel)
                        logger.info("ws_redis_subscribed channel=%s", self._channel)
                        async for msg in ps.listen():
                            if msg["type"] == "message":
                                data = msg["data"]
                                if isinstance(data, (bytes, bytearray)):
                                    await self._broadcast_local(data)
            except asyncio.CancelledError:
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("ws_redis_subscriber_error error=%s", exc)
                await asyncio.sleep(2)

    async def _broadcast_local(self, message: bytes) -> None:
        """Broadcast local seulement (sans republier sur Redis)."""
        dead: list[WebSocket] = []
        async with self._lock:
            clients = list(self._connections)
        for ws in clients:
            try:
                await ws.send_bytes(message)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        if dead:
            for ws in dead:
                await self.disconnect(ws)

    async def broadcast(self, message: bytes) -> None:
        """Send *message* to all connected clients; publish on Redis if configured."""
        await self._broadcast_local(message)
        if self._redis_url:
            try:
                import redis.asyncio as _redis  # noqa: PLC0415

                async with _redis.from_url(self._redis_url) as rc:
                    await rc.publish(self._channel, message)
            except Exception as exc:  # noqa: BLE001
                logger.warning("ws_redis_publish_failed error=%s", exc)
