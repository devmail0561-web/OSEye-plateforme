"""WebSocket endpoint — /ws/alerts — live alert stream."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from oseye.api.ws.manager import WebSocketManager

router = APIRouter(tags=["websocket"])

# Module-level manager — shared with the RuleWorker via app.state
alerts_ws_manager = WebSocketManager()

_VALID_WS_ROLES = frozenset({"analyst", "admin"})


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket) -> None:
    """Stream alert events to connected WebSocket clients.

    SEC-004: Token must be sent as the FIRST text frame within 5 seconds
    (not as a URL query param which gets logged by uvicorn).
    SEC-005: Caller must hold 'analyst' or 'admin' role.
    Closes with code 4001 if the token is missing, times out, or invalid.
    Closes with code 4003 if the token lacks a required role.
    """
    await ws.accept()

    # SEC-004: read token from first text frame, not query string
    try:
        token = await asyncio.wait_for(ws.receive_text(), timeout=5.0)
    except (asyncio.TimeoutError, Exception):  # noqa: BLE001
        await ws.close(code=4001)
        return

    if not token:
        await ws.close(code=4001)
        return

    try:
        handler = ws.app.state.jwt_handler
        payload = handler.verify_token(token)
    except Exception:  # noqa: BLE001
        await ws.close(code=4001)
        return

    # SEC-005: enforce role check
    roles: list[str] = list(payload.get("roles", []))
    if not _VALID_WS_ROLES.intersection(roles):
        await ws.close(code=4003)
        return

    await alerts_ws_manager.connect(ws)
    try:
        while True:
            # Keep connection alive; clients can send pings
            await asyncio.sleep(30)
            await ws.send_text("ping")
    except (WebSocketDisconnect, Exception):  # noqa: BLE001
        pass
    finally:
        await alerts_ws_manager.disconnect(ws)
