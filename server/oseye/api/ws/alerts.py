"""WebSocket endpoint — /ws/alerts — live alert stream."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from oseye.api.ws.manager import WebSocketManager

router = APIRouter(tags=["websocket"])

# Module-level manager — shared with the RuleWorker via app.state
alerts_ws_manager = WebSocketManager()


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket) -> None:
    """Stream alert events to connected WebSocket clients."""
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
