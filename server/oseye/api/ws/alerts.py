"""WebSocket endpoint — /ws/alerts — live alert stream."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from oseye.api.ws.manager import WebSocketManager

router = APIRouter(tags=["websocket"])

# Module-level manager — shared with the RuleWorker via app.state
alerts_ws_manager = WebSocketManager(channel="oseye:ws:alerts")

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
    except (TimeoutError, Exception):  # noqa: BLE001
        try:
            await ws.close(code=4001)
        except Exception:  # noqa: BLE001
            pass
        return

    if not token:
        try:
            await ws.close(code=4001)
        except Exception:  # noqa: BLE001
            pass
        return

    # API-09: reject oversized tokens to prevent DoS via memory exhaustion.
    if len(token) > 4096:
        try:
            await ws.close(code=1008)  # 1008 = Policy Violation
        except Exception:  # noqa: BLE001
            pass
        return

    # B-18: support both JWT tokens and API Keys (osk_ prefix)
    current_user: dict
    if token.startswith("osk_"):
        api_key_repo = getattr(ws.app.state, "api_key_repo", None)
        if api_key_repo is None:
            try:
                await ws.close(code=4001)
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            key_data = await api_key_repo.verify(token)
        except Exception:  # noqa: BLE001
            key_data = None
        if key_data is None:
            try:
                await ws.close(code=4001)
            except Exception:  # noqa: BLE001
                pass
            return
        current_user = {"sub": key_data.name, "roles": list(key_data.roles)}
    else:
        try:
            handler = ws.app.state.jwt_handler
            current_user = handler.verify_token(token)
        except Exception:  # noqa: BLE001
            try:
                await ws.close(code=4001)
            except Exception:  # noqa: BLE001
                pass
            return

    # SEC-005: enforce role check
    roles: list[str] = list(current_user.get("roles", []))
    if not _VALID_WS_ROLES.intersection(roles):
        try:
            await ws.close(code=4003)
        except Exception:  # noqa: BLE001
            pass
        return

    # SEC-WS-001: pass user_sub so the manager can enforce per-user connection cap
    user_sub: str | None = current_user.get("sub")
    await alerts_ws_manager.connect(ws, user_sub=user_sub)
    try:
        while True:
            # Keep connection alive; clients can send pings
            await asyncio.sleep(30)
            await ws.send_text("ping")
    except (WebSocketDisconnect, Exception):  # noqa: BLE001
        pass
    finally:
        await alerts_ws_manager.disconnect(ws)
