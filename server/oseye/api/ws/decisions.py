"""WebSocket endpoint — /ws/decisions — live decision stream."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from oseye.api.ws.manager import WebSocketManager

router = APIRouter(tags=["websocket"])

decisions_ws_manager = WebSocketManager()

_VALID_WS_ROLES = frozenset({"analyst", "admin"})


@router.websocket("/ws/decisions")
async def ws_decisions(ws: WebSocket) -> None:
    """Stream decision events to connected WebSocket clients.

    SEC-004: Token must be sent as the FIRST text frame within 5 seconds.
    SEC-005: Caller must hold 'analyst' or 'admin' role.
    Closes with code 4001 if token is missing/invalid, 4003 if role insufficient.
    """
    await ws.accept()

    try:
        token = await asyncio.wait_for(ws.receive_text(), timeout=5.0)
    except Exception:  # noqa: BLE001
        try:
            await ws.close(code=4001)
        except Exception:  # noqa: BLE001
            pass
        return

    if not token or len(token) > 4096:
        try:
            await ws.close(code=4001 if not token else 1008)
        except Exception:  # noqa: BLE001
            pass
        return

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

    roles: list[str] = list(current_user.get("roles", []))
    if not _VALID_WS_ROLES.intersection(roles):
        try:
            await ws.close(code=4003)
        except Exception:  # noqa: BLE001
            pass
        return

    user_sub: str | None = current_user.get("sub")
    await decisions_ws_manager.connect(ws, user_sub=user_sub)
    try:
        while True:
            await asyncio.sleep(30)
            await ws.send_text("ping")
    except (WebSocketDisconnect, Exception):  # noqa: BLE001
        pass
    finally:
        await decisions_ws_manager.disconnect(ws)
