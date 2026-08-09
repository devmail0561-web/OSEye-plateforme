"""Plugins router — /api/v1/plugins.

Endpoints:
    GET    /api/v1/plugins              — list installed plugins
    GET    /api/v1/plugins/{name}       — get plugin info
    POST   /api/v1/plugins/install      — install a plugin from a local path
    POST   /api/v1/plugins/{name}/enable  — start plugin sandbox
    POST   /api/v1/plugins/{name}/disable — stop plugin sandbox
    DELETE /api/v1/plugins/{name}       — uninstall plugin
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/plugins", tags=["plugins"])

_require_reader = require_role("analyst", "admin")
_require_admin = require_role("admin")


def _get_plugin_manager(request: Request) -> Any:
    mgr = getattr(request.app.state, "plugin_manager", None)
    if mgr is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Plugin manager not initialised",
        )
    return mgr


class _InstallBody(BaseModel):
    path: str
    verify: bool = True


@router.get("")
async def list_plugins(
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> list[dict[str, Any]]:
    mgr = _get_plugin_manager(request)
    return [
        {"name": p.name, "status": p.status, "pid": p.pid, "error": p.error}
        for p in mgr.list()
    ]


@router.get("/{name}")
async def get_plugin(
    name: str,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> dict[str, Any]:
    mgr = _get_plugin_manager(request)
    info = mgr.get(name)
    if info is None:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return {"name": info.name, "status": info.status, "pid": info.pid, "error": info.error}


@router.post("/install", status_code=status.HTTP_201_CREATED)
async def install_plugin(
    request: Request,
    body: _InstallBody,
    _: dict[str, Any] = Depends(_require_admin),
) -> dict[str, Any]:
    mgr = _get_plugin_manager(request)
    path = Path(body.path)
    if not path.exists():
        raise HTTPException(status_code=422, detail=f"Path not found: {body.path}")
    try:
        info = await mgr.install(path, verify=body.verify)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"name": info.name, "status": info.status}


@router.post("/{name}/enable")
async def enable_plugin(
    name: str,
    request: Request,
    _: dict[str, Any] = Depends(_require_admin),
) -> dict[str, Any]:
    mgr = _get_plugin_manager(request)
    if mgr.get(name) is None:
        raise HTTPException(status_code=404, detail="Plugin not found")
    info = await mgr.enable(name)
    return {"name": info.name, "status": info.status, "pid": info.pid}


@router.post("/{name}/disable")
async def disable_plugin(
    name: str,
    request: Request,
    _: dict[str, Any] = Depends(_require_admin),
) -> dict[str, Any]:
    mgr = _get_plugin_manager(request)
    if mgr.get(name) is None:
        raise HTTPException(status_code=404, detail="Plugin not found")
    info = await mgr.disable(name)
    return {"name": info.name, "status": info.status}


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_plugin(
    name: str,
    request: Request,
    _: dict[str, Any] = Depends(_require_admin),
) -> None:
    mgr = _get_plugin_manager(request)
    if mgr.get(name) is None:
        raise HTTPException(status_code=404, detail="Plugin not found")
    await mgr.delete(name)
