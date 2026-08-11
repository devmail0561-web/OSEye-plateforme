"""Plugins router — /api/v1/plugins.

Endpoints:
    GET    /api/v1/plugins              — list installed plugins
    GET    /api/v1/plugins/{name}       — get plugin info
    POST   /api/v1/plugins/upload       — upload a .py file and install it (multipart)
    POST   /api/v1/plugins/install      — install a plugin from a server-local path
    POST   /api/v1/plugins/{name}/enable  — start plugin sandbox
    POST   /api/v1/plugins/{name}/disable — stop plugin sandbox
    DELETE /api/v1/plugins/{name}       — uninstall plugin
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger

# SEC-PLUGIN-001: only allow plugin installs from this directory (configurable via env)
_DEFAULT_PLUGIN_UPLOAD_DIR = "/tmp/oseye-plugin-uploads"  # noqa: S108
_PLUGIN_UPLOAD_DIR = Path(
    os.environ.get("OSEYE_PLUGIN_UPLOAD_DIR", _DEFAULT_PLUGIN_UPLOAD_DIR)
).resolve()

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


@router.get("/config")
async def get_plugin_config(
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> dict[str, Any]:
    """Return plugin system configuration (read-only).

    Exposes whether signature verification is required so the UI can
    display the appropriate warning to the admin.
    """
    mgr = _get_plugin_manager(request)
    return {
        "require_signature": mgr._require_signature,  # noqa: SLF001
        "has_trusted_keys": mgr._verifier is not None,  # noqa: SLF001
    }


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


_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+\.py$")


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_plugin(
    request: Request,
    file: UploadFile = File(...),
    verify: bool = True,
    _: dict[str, Any] = Depends(_require_admin),
) -> dict[str, Any]:
    """Upload a plugin .py file directly from the browser.

    SEC-PLUGIN-002: filename is validated against [a-zA-Z0-9_-]+\\.py
    to prevent path traversal via the filename. The file is written to a
    temporary directory inside _PLUGIN_UPLOAD_DIR, which is itself
    validated in install_plugin before being copied to plugins_dir.
    """
    filename = file.filename or ""
    if not _SAFE_NAME_RE.match(filename):
        raise HTTPException(
            status_code=422,
            detail="Invalid plugin filename. Must match [a-zA-Z0-9_-]+.py",
        )

    _PLUGIN_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = _PLUGIN_UPLOAD_DIR / filename

    content = await file.read()
    if len(content) > 1 * 1024 * 1024:  # 1 MB hard cap
        raise HTTPException(status_code=413, detail="Plugin file exceeds 1 MB limit")

    dest.write_bytes(content)
    _logger.info("plugin_uploaded", filename=filename, size=len(content))

    mgr = _get_plugin_manager(request)
    try:
        info = await mgr.install(dest, verify=verify)
    except (PermissionError, ValueError) as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        dest.unlink(missing_ok=True)  # clean up temp upload after install

    return {"name": info.name, "status": info.status}


@router.post("/install", status_code=status.HTTP_201_CREATED)
async def install_plugin(
    request: Request,
    body: _InstallBody,
    _: dict[str, Any] = Depends(_require_admin),
) -> dict[str, Any]:
    # SEC-PLUGIN-001: resolve the path and verify it is within the allowed upload directory
    resolved = Path(body.path).resolve()
    if not resolved.is_relative_to(_PLUGIN_UPLOAD_DIR):
        _logger.warning(
            "plugin_install_path_traversal_blocked path=%s allowed_base=%s",
            resolved,
            _PLUGIN_UPLOAD_DIR,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"Plugin path must be under the allowed upload directory "
                f"({_PLUGIN_UPLOAD_DIR})"
            ),
        )

    mgr = _get_plugin_manager(request)
    if not resolved.exists():
        raise HTTPException(status_code=422, detail=f"Path not found: {body.path}")
    try:
        info = await mgr.install(resolved, verify=body.verify)
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
