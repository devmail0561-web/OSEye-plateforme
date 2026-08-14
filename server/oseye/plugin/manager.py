from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from oseye.plugin.sandbox import PluginSandbox
from oseye.plugin.verifier import PluginVerifier

logger = logging.getLogger(__name__)


class PluginStatus(StrEnum):
    LOADED = "loaded"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class PluginInfo:
    name: str
    path: Path
    status: PluginStatus = PluginStatus.STOPPED
    pid: int | None = None
    error: str | None = None


class PluginManager:
    """Load/unload plugins and manage their lifecycle.

    Methods:
      - install(path): copy plugin to plugins_dir, verify signature if verifier present
      - enable(name): start sandbox subprocess
      - disable(name): stop subprocess
      - delete(name): remove from plugins_dir
      - list(): return list[PluginInfo]
      - get(name): return PluginInfo | None
    """

    def __init__(
        self,
        plugins_dir: Path,
        ipc_socket: str = "/var/run/oseye/plugin.sock",
        verifier: PluginVerifier | None = None,
        require_signature: bool = True,
    ) -> None:
        self._plugins_dir = plugins_dir
        self._ipc_socket = ipc_socket
        self._verifier = verifier
        # SEC-PLUGIN-003: when True, installations without a valid .sig are rejected
        # even if no verifier is configured (prevents silent bypass).
        self._require_signature = require_signature
        self._plugins: dict[str, PluginInfo] = {}
        self._sandboxes: dict[str, PluginSandbox] = {}
        self._lock = asyncio.Lock()

        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(
                "Cannot create plugins_dir %s — permission denied. "
                "Run as root or pre-create the directory.",
                plugins_dir,
            )
        self._discover()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def install(self, path: Path, *, verify: bool = True) -> PluginInfo:
        """Copy a plugin file into plugins_dir and register it.

        Signature enforcement rules:
          - If require_signature=True and no verifier is configured → rejected
            (prevents silent bypass when plugin_keys_dir is missing).
          - If require_signature=True and verifier is configured but .sig is
            absent or invalid → rejected.
          - If require_signature=False, verification is best-effort only (skipped
            when verifier is absent or verify=False).

        Raises ValueError if signature requirements are not met.
        Raises FileNotFoundError if path does not exist.
        """
        if not path.exists():
            raise FileNotFoundError(f"Plugin path does not exist: {path}")

        name = path.stem

        # SEC-PLUGIN-003: signature enforcement.
        # verify=False is an explicit caller override — skip all signature checks.
        sig_path = path.with_suffix(".sig")
        needs_verify = False
        if verify and self._require_signature:
            if self._verifier is None:
                raise ValueError(
                    "Plugin signature verification is required "
                    "(OSEYE_PLUGIN_REQUIRE_SIGNATURE=true) but no trusted keys are "
                    "configured. Add Ed25519 public keys to plugin_keys_dir."
                )
            if not sig_path.exists():
                raise ValueError(
                    f"Signature file not found: {sig_path}. "
                    "Provide a .sig file alongside the plugin."
                )
            needs_verify = True
        elif verify and self._verifier is not None and sig_path.exists():
            needs_verify = True

        dest = self._plugins_dir / path.name
        async with self._lock:
            shutil.copy2(path, dest)

            # PL-03: verify AFTER copy to eliminate TOCTOU window
            if needs_verify and self._verifier is not None:
                if not self._verifier.verify(dest, sig_path):
                    dest.unlink(missing_ok=True)
                    raise ValueError(
                        f"Signature verification failed for plugin {name!r}. "
                        "Ensure the plugin is signed with a trusted key."
                    )

            info = PluginInfo(name=name, path=dest, status=PluginStatus.LOADED)
            self._plugins[name] = info
            logger.info("Installed plugin %r -> %s", name, dest)

        return info

    async def enable(self, name: str) -> PluginInfo:
        """Start the plugin subprocess in a sandbox.

        Raises KeyError if the plugin is not installed.
        Raises RuntimeError if the plugin is already running.
        """
        async with self._lock:
            info = self._plugins.get(name)
            if info is None:
                raise KeyError(f"Plugin not found: {name!r}")
            if info.status == PluginStatus.RUNNING:
                raise RuntimeError(f"Plugin {name!r} is already running")

            module = f"oseye_plugins.{name}"
            sandbox = PluginSandbox(
                plugin_module=module,
                socket_path=self._ipc_socket,
            )
            try:
                proc = await sandbox.start()
                info.status = PluginStatus.RUNNING
                info.pid = proc.pid
                info.error = None
                self._sandboxes[name] = sandbox
                logger.info("Enabled plugin %r (pid=%d)", name, proc.pid)
            except Exception as exc:
                info.status = PluginStatus.ERROR
                info.error = str(exc)
                logger.exception("Failed to start plugin %r", name)
                raise

        return info

    async def disable(self, name: str) -> PluginInfo:
        """Stop the plugin subprocess.

        Raises KeyError if the plugin is not installed.
        """
        async with self._lock:
            info = self._plugins.get(name)
            if info is None:
                raise KeyError(f"Plugin not found: {name!r}")

            sandbox = self._sandboxes.pop(name, None)
            if sandbox is not None:
                await sandbox.stop()

            info.status = PluginStatus.STOPPED
            info.pid = None
            logger.info("Disabled plugin %r", name)

        return info

    async def delete(self, name: str) -> None:
        """Stop and remove a plugin from plugins_dir.

        Raises KeyError if the plugin is not installed.
        """
        async with self._lock:
            info = self._plugins.get(name)
            if info is None:
                raise KeyError(f"Plugin not found: {name!r}")

            sandbox = self._sandboxes.pop(name, None)
            if sandbox is not None:
                await sandbox.stop()

            try:
                info.path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove plugin file: %s", info.path)

            del self._plugins[name]
            logger.info("Deleted plugin %r", name)

    def list(self) -> list[PluginInfo]:
        """Return all registered plugins."""
        return list(self._plugins.values())

    def get(self, name: str) -> PluginInfo | None:
        """Return PluginInfo for the given plugin name, or None."""
        return self._plugins.get(name)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover(self) -> None:
        """Scan plugins_dir for existing .py files and register them.

        When require_signature=True, each discovered plugin must have a
        corresponding .sig file that passes verification.  Plugins without a
        valid signature are registered with status=ERROR and skipped — they
        will not be enabled until the signature issue is resolved (PL-02 fix).
        """
        for py_file in sorted(self._plugins_dir.glob("*.py")):
            name = py_file.stem
            if self._require_signature:
                sig_path = py_file.with_suffix(".sig")
                if not sig_path.exists():
                    logger.warning(
                        "plugin_discover_no_sig: signature file missing for %r "
                        "(require_signature=True) — plugin not loaded",
                        name,
                    )
                    self._plugins[name] = PluginInfo(
                        name=name,
                        path=py_file,
                        status=PluginStatus.ERROR,
                        error="signature file missing — plugin not loaded (require_signature=True)",
                    )
                    continue
                if self._verifier is not None:
                    try:
                        self._verifier.verify(py_file, sig_path)
                    except Exception as exc:
                        logger.warning(
                            "plugin_discover_sig_invalid: signature invalid for %r: %s",
                            name,
                            exc,
                        )
                        self._plugins[name] = PluginInfo(
                            name=name,
                            path=py_file,
                            status=PluginStatus.ERROR,
                            error=f"signature invalid: {exc}",
                        )
                        continue
            self._plugins[name] = PluginInfo(
                name=name,
                path=py_file,
                status=PluginStatus.LOADED,
            )
            logger.debug("Discovered plugin: %s", name)

        if self._plugins:
            logger.info(
                "Discovered %d plugin(s) in %s", len(self._plugins), self._plugins_dir
            )
