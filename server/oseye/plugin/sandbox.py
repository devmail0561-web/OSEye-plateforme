from __future__ import annotations

import asyncio
import ctypes
import errno
import logging
import os
import resource
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_CGROUP_ROOT = Path("/sys/fs/cgroup")


def _apply_rlimits(cpu_limit_s: int, mem_limit_bytes: int) -> None:
    """Preexec function: apply resource limits in the child process.

    Applied limits:
      - RLIMIT_CPU  : wall-clock CPU seconds before SIGXCPU
      - RLIMIT_AS   : virtual address space (prevents memory bombs)
      - RLIMIT_NOFILE: max open file descriptors (reduces exfil surface)
      - RLIMIT_NPROC: max child processes (prevents fork bombs)
      - RLIMIT_FSIZE: max bytes a single write() can produce (limits disk writes)

    # SECURITY NOTE (PL-01): seccomp-bpf filtering is NOT implemented.
    # A malicious plugin subprocess has unrestricted syscall access including
    # socket(), execve(), ptrace(). Implement via python-seccomp
    # (libseccomp-dev) before enabling plugins in production.
    """
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit_s, cpu_limit_s))
    resource.setrlimit(resource.RLIMIT_AS, (mem_limit_bytes, mem_limit_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))          # max 64 file descriptors
    resource.setrlimit(resource.RLIMIT_NPROC, (8, 8))             # max 8 child processes
    _fsize = 10 * 1024 * 1024  # max 10 MB writes
    resource.setrlimit(resource.RLIMIT_FSIZE, (_fsize, _fsize))


class PluginSandbox:
    """Runs a plugin module in an isolated subprocess with resource limits.

    Limits applied:
      - CPU    : RLIMIT_CPU  = cpu_limit_s (default 5 s per burst)
      - Memory : RLIMIT_AS   = mem_limit_mb * 1024 * 1024 (default 128 MB)
      - FDs    : RLIMIT_NOFILE = 64 (reduces exfiltration surface)
      - Procs  : RLIMIT_NPROC  = 8  (prevents fork bombs)
      - Writes : RLIMIT_FSIZE  = 10 MB (limits disk writes)

    cgroups v2 note: full cgroup isolation requires root. When not root,
    we fall back to rlimit-only isolation and log a warning.
    """

    def __init__(
        self,
        plugin_module: str,
        socket_path: str,
        cpu_limit_s: int = 5,
        mem_limit_mb: int = 128,
    ) -> None:
        self._plugin_module = plugin_module
        self._socket_path = socket_path
        self._cpu_limit_s = cpu_limit_s
        self._mem_limit_bytes = mem_limit_mb * 1024 * 1024
        self._process: asyncio.subprocess.Process | None = None
        self._cgroup_path: Path | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def start(self) -> asyncio.subprocess.Process:
        """Start the plugin subprocess and apply resource limits.

        Returns the running asyncio.subprocess.Process.
        Raises RuntimeError if the process is already running.
        """
        if self._process is not None and self._process.returncode is None:
            raise RuntimeError(
                f"Plugin {self._plugin_module!r} is already running (pid={self._process.pid})"
            )

        self._try_setup_cgroup()

        cpu_limit = self._cpu_limit_s
        mem_limit = self._mem_limit_bytes

        def _preexec() -> None:
            # Network namespace isolation: CLONE_NEWNET = 0x40000000
            # Prevents the plugin from making any outbound connections.
            # Imports are at module level to avoid import-lock deadlock after fork()
            # in a multi-threaded asyncio process.
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # PL-02: configurable strict mode — abort plugin launch when
            # network namespace isolation fails (requires CAP_SYS_ADMIN or
            # a kernel with unprivileged user namespaces enabled).
            strict_netns = os.environ.get("OSEYE_PLUGIN_STRICT_NETNS", "false").lower() == "true"
            ret = libc.unshare(0x40000000)  # CLONE_NEWNET
            if ret != 0:
                err = ctypes.get_errno()
                code = errno.errorcode.get(err, err)
                if strict_netns:
                    print(
                        f"plugin_sandbox: unshare(CLONE_NEWNET) failed (ret={ret}, err={code})"
                        " — aborting plugin launch (OSEYE_PLUGIN_STRICT_NETNS=true)",
                        file=sys.stderr,
                    )
                    os._exit(1)  # Abort plugin launch if strict mode
                else:
                    print(
                        f"plugin_sandbox: unshare(CLONE_NEWNET) failed "
                        f"(ret={ret}) — network not isolated",
                        file=sys.stderr,
                    )
            _apply_rlimits(cpu_limit, mem_limit)
            if self._cgroup_path is not None:
                _move_to_cgroup(self._cgroup_path)

        self._process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            self._plugin_module,
            "--socket",
            self._socket_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=_preexec,
        )

        async def _drain(stream: asyncio.StreamReader | None) -> None:
            if stream is not None:
                async for _ in stream:
                    pass

        asyncio.create_task(_drain(self._process.stdout), name="plugin_stdout_drain")
        asyncio.create_task(_drain(self._process.stderr), name="plugin_stderr_drain")

        logger.info(
            "Started plugin %r in subprocess pid=%d",
            self._plugin_module,
            self._process.pid,
        )
        return self._process

    async def stop(self) -> None:
        """Stop the plugin subprocess gracefully, then forcefully if needed."""
        if self._process is None or self._process.returncode is not None:
            return

        pid = self._process.pid
        logger.info("Stopping plugin %r (pid=%d)", self._plugin_module, pid)

        try:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except TimeoutError:
                logger.warning(
                    "Plugin %r (pid=%d) did not exit after SIGTERM, sending SIGKILL",
                    self._plugin_module,
                    pid,
                )
                self._process.kill()
                await self._process.wait()
        except ProcessLookupError:
            pass  # Already gone

        self._cleanup_cgroup()
        logger.info("Plugin %r (pid=%d) stopped", self._plugin_module, pid)

    @property
    def pid(self) -> int | None:
        """Return the PID of the running subprocess, or None if not running."""
        if self._process is None:
            return None
        return self._process.pid

    # ------------------------------------------------------------------
    # cgroups v2 helpers (best-effort, requires root)
    # ------------------------------------------------------------------

    def _try_setup_cgroup(self) -> None:
        """Attempt to create a cgroup v2 scope for this plugin.

        Falls back silently to rlimit-only mode when not root or cgroups
        v2 is not available.
        """
        if os.geteuid() != 0:
            logger.warning(
                "Not running as root; cgroup v2 isolation unavailable for plugin %r. "
                "Falling back to rlimit-only isolation.",
                self._plugin_module,
            )
            return

        cgroup_base = _CGROUP_ROOT / "oseye" / "plugins"
        safe_name = self._plugin_module.replace(".", "_").replace("/", "_")
        cgroup_path = cgroup_base / safe_name

        try:
            cgroup_path.mkdir(parents=True, exist_ok=True)
            self._cgroup_path = cgroup_path
            logger.debug("Created cgroup v2 scope: %s", cgroup_path)
        except OSError:
            logger.warning(
                "Failed to create cgroup for plugin %r; using rlimit-only isolation",
                self._plugin_module,
                exc_info=True,
            )

    def _cleanup_cgroup(self) -> None:
        """Remove the plugin's cgroup directory after the process exits."""
        if self._cgroup_path is None:
            return
        try:
            self._cgroup_path.rmdir()
            logger.debug("Removed cgroup: %s", self._cgroup_path)
        except OSError:
            logger.debug(
                "Could not remove cgroup %s (may already be gone)",
                self._cgroup_path,
                exc_info=True,
            )
        finally:
            self._cgroup_path = None


def _move_to_cgroup(cgroup_path: Path) -> None:
    """Move the calling process into the given cgroup v2 scope.

    Called from preexec_fn inside the child process.
    """
    procs_file = cgroup_path / "cgroup.procs"
    try:
        procs_file.write_text(str(os.getpid()))
    except OSError:
        pass  # Best-effort; errors here are non-fatal
