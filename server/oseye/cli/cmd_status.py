"""oseye-server status — show server status."""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.request

_SYSTEMCTL = "/usr/bin/systemctl"


def _systemctl_available() -> bool:
    return os.path.isfile(_SYSTEMCTL)


def _health_check() -> dict | None:
    """Query the local health endpoint."""
    port = os.environ.get("OSEYE_API_PORT", "8000")
    url = f"http://localhost:{port}/api/v1/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            import json
            return json.loads(resp.read())
    except Exception:
        return None


def run(argv: list[str] | None = None) -> None:  # noqa: ARG001
    if _systemctl_available():
        subprocess.run(["systemctl", "status", "oseye-server", "--no-pager"], check=False)
        print()

    health = _health_check()
    if health:
        print(f"API health : \033[32mok\033[0m  (status={health.get('status')})")
    else:
        print("API health : \033[31munreachable\033[0m")
        if not _systemctl_available():
            sys.exit(1)
