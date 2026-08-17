"""oseye-server status — show server status."""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.request
import urllib.error


def _via_systemd() -> bool:
    return bool(os.environ.get("INVOCATION_ID"))


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
    # Systemd path: show systemctl status then health
    if not _via_systemd():
        subprocess.run(["systemctl", "status", "oseye-server", "--no-pager"], check=False)
        print()

    health = _health_check()
    if health:
        print(f"API health : \033[32mok\033[0m  (status={health.get('status')})")
    else:
        print("API health : \033[31munreachable\033[0m")
        if _via_systemd():
            sys.exit(1)
