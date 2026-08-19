"""oseye-server agents — agent management commands."""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error

_USAGE = """\
oseye-server agents ping <CN> [--timeout N] [--token JWT]

  Ping a connected agent and display round-trip latency.
  Returns 0 on success, 1 on timeout or error.

Options:
  --timeout N   Seconds to wait for reply (default: 5)
  --token JWT   Bearer token (default: reads OSEYE_CLI_TOKEN env var)
"""


def _api_url() -> str:
    port = os.environ.get("OSEYE_API_PORT", "8000")
    return f"http://localhost:{port}"


def _ping(cn: str, timeout: float, token: str | None) -> int:
    url = f"{_api_url()}/api/v1/agents/{cn}/ping?timeout={timeout}"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=int(timeout) + 2) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        print(f"\033[31mHTTP {exc.code}: {exc.reason}\033[0m", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"\033[31mError: {exc}\033[0m", file=sys.stderr)
        return 1

    if data.get("status") == "ok":
        latency = data.get("latency_ms", "?")
        print(f"\033[32m{cn}: ok  ({latency} ms)\033[0m")
        return 0
    else:
        print(f"\033[33m{cn}: timeout\033[0m")
        return 1


def run(argv: list[str] | None = None) -> None:
    args = argv or []

    if not args or args[0] in ("help", "--help", "-h"):
        print(_USAGE)
        return

    subcmd = args[0]
    rest = args[1:]

    if subcmd == "ping":
        if not rest:
            print("Error: missing CN argument", file=sys.stderr)
            print(_USAGE, file=sys.stderr)
            sys.exit(1)
        cn = rest[0]
        timeout = 5.0
        token = os.environ.get("OSEYE_CLI_TOKEN")
        i = 1
        while i < len(rest):
            if rest[i] == "--timeout" and i + 1 < len(rest):
                try:
                    timeout = float(rest[i + 1])
                except ValueError:
                    print("Error: --timeout must be a number", file=sys.stderr)
                    sys.exit(1)
                i += 2
            elif rest[i] == "--token" and i + 1 < len(rest):
                token = rest[i + 1]
                i += 2
            else:
                i += 1
        sys.exit(_ping(cn, timeout, token))
    else:
        print(f"Unknown agents subcommand: {subcmd}", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        sys.exit(1)
