"""oseye-server rules — admin-managed rule CRUD commands."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

_USAGE = """\
oseye-server rules list      [--enabled-only] [--token JWT]
oseye-server rules create    --name NAME [--type anomaly|surveillance]
                             [--severity info|low|medium|high|critical]
                             [--priority low|medium|high|critical]
                             [--profile PROFILE_ID]
                             [--yaml YAML_CONTENT] [--config JSON]
                             [--token JWT]
oseye-server rules edit      <RULE_ID> [--name NAME] [--type TYPE]
                             [--severity SEV] [--priority PRIO]
                             [--enabled true|false] [--token JWT]
oseye-server rules delete    <RULE_ID> [--token JWT]
oseye-server rules get       <RULE_ID> [--token JWT]
"""


def _api_url() -> str:
    port = os.environ.get("OSEYE_API_PORT", "8000")
    return f"http://localhost:{port}"


def _token(args_token: str | None) -> str | None:
    return args_token or os.environ.get("OSEYE_CLI_TOKEN")


def _request(method: str, path: str, token: str | None, body: dict | None = None) -> dict:
    url = f"{_api_url()}{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        try:
            detail = json.loads(body_bytes).get("detail", exc.reason)
        except Exception:
            detail = exc.reason
        print(f"\033[31mHTTP {exc.code}: {detail}\033[0m", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        print(f"\033[31mError: {exc}\033[0m", file=sys.stderr)
        sys.exit(1)


def _print_rule(r: dict) -> None:
    print(f"  id       : {r.get('rule_id', r.get('id', '?'))}")
    print(f"  name     : {r.get('name')}")
    print(f"  type     : {r.get('rule_type', 'anomaly')}")
    print(f"  severity : {r.get('severity')}")
    print(f"  priority : {r.get('priority', 'medium')}")
    print(f"  enabled  : {r.get('enabled')}")
    print(f"  version  : {r.get('version', 1)}")
    print(f"  profile  : {r.get('profile_id', '-')}")
    print()


def run(argv: list[str] | None = None) -> None:
    args = argv or []

    if not args or args[0] in ("help", "--help", "-h"):
        print(_USAGE)
        return

    subcmd = args[0]
    rest = args[1:]

    # Parse common --token
    tok: str | None = None
    filtered: list[str] = []
    i = 0
    while i < len(rest):
        if rest[i] == "--token" and i + 1 < len(rest):
            tok = rest[i + 1]
            i += 2
        else:
            filtered.append(rest[i])
            i += 1
    rest = filtered
    tok = _token(tok)

    if subcmd == "list":
        enabled_only = "--enabled-only" in rest
        path = "/api/v1/rules/db"
        if enabled_only:
            path += "?enabled_only=true"
        data = _request("GET", path, tok)
        items = data.get("items", [])
        if not items:
            print("No rules found.")
            return
        print(f"{'ID':<38} {'Name':<30} {'Type':<12} {'Sev':<10} {'En':>4}")
        print("-" * 100)
        for r in items:
            rid = r.get("rule_id", "?")
            print(f"{rid:<38} {r.get('name',''):<30} {r.get('rule_type',''):<12} "
                  f"{r.get('severity',''):<10} {'Y' if r.get('enabled') else 'N':>4}")

    elif subcmd == "create":
        params: dict[str, str | bool] = {}
        i = 0
        while i < len(rest):
            if rest[i] == "--name" and i + 1 < len(rest):
                params["name"] = rest[i + 1]; i += 2
            elif rest[i] == "--type" and i + 1 < len(rest):
                params["rule_type"] = rest[i + 1]; i += 2
            elif rest[i] == "--severity" and i + 1 < len(rest):
                params["severity"] = rest[i + 1]; i += 2
            elif rest[i] == "--priority" and i + 1 < len(rest):
                params["priority"] = rest[i + 1]; i += 2
            elif rest[i] == "--profile" and i + 1 < len(rest):
                params["profile_id"] = rest[i + 1]; i += 2
            elif rest[i] == "--yaml" and i + 1 < len(rest):
                params["yaml_content"] = rest[i + 1]; i += 2
            elif rest[i] == "--config" and i + 1 < len(rest):
                params["config_json"] = rest[i + 1]; i += 2
            else:
                i += 1
        if "name" not in params:
            print("Error: --name is required", file=sys.stderr)
            sys.exit(1)
        result = _request("POST", "/api/v1/rules", tok, params)
        print("\033[32mRule created:\033[0m")
        _print_rule(result)

    elif subcmd == "edit":
        if not rest:
            print("Error: missing RULE_ID", file=sys.stderr)
            sys.exit(1)
        rule_id = rest[0]
        rest = rest[1:]
        params = {}
        i = 0
        while i < len(rest):
            if rest[i] == "--name" and i + 1 < len(rest):
                params["name"] = rest[i + 1]; i += 2
            elif rest[i] == "--type" and i + 1 < len(rest):
                params["rule_type"] = rest[i + 1]; i += 2
            elif rest[i] == "--severity" and i + 1 < len(rest):
                params["severity"] = rest[i + 1]; i += 2
            elif rest[i] == "--priority" and i + 1 < len(rest):
                params["priority"] = rest[i + 1]; i += 2
            elif rest[i] == "--enabled" and i + 1 < len(rest):
                params["enabled"] = rest[i + 1].lower() == "true"; i += 2
            else:
                i += 1
        result = _request("PUT", f"/api/v1/rules/db/{rule_id}", tok, params)
        print("\033[32mRule updated:\033[0m")
        _print_rule(result)

    elif subcmd == "delete":
        if not rest:
            print("Error: missing RULE_ID", file=sys.stderr)
            sys.exit(1)
        rule_id = rest[0]
        _request("DELETE", f"/api/v1/rules/db/{rule_id}", tok)
        print(f"\033[32mRule {rule_id} deleted.\033[0m")

    elif subcmd == "get":
        if not rest:
            print("Error: missing RULE_ID", file=sys.stderr)
            sys.exit(1)
        rule_id = rest[0]
        result = _request("GET", f"/api/v1/rules/db/{rule_id}", tok)
        _print_rule(result)

    else:
        print(f"Unknown rules subcommand: {subcmd}", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        sys.exit(1)
