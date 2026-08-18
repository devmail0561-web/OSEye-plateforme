"""oseye-server user — manage local users."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_USERS_FILE = Path(os.environ.get("OSEYE_USERS_FILE", "/etc/oseye/users.json"))
_VALID_ROLES = {"admin", "analyst"}
_ROLE_GRANTS: dict[str, list[str]] = {
    "admin":   ["admin", "analyst"],
    "analyst": ["analyst"],
}


def _load() -> dict:
    try:
        if _USERS_FILE.exists():
            return json.loads(_USERS_FILE.read_text())
    except PermissionError:
        print(f"Permission denied reading {_USERS_FILE} — run as root.", file=sys.stderr)
        sys.exit(1)
    return {}


def _save(users: dict) -> None:
    _USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _USERS_FILE.write_text(json.dumps(users, indent=2))
    _USERS_FILE.chmod(0o640)


def _hash(password: str) -> str:
    import bcrypt
    encoded = password.encode("utf-8")[:72]
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("utf-8")


def _ask_password(prompt: str) -> str:
    import getpass

    from ._ui import PW_MAX_BYTES, PW_MIN_LEN, _validate_password
    print(f"  (min {PW_MIN_LEN} chars, max {PW_MAX_BYTES} bytes)")
    while True:
        pw = getpass.getpass(prompt)
        error = _validate_password(pw)
        if error:
            print(f"  {error}", file=sys.stderr)
            continue
        confirm = getpass.getpass("Confirm password: ")
        if pw != confirm:
            print("  Passwords do not match.", file=sys.stderr)
            continue
        return pw


def _cmd_create(args: argparse.Namespace) -> None:
    users = _load()
    username = args.username

    if username in users and not args.force:
        print(f"User '{username}' already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    role = args.role
    if role not in _VALID_ROLES:
        valid = ', '.join(sorted(_VALID_ROLES))
        print(f"Invalid role '{role}'. Valid roles: {valid}", file=sys.stderr)
        sys.exit(1)

    if args.password:
        from ._ui import _validate_password
        error = _validate_password(args.password)
        if error:
            print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)
        password = args.password
    else:
        password = _ask_password(f"Password for '{username}': ")

    users[username] = {
        "hashed_password": _hash(password),
        "roles": _ROLE_GRANTS[role],
    }
    _save(users)
    print(f"✓ User '{username}' created with role '{role}'.")
    print("  Restart oseye-server for changes to take effect.")


def _cmd_passwd(args: argparse.Namespace) -> None:
    users = _load()
    username = args.username

    if username not in users:
        print(f"User '{username}' not found.", file=sys.stderr)
        sys.exit(1)

    if args.password:
        from ._ui import _validate_password
        error = _validate_password(args.password)
        if error:
            print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)
        password = args.password
    else:
        password = _ask_password(f"New password for '{username}': ")

    users[username]["hashed_password"] = _hash(password)
    _save(users)
    print(f"✓ Password updated for '{username}'.")
    print("  Restart oseye-server for changes to take effect.")


def _cmd_delete(args: argparse.Namespace) -> None:
    users = _load()
    username = args.username

    if username not in users:
        print(f"User '{username}' not found.", file=sys.stderr)
        sys.exit(1)

    del users[username]
    _save(users)
    print(f"✓ User '{username}' deleted.")
    print("  Restart oseye-server for changes to take effect.")


def _cmd_list(_args: argparse.Namespace) -> None:
    users = _load()
    if not users:
        print("No users defined (server uses OSEYE_ADMIN/ANALYST_PASSWORD env vars).")
        return
    print(f"{'Username':<20} {'Roles'}")
    print("-" * 40)
    for username, data in sorted(users.items()):
        roles = ", ".join(data.get("roles", []))
        print(f"{username:<20} {roles}")


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="oseye-server user")
    sub = parser.add_subparsers(dest="subcmd", required=True)

    # create
    p_create = sub.add_parser("create", help="Create a new user")
    p_create.add_argument("username")
    p_create.add_argument("--role", required=True, choices=sorted(_VALID_ROLES),
                          help="User role: admin (full access) or analyst (read-only)")
    p_create.add_argument("--password", help="Password (prompted if omitted)")
    p_create.add_argument("--force", action="store_true", help="Overwrite existing user")

    # passwd
    p_passwd = sub.add_parser("passwd", help="Change a user's password")
    p_passwd.add_argument("username")
    p_passwd.add_argument("--password", help="New password (prompted if omitted)")

    # delete
    p_delete = sub.add_parser("delete", help="Delete a user")
    p_delete.add_argument("username")

    # list
    sub.add_parser("list", help="List all users")

    args = parser.parse_args(argv)

    if args.subcmd == "create":
        _cmd_create(args)
    elif args.subcmd == "passwd":
        _cmd_passwd(args)
    elif args.subcmd == "delete":
        _cmd_delete(args)
    elif args.subcmd == "list":
        _cmd_list(args)
