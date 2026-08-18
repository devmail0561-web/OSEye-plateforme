"""oseye-server enrollment token — manage enrollment tokens."""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Config loading — reads server.env + secrets.env (DB URL + HMAC key)
# ---------------------------------------------------------------------------

def _load_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env file, ignoring comments and blanks."""
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def _get_db_url() -> str:
    """Resolve DB URL: env var > secrets.env > server.env."""
    if os.environ.get("OSEYE_DB_URL"):
        return os.environ["OSEYE_DB_URL"]
    for path in [
        Path("/etc/oseye/secrets.env"),
        Path("/etc/oseye/server.env"),
    ]:
        env = _load_env_file(path)
        if "OSEYE_DB_URL" in env:
            return env["OSEYE_DB_URL"]
    print(
        "Cannot find OSEYE_DB_URL.\n"
        "Set it in the environment, /etc/oseye/secrets.env, or /etc/oseye/server.env.",
        file=sys.stderr,
    )
    sys.exit(1)


def _get_hmac_key() -> str:
    """Resolve HMAC key used to hash tokens."""
    if os.environ.get("OSEYE_CHECKPOINT_HMAC_KEY"):
        return os.environ["OSEYE_CHECKPOINT_HMAC_KEY"]
    for path in [
        Path("/etc/oseye/secrets.env"),
        Path("/etc/oseye/server.env"),
    ]:
        env = _load_env_file(path)
        if "OSEYE_CHECKPOINT_HMAC_KEY" in env:
            return env["OSEYE_CHECKPOINT_HMAC_KEY"]
    print(
        "Cannot find OSEYE_CHECKPOINT_HMAC_KEY.\n"
        "Set it in the environment or /etc/oseye/secrets.env.",
        file=sys.stderr,
    )
    sys.exit(1)


def _make_session_factory():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    engine = create_async_engine(_get_db_url(), echo=False)
    return async_sessionmaker(engine, expire_on_commit=False)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

async def _create(hours: int) -> None:
    os.environ.setdefault("OSEYE_CHECKPOINT_HMAC_KEY", _get_hmac_key())
    from oseye.storage.repositories.enrollment_tokens import SQLEnrollmentTokenRepository

    sf = _make_session_factory()
    repo = SQLEnrollmentTokenRepository(sf)

    raw = secrets.token_hex(32)
    expires_at = datetime.now(UTC) + timedelta(hours=hours)
    token_id = await repo.create(raw, expires_at, created_by="cli")

    print("\nEnrollment token created:")
    print(f"  Token   : {raw}")
    print(f"  ID      : {token_id}")
    print(f"  Expires : {expires_at.strftime('%Y-%m-%d %H:%M UTC')} ({hours}h)")
    print("\nTo enroll an agent:")
    print(f"  oseye-config enroll --server <HOST>:50051 --token {raw}\n")


async def _list() -> None:
    os.environ.setdefault("OSEYE_CHECKPOINT_HMAC_KEY", _get_hmac_key())
    from oseye.storage.repositories.enrollment_tokens import SQLEnrollmentTokenRepository

    sf = _make_session_factory()
    repo = SQLEnrollmentTokenRepository(sf)
    tokens = await repo.list_active()

    if not tokens:
        print("No active enrollment tokens.")
        return

    print(f"\n{'ID':<38}  {'Created by':<12}  {'Expires'}")
    print("-" * 72)
    for t in tokens:
        expires = t.get("expires_at", "")[:16].replace("T", " ")
        created_by = t.get("created_by", "")
        token_id = t.get("token_id", "")
        print(f"{token_id:<38}  {created_by:<12}  {expires} UTC")
    print()


async def _revoke(token_id: str) -> None:
    os.environ.setdefault("OSEYE_CHECKPOINT_HMAC_KEY", _get_hmac_key())
    from oseye.storage.repositories.enrollment_tokens import SQLEnrollmentTokenRepository

    sf = _make_session_factory()
    repo = SQLEnrollmentTokenRepository(sf)
    ok = await repo.revoke(token_id)

    if ok:
        print(f"✓ Token {token_id} revoked.")
    else:
        print(f"Token {token_id} not found or already expired.", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="oseye-server enrollment")
    sub = parser.add_subparsers(dest="subcmd", required=True)

    p_create = sub.add_parser("token create", help="Create an enrollment token")
    p_create.add_argument(
        "--valid-hours", type=int, default=24, metavar="N",
        help="Token validity in hours (default: 24, max: 8760)",
    )

    sub.add_parser("token list", help="List active enrollment tokens")

    p_revoke = sub.add_parser("token revoke", help="Revoke a token by ID")
    p_revoke.add_argument("token_id", help="Token ID (from 'token list')")

    # Handle 'token create/list/revoke' as two-word subcommands
    if argv and len(argv) >= 2 and argv[0] == "token":
        args = parser.parse_args([f"token {argv[1]}"] + list(argv[2:]))
    else:
        args = parser.parse_args(argv)

    if args.subcmd == "token create":
        if args.valid_hours < 1 or args.valid_hours > 8760:
            print("--valid-hours must be between 1 and 8760.", file=sys.stderr)
            sys.exit(1)
        asyncio.run(_create(args.valid_hours))
    elif args.subcmd == "token list":
        asyncio.run(_list())
    elif args.subcmd == "token revoke":
        asyncio.run(_revoke(args.token_id))
