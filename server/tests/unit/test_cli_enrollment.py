"""Unit tests for oseye-server enrollment token create/list/revoke."""

from __future__ import annotations

import os
import pytest

# Provide HMAC key before importing cmd_enrollment (avoids sys.exit in _get_hmac_key)
os.environ.setdefault("OSEYE_CHECKPOINT_HMAC_KEY", "a" * 64)
# OSEYE_DB_URL is set per-test via monkeypatch to avoid polluting the suite.

from unittest.mock import AsyncMock, patch, MagicMock

from oseye.cli.cmd_enrollment import _create, _list, _revoke


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_repo(
    token_id="abc-123",
    tokens=None,
    revoke_ok=True,
):
    repo = AsyncMock()
    repo.create.return_value = token_id
    repo.list_active.return_value = tokens or [
        {
            "token_id": "abc-123",
            "created_by": "cli",
            "expires_at": "2099-01-01T00:00:00+00:00",
        }
    ]
    repo.revoke.return_value = revoke_ok
    return repo


def _patch_repo(repo):
    # SQLEnrollmentTokenRepository is imported inside the async functions,
    # so patch it at the source module level.
    return patch(
        "oseye.storage.repositories.enrollment_tokens.SQLEnrollmentTokenRepository",
        return_value=repo,
    )


def _patch_sf():
    return patch("oseye.cli.cmd_enrollment._make_session_factory", return_value=MagicMock())


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_default_ttl(capsys, monkeypatch):
    monkeypatch.setenv("OSEYE_DB_URL", "sqlite+aiosqlite:///:memory:")
    repo = _make_repo()
    with _patch_sf(), _patch_repo(repo):
        await _create(24)

    repo.create.assert_awaited_once()
    _, kwargs = repo.create.call_args
    # created_by should be "cli"
    assert repo.create.call_args[1].get("created_by") == "cli" or \
           repo.create.call_args[0][2] == "cli"

    out = capsys.readouterr().out
    assert "abc-123" in out
    assert "24h" in out
    assert "oseye-config enroll" in out


@pytest.mark.asyncio
async def test_create_custom_ttl(capsys, monkeypatch):
    monkeypatch.setenv("OSEYE_DB_URL", "sqlite+aiosqlite:///:memory:")
    repo = _make_repo()
    with _patch_sf(), _patch_repo(repo):
        await _create(48)

    out = capsys.readouterr().out
    assert "48h" in out


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_with_tokens(capsys, monkeypatch):
    monkeypatch.setenv("OSEYE_DB_URL", "sqlite+aiosqlite:///:memory:")
    repo = _make_repo()
    with _patch_sf(), _patch_repo(repo):
        await _list()

    out = capsys.readouterr().out
    assert "abc-123" in out
    assert "cli" in out


@pytest.mark.asyncio
async def test_list_empty(capsys, monkeypatch):
    monkeypatch.setenv("OSEYE_DB_URL", "sqlite+aiosqlite:///:memory:")
    repo = AsyncMock()
    repo.list_active.return_value = []
    with _patch_sf(), _patch_repo(repo):
        await _list()

    out = capsys.readouterr().out
    assert "No active" in out


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoke_success(capsys, monkeypatch):
    monkeypatch.setenv("OSEYE_DB_URL", "sqlite+aiosqlite:///:memory:")
    repo = _make_repo(revoke_ok=True)
    with _patch_sf(), _patch_repo(repo):
        await _revoke("abc-123")

    repo.revoke.assert_awaited_once_with("abc-123")
    out = capsys.readouterr().out
    assert "revoked" in out.lower()


@pytest.mark.asyncio
async def test_revoke_not_found(capsys, monkeypatch):
    monkeypatch.setenv("OSEYE_DB_URL", "sqlite+aiosqlite:///:memory:")
    repo = _make_repo(revoke_ok=False)
    with _patch_sf(), _patch_repo(repo):
        with pytest.raises(SystemExit) as exc:
            await _revoke("nonexistent")

    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# CLI validation
# ---------------------------------------------------------------------------

def test_valid_hours_range():
    """--valid-hours must be 1..8760."""
    from oseye.cli.cmd_enrollment import run
    import sys

    for bad in [0, 8761]:
        with patch("sys.argv", ["oseye-server", "enrollment", "token", "create",
                                "--valid-hours", str(bad)]):
            with pytest.raises(SystemExit) as exc:
                run(["token", "create", "--valid-hours", str(bad)])
            assert exc.value.code == 1


def test_env_file_parser(tmp_path):
    """_load_env_file parses KEY=VALUE correctly."""
    from oseye.cli.cmd_enrollment import _load_env_file

    f = tmp_path / "test.env"
    f.write_text("# comment\nFOO=bar\nBAZ=qux\n\n")
    result = _load_env_file(f)
    assert result == {"FOO": "bar", "BAZ": "qux"}


def test_env_file_missing(tmp_path):
    from oseye.cli.cmd_enrollment import _load_env_file
    assert _load_env_file(tmp_path / "nonexistent.env") == {}
