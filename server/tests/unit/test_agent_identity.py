"""Tests for agent identity exposure (P4) and auto-exclusion config (P6)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")

import yaml  # noqa: E402

from oseye.core.schema import SurveillanceProfile  # noqa: E402

_PROFILES_DIR = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "oseye", "policy", "profiles",
)

_PROFILE_FILES = [
    "workstation.yaml",
    "server.yaml",
    "minimal.yaml",
    "stealth.yaml",
    "compliance.yaml",
    "investigation.yaml",
]


# ---------------------------------------------------------------------------
# P6 — Auto-exclusion: all profiles must declare oseye-agent in ignore_processes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename", _PROFILE_FILES)
def test_profile_ignores_oseye_agent(filename: str) -> None:
    """Every profile must exclude oseye-agent from surveillance."""
    path = os.path.join(_PROFILES_DIR, filename)
    with open(path) as f:
        data = yaml.safe_load(f)
    procs = data.get("ignore_processes", [])
    assert "oseye-agent" in procs, f"{filename} is missing oseye-agent in ignore_processes"


@pytest.mark.parametrize("filename", _PROFILE_FILES)
def test_profile_ignores_oseye_config(filename: str) -> None:
    """Every profile must exclude oseye-config from surveillance."""
    path = os.path.join(_PROFILES_DIR, filename)
    with open(path) as f:
        data = yaml.safe_load(f)
    procs = data.get("ignore_processes", [])
    assert "oseye-config" in procs, f"{filename} is missing oseye-config in ignore_processes"


@pytest.mark.parametrize("filename", _PROFILE_FILES)
def test_profile_ignores_oseye_paths(filename: str) -> None:
    """Every profile must exclude /etc/oseye/ paths from surveillance."""
    path = os.path.join(_PROFILES_DIR, filename)
    with open(path) as f:
        data = yaml.safe_load(f)
    prefixes = data.get("ignore_paths_prefix", [])
    assert "/etc/oseye/" in prefixes, f"{filename} is missing /etc/oseye/ in ignore_paths_prefix"


# ---------------------------------------------------------------------------
# P6 — SurveillanceProfile schema supports ignore fields
# ---------------------------------------------------------------------------


def test_surveillance_profile_has_ignore_processes_field() -> None:
    """SurveillanceProfile supports ignore_processes field."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    profile = SurveillanceProfile(
        name="test",
        description="test profile",
        created_at=now,
        updated_at=now,
        ignore_processes=["oseye-agent", "oseye-config"],
        ignore_paths_prefix=["/etc/oseye/"],
    )
    assert "oseye-agent" in profile.ignore_processes
    assert "oseye-config" in profile.ignore_processes
    assert "/etc/oseye/" in profile.ignore_paths_prefix


def test_surveillance_profile_default_empty_ignore_lists() -> None:
    """SurveillanceProfile defaults to empty ignore lists when not specified."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    profile = SurveillanceProfile(name="test", description="x", created_at=now, updated_at=now)
    assert isinstance(profile.ignore_processes, list)
    assert len(profile.ignore_processes) == 0
    assert isinstance(profile.ignore_paths_prefix, list)
    assert len(profile.ignore_paths_prefix) == 0


# ---------------------------------------------------------------------------
# P4 — agents router exposes agent_id
# ---------------------------------------------------------------------------


def test_row_to_dict_exposes_agent_id() -> None:
    """_row_to_dict must return an agent_id key."""
    from unittest.mock import MagicMock
    from datetime import UTC, datetime

    from oseye.api.routers.agents import _row_to_dict

    row = MagicMock()
    row.cn = "virus-one"
    row.online = True
    row.first_seen = datetime.now(UTC)
    row.last_seen = datetime.now(UTC)
    row.version = "0.3.0"
    row.active_profile = "workstation"
    row.ip_address = "127.0.0.1"
    row.platform = "linux"

    result = _row_to_dict(row)
    assert "agent_id" in result
    assert result["agent_id"] == "virus-one"
