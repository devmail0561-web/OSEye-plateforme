"""Tests for baseline_apps in surveillance profiles and SurveillanceProfile schema."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")

from oseye.core.schema import SurveillanceProfile  # noqa: E402

PROFILES_DIR = Path(__file__).parent.parent.parent / "oseye" / "policy" / "profiles"

ROLE_PROFILES = [
    "workstation",
    "server",
    "webserver",
    "database",
    "dns",
    "mail",
    "laptop",
    "desktop",
]

ALL_PROFILES = ROLE_PROFILES + ["minimal", "stealth", "compliance", "investigation"]


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------


def test_surveillance_profile_has_baseline_fields() -> None:
    """SurveillanceProfile accepts baseline_apps, baseline_net_dests, baseline_users."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    p = SurveillanceProfile(
        name="test",
        baseline_apps=["systemd", "sshd"],
        baseline_net_dests=["8.8.8.8:53"],
        baseline_users=["root", "www-data"],
        created_at=now,
        updated_at=now,
    )
    assert "systemd" in p.baseline_apps
    assert "sshd" in p.baseline_apps
    assert "8.8.8.8:53" in p.baseline_net_dests
    assert "root" in p.baseline_users


def test_surveillance_profile_baseline_defaults_empty() -> None:
    """SurveillanceProfile baseline fields default to empty lists."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    p = SurveillanceProfile(name="test", created_at=now, updated_at=now)
    assert p.baseline_apps == []
    assert p.baseline_net_dests == []
    assert p.baseline_users == []


# ---------------------------------------------------------------------------
# YAML profile tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_profile_yaml_exists(profile_name: str) -> None:
    """Each profile has a YAML file."""
    assert (PROFILES_DIR / f"{profile_name}.yaml").exists()


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_profile_yaml_parseable(profile_name: str) -> None:
    """Each profile YAML is valid YAML."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)


@pytest.mark.parametrize("profile_name", ROLE_PROFILES)
def test_role_profile_has_baseline_apps(profile_name: str) -> None:
    """Role profiles have a non-empty baseline_apps list."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    data = yaml.safe_load(path.read_text())
    apps = data.get("baseline_apps", [])
    assert isinstance(apps, list), f"{profile_name}: baseline_apps must be a list"
    assert len(apps) > 0, f"{profile_name}: baseline_apps must not be empty"


@pytest.mark.parametrize("profile_name", ROLE_PROFILES)
def test_role_profile_baseline_apps_contains_systemd(profile_name: str) -> None:
    """Role profiles all list systemd as a baseline process."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    data = yaml.safe_load(path.read_text())
    assert "systemd" in data.get("baseline_apps", [])


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_profile_loads_via_pydantic(profile_name: str) -> None:
    """Each profile loads cleanly through SurveillanceProfile.model_validate."""
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    path = PROFILES_DIR / f"{profile_name}.yaml"
    raw = yaml.safe_load(path.read_text())
    raw.setdefault("created_at", now)
    raw.setdefault("updated_at", now)
    profile = SurveillanceProfile.model_validate(raw)
    assert profile.name == profile_name
    assert isinstance(profile.baseline_apps, list)
    assert isinstance(profile.baseline_net_dests, list)
    assert isinstance(profile.baseline_users, list)
