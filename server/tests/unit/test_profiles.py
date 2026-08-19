"""Tests for specialized machine profiles."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

PROFILES_DIR = Path(__file__).parent.parent.parent / "oseye" / "policy" / "profiles"
REQUIRED_PROFILES = [
    "workstation",
    "server",
    "minimal",
    "stealth",
    "compliance",
    "investigation",
    "webserver",
    "database",
    "dns",
    "mail",
    "laptop",
    "desktop",
]
NEW_PROFILES = ["webserver", "database", "dns", "mail", "laptop", "desktop"]
REQUIRED_FIELDS = ["name", "description", "version", "platforms", "collectors", "min_severity"]


@pytest.mark.parametrize("profile_name", REQUIRED_PROFILES)
def test_profile_yaml_exists(profile_name: str) -> None:
    """Each required profile has a YAML file."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    assert path.exists(), f"Profile {profile_name}.yaml not found in {PROFILES_DIR}"


@pytest.mark.parametrize("profile_name", REQUIRED_PROFILES)
def test_profile_yaml_valid(profile_name: str) -> None:
    """Each profile YAML is valid and parseable."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    assert data is not None
    assert isinstance(data, dict)


@pytest.mark.parametrize("profile_name", REQUIRED_PROFILES)
def test_profile_has_required_fields(profile_name: str) -> None:
    """Each profile has the required top-level fields."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    for field in REQUIRED_FIELDS:
        assert field in data, f"Profile {profile_name} missing field '{field}'"


@pytest.mark.parametrize("profile_name", REQUIRED_PROFILES)
def test_profile_name_matches_filename(profile_name: str) -> None:
    """Profile 'name' field matches its filename."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    assert data["name"] == profile_name


@pytest.mark.parametrize("profile_name", REQUIRED_PROFILES)
def test_profile_has_ignore_processes(profile_name: str) -> None:
    """Each profile has ignore_processes containing oseye-agent."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    ignore = data.get("ignore_processes", [])
    assert isinstance(ignore, list)
    assert "oseye-agent" in ignore, f"Profile {profile_name} must ignore 'oseye-agent'"
    assert "oseye-config" in ignore, f"Profile {profile_name} must ignore 'oseye-config'"


@pytest.mark.parametrize("profile_name", REQUIRED_PROFILES)
def test_profile_has_ignore_paths_prefix(profile_name: str) -> None:
    """Each profile has ignore_paths_prefix containing /etc/oseye/."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    prefixes = data.get("ignore_paths_prefix", [])
    assert isinstance(prefixes, list)
    assert "/etc/oseye/" in prefixes, f"Profile {profile_name} must exclude /etc/oseye/"


@pytest.mark.parametrize("profile_name", NEW_PROFILES)
def test_new_profiles_are_linux_only(profile_name: str) -> None:
    """New server/workstation profiles target linux (laptops/desktops may have more)."""
    path = PROFILES_DIR / f"{profile_name}.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    platforms = data.get("platforms", [])
    assert "linux" in platforms


def test_profile_autonomy_covers_all_new_profiles() -> None:
    """PROFILE_AUTONOMY in rule_signer covers all new profiles."""
    import os
    os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")
    from oseye.policy.rule_signer import PROFILE_AUTONOMY
    for name in NEW_PROFILES:
        assert name in PROFILE_AUTONOMY, f"PROFILE_AUTONOMY missing entry for '{name}'"


def test_policy_engine_loads_new_profiles() -> None:
    """PolicyEngine can import without error after adding new profiles."""
    import os
    os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")
    from oseye.policy.engine import PolicyEngine  # noqa: F401
