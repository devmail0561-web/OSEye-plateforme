"""Tests for the RuleSigner — rule loading, RuleSet building, signing."""
from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from oseye.policy.rule_signer import (
    PROFILE_AUTONOMY,
    RuleSigner,
    budget_for_profile,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIMPLE_RULE = {
    "id": "test_rule",
    "name": "Test rule",
    "version": 1,
    "severity": "critical",
    "autonomy": "critical_only",
    "threshold": 0.7,
    "response": "log",
    "confidence": 0.9,
    "conditions": [
        {"field": "path", "op": "eq", "value": "/etc/shadow", "weight": 1.0}
    ],
}

_CORR_RULE = {
    "id": "test_corr",
    "name": "Test correlation",
    "version": 1,
    "severity": "high",
    "autonomy": "log_only",
    "threshold": 0.7,
    "response": "log",
    "confidence": 0.8,
    "correlation": {
        "event_type": "",
        "group_by": "_source",
        "count_threshold": 20,
        "timeframe_seconds": 30,
        "conditions": {"event": "new", "_source": "netlink"},
    },
}


def _write_rules_file(tmpdir: Path, rules: list[dict]) -> Path:
    path = tmpdir / "core.yaml"
    path.write_text(yaml.dump(rules), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# budget_for_profile
# ---------------------------------------------------------------------------


def test_budget_investigation():
    b = budget_for_profile("investigation")
    assert b["max_rules"] == 100
    assert b["budget_per_event_micros"] == 200


def test_budget_default():
    b = budget_for_profile("workstation")
    assert b["max_rules"] == 50
    assert b["budget_per_event_micros"] == 100


def test_budget_minimal():
    b = budget_for_profile("minimal")
    assert b["max_rules"] == 20


# ---------------------------------------------------------------------------
# PROFILE_AUTONOMY
# ---------------------------------------------------------------------------


def test_profile_autonomy_investigation():
    assert PROFILE_AUTONOMY["investigation"] == "always_act"


def test_profile_autonomy_workstation():
    assert PROFILE_AUTONOMY["workstation"] == "critical_only"


def test_profile_autonomy_stealth():
    assert PROFILE_AUTONOMY["stealth"] == "log_only"


# ---------------------------------------------------------------------------
# RuleSigner.build_ruleset — unsigned
# ---------------------------------------------------------------------------


def test_build_ruleset_empty_when_no_dir():
    signer = RuleSigner()
    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", Path("/nonexistent/rules/agent")):
        data = json.loads(signer.build_ruleset())
    assert data["rules"] == []
    assert data["signature"] is None


def test_build_ruleset_loads_rules(tmp_path):
    rules_dir = tmp_path / "rules" / "agent"
    rules_dir.mkdir(parents=True)
    _write_rules_file(rules_dir, [_SIMPLE_RULE, _CORR_RULE])

    signer = RuleSigner()
    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", rules_dir):
        data = json.loads(signer.build_ruleset())

    assert len(data["rules"]) == 2
    assert data["rules"][0]["id"] == "test_rule"
    assert data["rules"][1]["id"] == "test_corr"
    assert data["signature"] is None


def test_build_ruleset_version_monotonic(tmp_path):
    rules_dir = tmp_path / "rules" / "agent"
    rules_dir.mkdir(parents=True)
    _write_rules_file(rules_dir, [_SIMPLE_RULE])

    signer = RuleSigner()
    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", rules_dir):
        d1 = json.loads(signer.build_ruleset(version=100))
        d2 = json.loads(signer.build_ruleset(version=200))

    assert d1["version"] == 100
    assert d2["version"] == 200


def test_build_ruleset_auto_version(tmp_path):
    rules_dir = tmp_path / "rules" / "agent"
    rules_dir.mkdir(parents=True)
    _write_rules_file(rules_dir, [_SIMPLE_RULE])

    signer = RuleSigner()
    import time
    before = int(time.time())
    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", rules_dir):
        data = json.loads(signer.build_ruleset())
    after = int(time.time())

    assert before <= data["version"] <= after + 1


def test_build_ruleset_bad_rule_file_skipped(tmp_path):
    rules_dir = tmp_path / "rules" / "agent"
    rules_dir.mkdir(parents=True)
    # Valid file
    _write_rules_file(rules_dir, [_SIMPLE_RULE])
    # Invalid YAML file
    (rules_dir / "broken.yaml").write_text("{{{{ bad yaml", encoding="utf-8")

    signer = RuleSigner()
    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", rules_dir):
        data = json.loads(signer.build_ruleset())

    # Only the valid rule loaded
    assert len(data["rules"]) == 1


# ---------------------------------------------------------------------------
# RuleSigner.build_ruleset — with signing key
# ---------------------------------------------------------------------------


def test_build_ruleset_signed(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    rules_dir = tmp_path / "rules" / "agent"
    rules_dir.mkdir(parents=True)
    _write_rules_file(rules_dir, [_SIMPLE_RULE])

    # Generate a throwaway key pair
    private_key = Ed25519PrivateKey.generate()
    key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    key_file = tmp_path / "signing.key"
    key_file.write_bytes(key_pem)

    signer = RuleSigner(private_key_path=str(key_file))
    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", rules_dir):
        data = json.loads(signer.build_ruleset(version=42))

    assert data["signature"] is not None
    sig_bytes = base64.b64decode(data["signature"])
    assert len(sig_bytes) == 64  # Ed25519 signature is always 64 bytes


def test_build_ruleset_bad_key_falls_back_to_unsigned(tmp_path):
    rules_dir = tmp_path / "rules" / "agent"
    rules_dir.mkdir(parents=True)
    _write_rules_file(rules_dir, [_SIMPLE_RULE])

    signer = RuleSigner(private_key_path="/nonexistent/key.pem")
    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", rules_dir):
        data = json.loads(signer.build_ruleset())

    # Falls back gracefully — unsigned
    assert data["signature"] is None
    assert len(data["rules"]) == 1


# ---------------------------------------------------------------------------
# Integration with PolicyEngine
# ---------------------------------------------------------------------------


def test_policy_engine_injects_ruleset(tmp_path):
    """push_to_agent must embed rule_set, autonomy, and budget in the payload."""
    import asyncio

    from oseye.bus.memory_bus import InMemoryEventBus
    from oseye.core.schema import SurveillanceProfile
    from oseye.policy.engine import PolicyEngine

    rules_dir = tmp_path / "rules" / "agent"
    rules_dir.mkdir(parents=True)
    _write_rules_file(rules_dir, [_SIMPLE_RULE])

    bus = InMemoryEventBus()
    signer = RuleSigner()

    engine = PolicyEngine(bus=bus, rule_signer=signer)

    from datetime import UTC, datetime
    now = datetime.now(UTC)
    profile = SurveillanceProfile(
        name="workstation",
        description="test",
        version=1,
        collectors={},
        created_at=now,
        updated_at=now,
    )
    engine._profiles["workstation"] = profile

    received: list[bytes] = []

    async def run():
        sub = await bus.subscribe("policy:push:test-agent-1")
        push_task = asyncio.ensure_future(
            engine.push_to_agent("test-agent-1", "workstation")
        )
        msg = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
        received.append(msg)
        await push_task

    with patch("oseye.policy.rule_signer._AGENT_RULES_DIR", rules_dir):
        asyncio.run(run())

    assert received
    data = json.loads(received[0])
    assert "autonomy" in data
    assert data["autonomy"] == "critical_only"
    assert "budget" in data
    assert data["budget"]["max_rules"] == 50
    assert "rule_set" in data
    assert len(data["rule_set"]["rules"]) == 1
