"""Rule signer — builds and signs RuleSet JSON blobs for the agent's local rule engine."""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

import yaml

from oseye.core.observability import get_logger

_logger = get_logger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[3]  # server/oseye/policy/ → repo root
_AGENT_RULES_DIR = _REPO_ROOT / "rules" / "agent"

# Autonomy level per profile name.
PROFILE_AUTONOMY: dict[str, str] = {
    "investigation": "always_act",
    "compliance": "critical_high",
    "workstation": "critical_only",
    "desktop": "critical_only",
    "laptop": "critical_only",
    "server": "critical_only",
    "webserver": "critical_only",
    "database": "critical_only",
    "fileserver": "critical_only",
    "dns": "critical_only",
    "mail": "critical_only",
    "container": "critical_only",
    "minimal": "log_only",
    "stealth": "log_only",
}

# ResourceBudget per profile name; keys match Go's ResourceBudget JSON fields.
_BUDGET_INVESTIGATION = {
    "max_rules": 100,
    "cpu_budget_pct": 2.0,
    "buffer_mb": 100,
    "batch_size": 1000,
    "budget_per_event_micros": 200,
    "max_correlation_groups": 2000,
    "max_correlation_events": 20000,
}
_BUDGET_MINIMAL = {
    "max_rules": 20,
    "cpu_budget_pct": 0.5,
    "buffer_mb": 20,
    "batch_size": 500,
    "budget_per_event_micros": 50,
    "max_correlation_groups": 500,
    "max_correlation_events": 5000,
}
_BUDGET_DEFAULT = {
    "max_rules": 50,
    "cpu_budget_pct": 1.0,
    "buffer_mb": 50,
    "batch_size": 1000,
    "budget_per_event_micros": 100,
    "max_correlation_groups": 1000,
    "max_correlation_events": 10000,
}
PROFILE_BUDGET: dict[str, dict[str, Any]] = {
    "investigation": _BUDGET_INVESTIGATION,
    "minimal": _BUDGET_MINIMAL,
    "stealth": _BUDGET_MINIMAL,
}


def budget_for_profile(profile_name: str) -> dict[str, Any]:
    """Return the ResourceBudget dict for a given profile name."""
    return PROFILE_BUDGET.get(profile_name, _BUDGET_DEFAULT)


class RuleSigner:
    """Loads agent-format rules from ``rules/agent/``, builds, and optionally signs a RuleSet.

    If no signing key is configured the RuleSet is pushed unsigned (signature=null).
    The agent accepts unsigned rule sets when ``NewStore(dir, nil)`` is used (current default).

    Canonical-form warning: Go's store.verifySignature() re-marshals the Rule structs
    after unmarshal to compute the canonical signing bytes. Python's json.dumps output
    and Go's json.Marshal output for the same logical data may differ (field ordering,
    zero-value emission). Until the Go verifier is changed to verify against the raw
    received RuleSet bytes, do NOT set OSEYE_RULE_SIGNING_KEY_PATH — agents initialized
    with nil verifyKey (current default) accept unsigned rule sets without issue.
    """

    def __init__(self, private_key_path: str | None = None) -> None:
        self._private_key: Any | None = None
        if private_key_path:
            self._load_key(private_key_path)

    def _load_key(self, path: str) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            data = Path(path).read_bytes()
            key = load_pem_private_key(data, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"Expected Ed25519 private key, got {type(key).__name__}")
            self._private_key = key
            _logger.info("rule_signer.key_loaded", path=path)
            _logger.warning(
                "rule_signer.signing_key_loaded_verification_disabled",
                msg=(
                    "Rule signing key loaded, but Go agent verifier re-marshals Rule structs "
                    "after unmarshal — Python canonical JSON and Go canonical JSON differ. "
                    "Signatures will be rejected by agents with verifyKey != nil. "
                    "Leave OSEYE_RULE_SIGNING_KEY_PATH unset until the Go verifier is updated "
                    "to verify against raw received bytes (tracked as future work)."
                ),
            )
        except ImportError:
            _logger.warning(
                "rule_signer.no_cryptography",
                msg="pip install cryptography to enable rule signing",
            )
        except TypeError as exc:
            # Password-protected key — load_pem_private_key raises TypeError when
            # password=None is passed to an encrypted key. This is fatal at startup.
            raise RuntimeError(
                f"Rule signing key at {path!r} is password-protected. "
                "Decrypt it first or provide the passphrase via the config."
            ) from exc
        except Exception as exc:  # noqa: BLE001
            # File not found, permission denied, invalid PEM, etc. — log and
            # continue without signing (rules pushed unsigned).
            _logger.error("rule_signer.key_load_failed", path=path, error=str(exc))

    def build_ruleset(self, version: int | None = None) -> bytes:
        """Return JSON bytes matching Go's ``localrules.RuleSet`` struct.

        Embed the result as ``json.loads(signer.build_ruleset())`` in the
        ``rule_set`` key of the policy push payload.
        """
        rules = self._load_rules()
        v = version if version is not None else int(time.time())

        canonical = json.dumps(
            {"version": v, "rules": rules}, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

        signature: str | None = None
        if self._private_key is not None:
            sig_bytes: bytes = self._private_key.sign(canonical)
            signature = base64.b64encode(sig_bytes).decode("ascii")

        ruleset: dict[str, Any] = {"version": v, "rules": rules, "signature": signature}
        out = json.dumps(ruleset, separators=(",", ":")).encode("utf-8")
        _logger.info(
            "rule_signer.ruleset_built",
            version=v,
            rules=len(rules),
            signed=signature is not None,
        )
        return out

    def _load_rules(self) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        if not _AGENT_RULES_DIR.exists():
            _logger.warning("rule_signer.no_rules_dir", path=str(_AGENT_RULES_DIR))
            return rules
        paths = sorted(_AGENT_RULES_DIR.glob("*.yaml")) + sorted(_AGENT_RULES_DIR.glob("*.yml"))
        for path in paths:
            try:
                raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    rules.extend(raw)
                elif isinstance(raw, dict):
                    rules.append(raw)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("rule_signer.rule_load_failed", path=str(path), error=str(exc))
        return rules
