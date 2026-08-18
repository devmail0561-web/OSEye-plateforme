"""Policy Engine — loads built-in YAML profiles and pushes them to agents via bus."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from oseye.bus.interface import EventBus
from oseye.core.observability import get_logger
from oseye.core.schema import SurveillanceProfile
from oseye.policy.rule_signer import PROFILE_AUTONOMY, budget_for_profile

if TYPE_CHECKING:
    from oseye.policy.rule_signer import RuleSigner

_PROFILES_DIR = Path(__file__).parent / "profiles"

_logger = get_logger(__name__)


class PolicyEngine:
    """Loads built-in YAML profiles, validates them, pushes to agents via bus.

    When a ``RuleSigner`` is provided, every push includes a signed ``rule_set``
    blob and the agent-facing autonomy/budget fields required by the local rule engine.
    """

    def __init__(
        self,
        bus: EventBus,
        default_profile: str = "workstation",
        rule_signer: RuleSigner | None = None,
    ) -> None:
        self._bus = bus
        self._profiles: dict[str, SurveillanceProfile] = {}
        self._known_agents: set[str] = set()  # agent CNs (TLS certificate CN)
        self._default_profile = default_profile
        self._rule_signer = rule_signer

    # ------------------------------------------------------------------
    # Profile loading
    # ------------------------------------------------------------------

    async def load_profiles(self) -> None:
        """Load all YAML files from policy/profiles/ dir into memory.

        Files that fail Pydantic validation are logged as warnings and skipped.
        """
        loaded = 0
        skipped = 0
        now = datetime.now(UTC)

        for path in sorted(_PROFILES_DIR.glob("*.yaml")) + sorted(
            _PROFILES_DIR.glob("*.yml")
        ):
            try:
                raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
                raw.setdefault("created_at", now)
                raw.setdefault("updated_at", now)
                profile = SurveillanceProfile.model_validate(raw)
                self._profiles[profile.name] = profile
                loaded += 1
                _logger.info("policy.profile.loaded", name=profile.name, path=str(path))
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                _logger.warning("policy.profile.skipped", path=str(path), error=str(exc))

        _logger.info("policy.profiles.ready", loaded=loaded, skipped=skipped)

    # ------------------------------------------------------------------
    # Profile access
    # ------------------------------------------------------------------

    def get_profile(self, name: str) -> SurveillanceProfile | None:
        return self._profiles.get(name)

    def list_profiles(self) -> list[SurveillanceProfile]:
        return sorted(self._profiles.values(), key=lambda p: p.name)

    def seed_known_agents(self, cns: list[str]) -> None:
        """Pre-populate the known-agents set from persisted CNs."""
        self._known_agents.update(cns)

    def unregister_agent(self, cn: str) -> None:
        """POL-01: Remove *cn* from _known_agents.

        Call this from the gRPC service when an agent's stream disconnects so
        that _known_agents does not grow indefinitely on long-running servers.
        """
        self._known_agents.discard(cn)
        _logger.info("policy.agent_unregistered", cn=cn)

    async def push_default_to_agent(self, cn: str) -> None:
        """Push the default profile to a newly connected agent."""
        if self._default_profile in self._profiles:
            await self.push_to_agent(cn, self._default_profile)
        else:
            _logger.error(
                "policy.default_profile_not_found",
                default=self._default_profile,
                loaded=[p.name for p in self.list_profiles()],
            )
            raise RuntimeError(
                f"Default surveillance profile {self._default_profile!r} is not loaded. "
                "Ensure OSEYE_DEFAULT_SURVEILLANCE_PROFILE matches a profile on disk."
            )

    # ------------------------------------------------------------------
    # Push to agents
    # ------------------------------------------------------------------

    async def push_to_agent(self, cn: str, profile_name: str) -> None:
        """Publish profile JSON to bus topic ``policy:push:{cn}``.

        The payload includes the standard SurveillanceProfile fields plus:
        - ``autonomy``  — autonomy level for the agent's local rule engine
        - ``budget``    — resource budget (max_rules, budget_per_event_micros, …)
        - ``role``      — profile name used as role hint
        - ``rule_set``  — signed RuleSet JSON object (only when rule_signer is set)

        Raises ``KeyError`` if *profile_name* is not loaded.
        """
        profile = self._profiles.get(profile_name)
        if profile is None:
            raise KeyError(f"Unknown profile: {profile_name!r}")

        payload_data: dict[str, Any] = profile.model_dump(mode="json")

        # Inject agent-facing fields consumed by hostprofile.ProfileStore.
        payload_data["autonomy"] = PROFILE_AUTONOMY.get(profile_name, "critical_only")
        payload_data["budget"] = budget_for_profile(profile_name)
        payload_data["role"] = profile_name

        # Inject signed RuleSet when a signer is configured.
        if self._rule_signer is not None:
            try:
                ruleset_bytes = self._rule_signer.build_ruleset()
                payload_data["rule_set"] = json.loads(ruleset_bytes)
            except Exception as exc:  # noqa: BLE001
                _logger.error("policy.ruleset_build_failed", error=str(exc))
                return  # do not push a profile without its rule_set

        topic = f"policy:push:{cn}"
        payload: bytes = json.dumps(payload_data).encode("utf-8")
        await self._bus.publish(topic, payload)
        self._known_agents.add(cn)
        _logger.info(
            "policy.pushed",
            cn=cn,
            profile=profile_name,
            topic=topic,
            rule_set_injected=self._rule_signer is not None,
        )

    async def push_to_all(self, profile_name: str) -> dict[str, str]:
        """Broadcast a profile to all registered agent IDs.

        POL-01: each agent push is isolated — a failure for one agent does not
        stop delivery to the others.  Returns a dict mapping agent_id → "ok"
        or "error: <message>".

        Raises ``KeyError`` if *profile_name* is not loaded.
        """
        if profile_name not in self._profiles:
            raise KeyError(f"Unknown profile: {profile_name!r}")

        results: dict[str, str] = {}
        for cn in list(self._known_agents):
            try:
                await self.push_to_agent(cn, profile_name)
                results[cn] = "ok"
            except Exception as exc:
                _logger.error("push_to_agent_failed", cn=cn, error=str(exc))
                results[cn] = f"error: {exc}"

        _logger.info(
            "policy.broadcast",
            profile=profile_name,
            agent_count=len(self._known_agents),
            ok=sum(1 for v in results.values() if v == "ok"),
            errors=sum(1 for v in results.values() if v.startswith("error:")),
        )
        return results
