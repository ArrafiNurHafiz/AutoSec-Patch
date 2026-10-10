from typing import Optional
from autosec.types import ModelTier, SecurityFinding


class ModelMeshRouter:
    """Intelligently routes subagent requests to the optimal NVIDIA Nemotron model."""

    def __init__(
        self,
        default_nano: Optional[str] = None,
        default_super: Optional[str] = None,
        default_ultra: Optional[str] = None,
    ):
        self.nano_model = default_nano or ModelTier.NANO.value
        self.super_model = default_super or ModelTier.SUPER.value
        self.ultra_model = default_ultra or ModelTier.ULTRA.value
        self.token_savings_ratio = 0.0

    def route_agent_task(
        self, agent_role: str, finding: Optional[SecurityFinding] = None
    ) -> str:
        role = agent_role.lower()
        if "triage" in role or "filter" in role or "ast" in role:
            return self.nano_model
        elif "red" in role or "exploit" in role or "adversary" in role:
            return self.ultra_model
        elif "blue" in role or "patch" in role or "remediate" in role:
            # If critical blast radius, route to Ultra, otherwise Super
            if finding and finding.severity == "CRITICAL":
                return self.ultra_model
            return self.super_model
        elif "verifier" in role or "formal" in role:
            return self.ultra_model
        return self.super_model
