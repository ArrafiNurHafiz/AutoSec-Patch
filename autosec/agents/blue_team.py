import re
from typing import Optional, List
from autosec.types import SecurityFinding, SwarmAgentResult, ModelTier
from autosec.client import NebiusNemotronClient

BLUE_SYSTEM_PROMPT = """You are a Principal Security Architect and Autonomous Blue Team Engineer.
Your goal: Synthesize zero-side-effect security patches constrained strictly to the AST scope.
Preserve 100% of business logic, invariant contracts, and type signatures.
Output your unified diff enclosed strictly in ```patch ... ```.
"""

class BlueTeamAgent:
    """Defense agent that synthesizes minimal invariant-preserving patches using Nemotron-70B/Ultra."""

    def __init__(self, client: Optional[NebiusNemotronClient] = None):
        self.client = client or NebiusNemotronClient(model=ModelTier.SUPER.value)

    def synthesize_patch(
        self,
        finding: SecurityFinding,
        source_code: str,
        blast_radius: List[str],
        adversarial_feedback: Optional[str] = None
    ) -> SwarmAgentResult:
        feedback_section = f"\nAdversarial Verifier Feedback:\n{adversarial_feedback}" if adversarial_feedback else ""
        prompt = f"""Target File: {finding.file_path}
Vulnerability: {finding.rule_id} ({finding.cwe or 'CWE-Unknown'})
Target Scope: Lines {finding.start_line}-{finding.end_line}
Impacted Call-Graph Functions (Blast Radius): {', '.join(blast_radius)}
{feedback_section}

--- SOURCE CODE ---
{source_code}
--- END SOURCE CODE ---

Produce the minimal patch diff fixing the vulnerability while preserving all caller contracts.
"""
        messages = [
            {"role": "system", "content": BLUE_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw_output = self.client.chat_completion(messages)
        diff = self._extract_diff(raw_output)

        return SwarmAgentResult(
            agent_name="BlueTeam-PatchSynthesizer",
            model_used=self.client.model,
            status="SUCCESS",
            output=diff,
            token_usage={"prompt": len(prompt) // 4, "completion": len(diff) // 4},
        )

    def _extract_diff(self, text: str) -> str:
        match = re.search(r"```(?:patch|diff)?\s*\n(.*?)\n```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()
