import re
from typing import Optional, List
from autosec.types import SecurityFinding, SwarmAgentResult, ModelTier
from autosec.client import NebiusNemotronClient
from autosec.ast_patcher import AstSemanticPatcher

BLUE_SYSTEM_PROMPT = """You are a Principal Security Architect and Autonomous Blue Team Engineer.
Your goal: Given an identified vulnerability and the original source code, synthesize a PRODUCTION-GRADE patch.
Strict Rules:
1. Fix ONLY the vulnerability (e.g. parameterize SQL, sanitize shell/paths, safe deserialization).
2. NEVER modify unrelated function signatures or delete functions (strictly preserve AST invariant contracts).
3. Output ONLY valid Unified Diff enclosed in ```diff ... ``` or ```patch ... ```.
"""


class BlueTeamAgent:
    """Defense agent that combines LLM reasoning (Nemotron-70B) with Deterministic AST fallback."""

    def __init__(self, client: Optional[NebiusNemotronClient] = None):
        self.client = client or NebiusNemotronClient(model=ModelTier.SUPER.value)

    def synthesize_patch(
        self,
        finding: SecurityFinding,
        source_code: str,
        blast_radius: List[str],
        adversarial_feedback: Optional[str] = None,
    ) -> SwarmAgentResult:
        feedback_section = (
            f"\nAdversarial Verifier Feedback:\n{adversarial_feedback}"
            if adversarial_feedback
            else ""
        )
        prompt = f"""Target File: {finding.file_path}
Vulnerability: {finding.rule_id} ({finding.cwe or 'CWE-Unknown'})
Target Scope: Lines {finding.start_line}-{finding.end_line}
Impacted Call-Graph Functions: {', '.join(blast_radius)}
{feedback_section}

--- SOURCE CODE ---
{source_code}
--- END SOURCE CODE ---

Generate a precision Unified Diff patch:
"""
        messages = [
            {"role": "system", "content": BLUE_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw_output = self.client.chat_completion(messages)
        extracted_diff = self._extract_diff(raw_output)

        # If LLM output is mock / invalid, apply Deterministic AST Semantic Patch Engine
        final_diff = extracted_diff
        if not self.client.api_key or "--- a/vulnerable.py" in extracted_diff:
            target_fn = blast_radius[0] if blast_radius else "all"
            if finding.cwe == "CWE-89" or "sqli" in finding.rule_id.lower():
                ok, patched, ast_diff = AstSemanticPatcher.patch_sqli_sqlite(
                    source_code, target_fn
                )
                if ok and ast_diff:
                    final_diff = ast_diff
            elif finding.cwe == "CWE-78" or "cmdi" in finding.rule_id.lower():
                ok, patched, ast_diff = AstSemanticPatcher.patch_command_injection(
                    source_code, target_fn
                )
                if ok and ast_diff:
                    final_diff = ast_diff

        return SwarmAgentResult(
            agent_name="BlueTeam-PatchSynthesizer",
            model_used=self.client.model,
            status="SUCCESS",
            output=final_diff,
            token_usage={
                "prompt": len(prompt) // 4,
                "completion": len(final_diff) // 4,
            },
        )

    def _extract_diff(self, text: str) -> str:
        match = re.search(r"```(?:patch|diff)?\s*\n(.*?)\n```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()
