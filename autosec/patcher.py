import re
from typing import Optional
from autosec.parser import VulnerabilityFinding
from autosec.client import NebiusNemotronClient

SYSTEM_PROMPT = """You are an elite application security engineer and automated patching agent.
Your mission: Given a vulnerability finding and the original source code, produce the MINIMAL, safe, production-grade patch.
Rules:
1. Fix ONLY the security defect without altering unrelated business logic (YAGNI principle).
2. Output your response as a valid Unified Diff format enclosed strictly in ```patch ... ``` or ```diff ... ``` codeblocks.
3. Keep line changes minimal and maintain existing coding style and formatting.
"""


def build_prompt(finding: VulnerabilityFinding, source_code: str) -> str:
    return f"""Target File: {finding.file_path}
Vulnerability Rule: {finding.rule_id}
CWE: {finding.cwe or 'Not Specified'}
Finding Description: {finding.message}
Target Lines: {finding.start_line}-{finding.end_line}

--- ORIGINAL SOURCE CODE ({finding.file_path}) ---
{source_code}
--- END SOURCE CODE ---

Analyze the vulnerability and output the unified diff (patch) to remediate it.
"""


def extract_patch_block(response_text: str) -> str:
    """Extract unified diff from model response codeblocks."""
    pattern = r"```(?:patch|diff)?\s*\n(.*?)\n```"
    match = re.search(pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return response_text.strip()


class NemotronPatcher:
    def __init__(self, client: Optional[NebiusNemotronClient] = None):
        self.client = client or NebiusNemotronClient()

    def generate_patch(self, finding: VulnerabilityFinding, source_code: str) -> str:
        prompt = build_prompt(finding, source_code)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw_output = self.client.chat_completion(messages)
        return extract_patch_block(raw_output)

    def heal_patch(
        self, finding: VulnerabilityFinding, source_code: str, test_failure_output: str
    ) -> str:
        """Self-healing loop if initial patch breaks regression tests."""
        prompt = f"""The previous patch failed regression tests.
Target File: {finding.file_path}
Vulnerability Rule: {finding.rule_id}

--- SOURCE CODE ---
{source_code}

--- TEST FAILURE OUTPUT ---
{test_failure_output}

Fix the patch so it remediates the security issue while passing all regression tests.
Output ONLY the unified diff enclosed in ```patch ... ```.
"""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        raw_output = self.client.chat_completion(messages)
        return extract_patch_block(raw_output)
