import re
from typing import Dict, Optional
from autosec.types import SecurityFinding, SwarmAgentResult, ModelTier
from autosec.client import NebiusNemotronClient

EXPLOIT_TEMPLATES = {
    "CWE-89": """# AutoSec Synthesized Exploit PoC: SQL Injection (CWE-89)
import sqlite3

def run_exploit(target_func):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'superuser'), ('guest', 'user')")
    conn.commit()

    payload = "' OR '1'='1"
    res = target_func(conn, payload)
    # If exploit succeeds, it returns the admin row despite invalid username
    if res and res[1] == "admin":
        return True, "EXPLOIT_SUCCESS: SQL Injection bypassed authentication"
    return False, "EXPLOIT_BLOCKED: Parameterized query sanitized input"
""",
    "CWE-78": """# AutoSec Synthesized Exploit PoC: OS Command Injection (CWE-78)
def run_exploit(target_func):
    payload = "; echo INJECTED_FLAG"
    res = target_func(payload)
    if "INJECTED_FLAG" in str(res):
        return True, "EXPLOIT_SUCCESS: Command injection executed payload"
    return False, "EXPLOIT_BLOCKED: Shell execution prevented or sanitized"
""",
    "CWE-22": """# AutoSec Synthesized Exploit PoC: Path Traversal (CWE-22)
def run_exploit(target_func):
    payload = "../../../../etc/passwd"
    res = target_func(payload)
    if res and "root:" in str(res):
        return True, "EXPLOIT_SUCCESS: Arbitrary file read succeeded"
    return False, "EXPLOIT_BLOCKED: Path traversal sanitized"
""",
}

class RedTeamAgent:
    """Adversarial agent that synthesizes dynamic exploit PoCs using Nemotron-3-Ultra."""

    def __init__(self, client: Optional[NebiusNemotronClient] = None):
        self.client = client or NebiusNemotronClient(model=ModelTier.ULTRA.value)

    def generate_exploit_poc(self, finding: SecurityFinding, source_code: str) -> SwarmAgentResult:
        cwe_key = finding.cwe if finding.cwe in EXPLOIT_TEMPLATES else "CWE-89"
        default_poc = EXPLOIT_TEMPLATES.get(cwe_key, EXPLOIT_TEMPLATES["CWE-89"])

        prompt = f"""[RED TEAM ADVERSARIAL AGENT]
Analyze the vulnerability in {finding.file_path} (Rule: {finding.rule_id}, CWE: {finding.cwe}).
Generate an executable Python exploit PoC function `run_exploit(target_func)` that returns (True, message) if exploit works and (False, message) if secure.

Source Code:
{source_code}
"""
        messages = [
            {"role": "system", "content": "You are a Red Team exploit developer. Output pure executable Python PoC code enclosed in ```python ... ```."},
            {"role": "user", "content": prompt},
        ]
        raw_output = self.client.chat_completion(messages)
        poc_code = self._extract_code(raw_output) or default_poc

        return SwarmAgentResult(
            agent_name="RedTeam-ExploitSynthesizer",
            model_used=self.client.model,
            status="SUCCESS",
            output=poc_code,
            token_usage={"prompt": len(prompt) // 4, "completion": len(poc_code) // 4},
        )

    def _extract_code(self, text: str) -> Optional[str]:
        match = re.search(r"```(?:python)?\s*\n(.*?)\n```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None
