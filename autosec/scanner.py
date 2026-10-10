import subprocess
import shutil
import json
import os
from typing import List
from autosec.parser import VulnerabilityFinding, parse_sarif_or_json


class LiveSASTOrchestrator:
    """Orchestrates real SAST tools (Semgrep, Bandit, Flake8) directly against the codebase."""

    @classmethod
    def run_semgrep_live(cls, target_dir: str = ".") -> List[VulnerabilityFinding]:
        """Runs semgrep CLI if installed, generating live SARIF."""
        if not shutil.which("semgrep"):
            return []

        sarif_out = os.path.join(target_dir, "live_semgrep.sarif")
        cmd = [
            "semgrep",
            "scan",
            "--config",
            "auto",
            "--sarif",
            "--output",
            sarif_out,
            target_dir,
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if os.path.exists(sarif_out):
                findings = parse_sarif_or_json(sarif_out)
                os.remove(sarif_out)
                return findings
        except Exception:
            pass
        return []

    @classmethod
    def run_bandit_live(cls, target_dir: str = ".") -> List[VulnerabilityFinding]:
        """Runs bandit security scanner for Python AST vulnerabilities."""
        if not shutil.which("bandit"):
            return []

        json_out = os.path.join(target_dir, "live_bandit.json")
        cmd = ["bandit", "-r", target_dir, "-f", "json", "-o", json_out]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if os.path.exists(json_out):
                with open(json_out, "r") as f:
                    data = json.load(f)
                os.remove(json_out)
                findings = []
                for item in data.get("results", []):
                    findings.append(
                        VulnerabilityFinding(
                            rule_id=item.get("test_id", "BANDIT_RULE"),
                            message=item.get("issue_text", ""),
                            file_path=item.get("filename", "").lstrip("./"),
                            start_line=item.get("line_number", 1),
                            end_line=item.get("line_number", 1),
                            snippet=item.get("code", ""),
                            cwe=f"CWE-{item.get('issue_cwe', {}).get('id', 'Unknown')}",
                        )
                    )
                return findings
        except Exception:
            pass
        return []
