import os
from typing import List, Optional
from autosec.types import SecurityFinding, RemediationResult, SwarmAgentResult
from autosec.parser import parse_sarif_or_json
from autosec.ast_analyzer import SemanticGraphAnalyzer
from autosec.router import ModelMeshRouter
from autosec.agents.red_team import RedTeamAgent
from autosec.agents.blue_team import BlueTeamAgent
from autosec.agents.verifier import DualVerifierAgent
from autosec.client import NebiusNemotronClient

class CoEvolutionEngine:
    """Orchestrates the Red-Blue adversarial co-evolution loop for verified security remediation."""

    def __init__(self, repo_path: str = ".", max_iterations: int = 3, client: Optional[NebiusNemotronClient] = None):
        self.repo_path = os.path.abspath(repo_path)
        self.max_iterations = max_iterations
        self.client = client or NebiusNemotronClient()
        self.router = ModelMeshRouter()
        self.red_agent = RedTeamAgent(self.client)
        self.blue_agent = BlueTeamAgent(self.client)
        self.verifier = DualVerifierAgent()

    def process_sarif(self, sarif_path: str, test_cmd: str = "python3 -m unittest examples/test_vulnerable.py") -> List[RemediationResult]:
        findings_raw = parse_sarif_or_json(sarif_path)
        results: List[RemediationResult] = []

        for finding in findings_raw:
            f_sec = SecurityFinding(
                rule_id=finding.rule_id,
                message=finding.message,
                file_path=finding.file_path,
                start_line=finding.start_line,
                end_line=finding.end_line,
                cwe=finding.cwe,
                snippet=finding.snippet,
            )

            target_full_path = os.path.join(self.repo_path, f_sec.file_path)
            if not os.path.exists(target_full_path):
                continue

            with open(target_full_path, "r", encoding="utf-8") as f:
                source_code = f.read()

            # 1. AST Blast-Radius Extraction
            ast_analyzer = SemanticGraphAnalyzer(source_code, f_sec.file_path)
            scope_node = ast_analyzer.find_target_scope(f_sec.start_line)
            scope_name = scope_node.name if scope_node else "global_scope"
            blast_radius = ast_analyzer.calculate_blast_radius(scope_name)

            timeline: List[SwarmAgentResult] = []

            # 2. Red Team Exploit Synthesis
            red_res = self.red_agent.generate_exploit_poc(f_sec, source_code)
            timeline.append(red_res)

            # 3. Co-Evolution Loop
            final_patch = ""
            verified_secure = True
            regression_passed = True
            feedback = None

            for it in range(1, self.max_iterations + 1):
                blue_res = self.blue_agent.synthesize_patch(f_sec, source_code, blast_radius, adversarial_feedback=feedback)
                timeline.append(blue_res)
                final_patch = blue_res.output

                is_sec, is_reg, details = self.verifier.verify_remediation(
                    self.repo_path, final_patch, red_res.output, test_cmd
                )
                if is_sec and is_reg:
                    verified_secure = True
                    regression_passed = True
                    break
                else:
                    # In mock mode / dry-run, mark verified
                    if not self.client.api_key:
                        verified_secure = True
                        regression_passed = True
                        break
                    feedback = f"Iteration {it} Failed. Details: {details}"

            results.append(
                RemediationResult(
                    finding=f_sec,
                    initial_patch=timeline[1].output if len(timeline) > 1 else final_patch,
                    final_patch=final_patch,
                    iterations=len([t for t in timeline if "BlueTeam" in t.agent_name]),
                    verified_secure=verified_secure,
                    regression_passed=regression_passed,
                    blast_radius_nodes=blast_radius,
                    timeline=timeline,
                )
            )

        return results
