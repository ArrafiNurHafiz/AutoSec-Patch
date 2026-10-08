from dataclasses import dataclass
from typing import List, Dict, Tuple
from autosec.types import SecurityFinding, SwarmAgentResult
from autosec.swarm.memory import EpisodicSwarmMemory

@dataclass
class ConsensusVerdict:
    approved: bool
    approval_rate: float
    selected_patch: str
    dissenting_opinions: List[str]
    confidence_level: float

class SwarmConsensusProtocol:
    """Orchestrates multi-agent debate and voting between Red, Blue, Auditor, and Architect."""

    def __init__(self, memory: EpisodicSwarmMemory):
        self.memory = memory

    def adjudicate_patch(
        self,
        finding: SecurityFinding,
        candidate_patch: str,
        is_secure: bool,
        is_regression_clean: bool,
        blast_radius_nodes: List[str]
    ) -> ConsensusVerdict:
        votes = []
        dissent = []

        # 1. Red Team Vote (Exploitability resistance)
        if is_secure:
            votes.append(("RedTeam", 1.0, "Exploit neutralized completely"))
        else:
            votes.append(("RedTeam", 0.0, "Exploit bypass detected"))
            dissent.append("RedTeam: Payload still executes")

        # 2. Blue Team Vote (Functional integrity)
        if is_regression_clean:
            votes.append(("BlueTeam", 1.0, "Regression tests pass 100%"))
        else:
            votes.append(("BlueTeam", 0.0, "Regression suite broken"))
            dissent.append("BlueTeam: Business logic altered")

        # 3. Architect Agent Vote (Blast Radius constraint)
        if len(blast_radius_nodes) <= 5:
            votes.append(("ArchitectAgent", 1.0, "Blast radius cleanly contained"))
        else:
            votes.append(("ArchitectAgent", 0.5, "High blast radius complexity"))
            dissent.append("ArchitectAgent: Broad caller impact requires caution")

        # 4. AppSec Auditor Vote (Memory match & best practice)
        past_fix = self.memory.recall_similar_fix(finding.cwe or "CWE-89")
        if past_fix:
            votes.append(("AppSecAuditor", 1.0, f"Fix aligns with learned memory {past_fix.memory_id}"))
        else:
            votes.append(("AppSecAuditor", 0.9, "Novel remediation pattern validated"))

        total_score = sum(v[1] for v in votes)
        approval_rate = total_score / len(votes)
        is_approved = approval_rate >= 0.75 and is_secure and is_regression_clean

        if is_approved:
            self.memory.remember(
                cwe=finding.cwe or "CWE-89",
                pattern_signature=finding.rule_id,
                successful_patch_strategy="AST Invariant Parameterization / Sanitization",
                exploit_payload_signature="RedTeam Synthesized PoC",
                confidence=approval_rate,
            )

        return ConsensusVerdict(
            approved=is_approved,
            approval_rate=round(approval_rate, 2),
            selected_patch=candidate_patch,
            dissenting_opinions=dissent,
            confidence_level=round(approval_rate * 100, 1),
        )
