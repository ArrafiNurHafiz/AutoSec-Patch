from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional


class ModelTier(str, Enum):
    NANO = "nvidia/llama-3.1-nemotron-nano"
    SUPER = "nvidia/llama-3.1-nemotron-70b-instruct"
    ULTRA = "nvidia/nemotron-3-ultra"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityFinding:
    rule_id: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    cwe: Optional[str] = None
    severity: FindingSeverity = FindingSeverity.HIGH
    snippet: Optional[str] = None
    taint_source: Optional[str] = None
    taint_sink: Optional[str] = None


@dataclass
class SwarmAgentResult:
    agent_name: str
    model_used: str
    status: str
    output: Any
    token_usage: Dict[str, int] = field(
        default_factory=lambda: {"prompt": 0, "completion": 0}
    )
    duration_ms: float = 0.0


@dataclass
class RemediationResult:
    finding: SecurityFinding
    initial_patch: str
    final_patch: str
    iterations: int
    verified_secure: bool
    regression_passed: bool
    blast_radius_nodes: List[str]
    timeline: List[SwarmAgentResult] = field(default_factory=list)
