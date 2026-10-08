from dataclasses import dataclass
from typing import Dict, Optional
from autosec.types import SecurityFinding

@dataclass
class RiskProfile:
    composite_score: float
    cvss_base: float
    epss_percentile: float
    reachability_depth: int
    is_externally_reachable: bool
    priority_level: str

class DynamicRiskPrioritizer:
    """Computes Composite Risk Score = 0.4*CVSS + 0.3*(EPSS*10) + 0.3*(Reachability*10)."""

    DEFAULT_CVSS_MAP = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 3.0,
        "INFO": 1.0,
    }

    @classmethod
    def calculate_risk(
        cls,
        finding: SecurityFinding,
        call_depth: int = 1,
        epss_score: float = 0.65
    ) -> RiskProfile:
        cvss = cls.DEFAULT_CVSS_MAP.get(str(finding.severity).upper(), 7.5)
        # Normalize reachability (depth 1-3 = high reachability)
        reachability_norm = 1.0 if call_depth <= 2 else (0.6 if call_depth <= 4 else 0.2)
        
        composite = (0.4 * cvss) + (0.3 * (epss_score * 10)) + (0.3 * (reachability_norm * 10))
        
        if composite >= 8.5:
            priority = "P0 - IMMEDIATE BLOCKER"
        elif composite >= 6.5:
            priority = "P1 - HIGH REMEDIATION"
        elif composite >= 4.0:
            priority = "P2 - MEDIUM"
        else:
            priority = "P3 - LOW"

        return RiskProfile(
            composite_score=round(composite, 2),
            cvss_base=cvss,
            epss_percentile=round(epss_score, 4),
            reachability_depth=call_depth,
            is_externally_reachable=(call_depth <= 2),
            priority_level=priority,
        )
