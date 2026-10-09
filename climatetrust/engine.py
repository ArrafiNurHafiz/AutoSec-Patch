"""ClimateTrust AI Verification Engine: Orchestrates multi-agent auditing and adversarial detection."""

from typing import List, Dict, Tuple
from climatetrust.types import TelemetryPoint, AuditFinding, VerificationStatus
from climatetrust.detector import (
    SpatialTemporalAnomalyDetector,
    AtmosphericPhysicsVerifier,
    EntropyAndReplayDetector
)


class ClimateTrustEngine:
    """Core AI Verification Mesh for climate and emissions telemetry."""

    def __init__(self):
        self.spatial_detector = SpatialTemporalAnomalyDetector()
        self.physics_verifier = AtmosphericPhysicsVerifier()
        self.entropy_detector = EntropyAndReplayDetector()

    def audit_epoch(
        self,
        points: List[TelemetryPoint]
    ) -> Tuple[List[TelemetryPoint], List[TelemetryPoint], List[AuditFinding], float]:
        """Audit an entire epoch batch of telemetry points.
        
        Returns:
            verified_points: Telemetry points confirmed clean and tamper-free.
            rejected_points: Telemetry points caught by adversarial verification.
            all_findings: List of all audit findings detected.
            epoch_integrity_score: Normalized integrity score (0.0 - 1.0).
        """
        all_findings: List[AuditFinding] = []

        # Run multi-agent detectors
        all_findings.extend(self.spatial_detector.audit_spatial_coherence(points))
        all_findings.extend(self.physics_verifier.audit_combustion_covariance(points))
        all_findings.extend(self.entropy_detector.audit_entropy_and_flatlines(points))

        # Map findings per station
        station_findings: Dict[str, List[AuditFinding]] = {p.station_id: [] for p in points}
        for finding in all_findings:
            if finding.station_id in station_findings:
                station_findings[finding.station_id].append(finding)

        verified_points: List[TelemetryPoint] = []
        rejected_points: List[TelemetryPoint] = []

        total_penalty = 0.0

        for p in points:
            findings = station_findings[p.station_id]
            is_compromised = False

            for f in findings:
                if f.severity in ("CRITICAL", "HIGH") and f.confidence >= 0.80:
                    is_compromised = True
                    total_penalty += 1.0
                elif f.severity == "MEDIUM":
                    total_penalty += 0.5
                else:
                    total_penalty += 0.2

            if is_compromised:
                rejected_points.append(p)
            else:
                verified_points.append(p)

        total_samples = len(points)
        if total_samples > 0:
            raw_score = 1.0 - (total_penalty / total_samples)
            epoch_integrity_score = max(0.0, min(1.0, raw_score))
        else:
            epoch_integrity_score = 1.0

        return verified_points, rejected_points, all_findings, epoch_integrity_score
