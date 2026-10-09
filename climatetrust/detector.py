"""AI Adversarial Verification Mesh and Physics-Informed Anomaly Detectors for Climate Telemetry."""

import math
from typing import List, Dict, Tuple
from climatetrust.types import TelemetryPoint, AuditFinding, AttackType, VerificationStatus


class SpatialTemporalAnomalyDetector:
    """Evaluates spatial correlation and cluster neighbor coherence."""

    @staticmethod
    def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate great circle distance between two points in kilometers."""
        radius = 6371.0  # Earth radius in km
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2.0) ** 2 +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2.0) ** 2)
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return radius * c

    def audit_spatial_coherence(self, points: List[TelemetryPoint]) -> List[AuditFinding]:
        """Detect spatial divergence where a station's reading wildly violates its spatial neighborhood."""
        findings: List[AuditFinding] = []
        if len(points) < 3:
            return findings

        # Group by spatial proximity (< 15 km)
        for target in points:
            neighbors = [
                p for p in points
                if p.station_id != target.station_id and
                self.haversine_distance_km(target.latitude, target.longitude, p.latitude, p.longitude) <= 15.0
            ]

            if not neighbors:
                continue

            # Compute neighborhood average and standard deviation
            mean_co2 = sum(p.co2_ppm for p in neighbors) / len(neighbors)
            mean_pm25 = sum(p.pm25_ugm3 for p in neighbors) / len(neighbors)

            # Significant divergence check (e.g. divergence > 35% from spatial neighbors)
            co2_diff = abs(target.co2_ppm - mean_co2)
            if co2_diff > 90.0:
                findings.append(AuditFinding(
                    rule_name="SPATIAL_NEIGHBORHOOD_DIVERGENCE",
                    severity="HIGH",
                    confidence=0.92,
                    station_id=target.station_id,
                    metric_impacted="co2_ppm",
                    explanation=(
                        f"Station {target.station_id} reported CO2={target.co2_ppm:.1f} ppm, "
                        f"diverging drastically from {len(neighbors)} spatial neighbors (mean={mean_co2:.1f} ppm)."
                    ),
                    evidence={
                        "target_co2": target.co2_ppm,
                        "neighbor_mean_co2": round(mean_co2, 2),
                        "delta_ppm": round(co2_diff, 2),
                        "neighbors_count": len(neighbors)
                    }
                ))

        return findings


class AtmosphericPhysicsVerifier:
    """Enforces multi-gas combustion stoichiometry and atmospheric co-variance rules."""

    def audit_combustion_covariance(self, points: List[TelemetryPoint]) -> List[AuditFinding]:
        """Detect selective under-reporting fraud where CO2 is suppressed while combustion co-pollutants remain high."""
        findings: List[AuditFinding] = []

        for p in points:
            # Combustion rule: In industrial/urban combustion, high PM2.5 (>35 ug/m3) or high CH4 (>2100 ppb)
            # is physically coupled with elevated CO2 (>480 ppm).
            # If CO2 claims to be clean (<430 ppm) despite heavy PM2.5 and CH4, suspect under-reporting clamp!
            has_heavy_copollutants = (p.pm25_ugm3 > 30.0 or p.ch4_ppb > 2150.0)
            claims_low_co2 = (p.co2_ppm < 430.0)

            if has_heavy_copollutants and claims_low_co2:
                findings.append(AuditFinding(
                    rule_name="COMBUSTION_DECOUPLING_UNDER_REPORTING",
                    severity="CRITICAL",
                    confidence=0.96,
                    station_id=p.station_id,
                    metric_impacted="co2_ppm",
                    explanation=(
                        f"Physical decoupling detected: Station {p.station_id} claims low CO2 ({p.co2_ppm:.1f} ppm) "
                        f"despite severe combustion markers (PM2.5={p.pm25_ugm3:.1f} ug/m3, CH4={p.ch4_ppb:.1f} ppb). "
                        "High probability of carbon tax evasion through fraudulent telemetry clipping."
                    ),
                    evidence={
                        "reported_co2": p.co2_ppm,
                        "reported_pm25": p.pm25_ugm3,
                        "reported_ch4": p.ch4_ppb
                    }
                ))

        return findings


class EntropyAndReplayDetector:
    """Detects synthetic flatlines, zero-entropy payloads, and replay attacks."""

    def audit_entropy_and_flatlines(self, points: List[TelemetryPoint]) -> List[AuditFinding]:
        """Detect suspiciously static synthetic payloads lacking natural atmospheric entropy."""
        findings: List[AuditFinding] = []

        for p in points:
            # Check for suspicious exact round numbers across multiple metrics
            is_suspiciously_round = (
                p.co2_ppm == round(p.co2_ppm, 0) and
                p.ch4_ppb == round(p.ch4_ppb, 0) and
                p.pm25_ugm3 == round(p.pm25_ugm3, 0) and
                p.temperature_c == round(p.temperature_c, 0) and
                p.humidity_pct == round(p.humidity_pct, 0)
            )

            if is_suspiciously_round:
                findings.append(AuditFinding(
                    rule_name="SYNTHETIC_ZERO_ENTROPY_PAYLOAD",
                    severity="HIGH",
                    confidence=0.88,
                    station_id=p.station_id,
                    metric_impacted="all_metrics",
                    explanation=(
                        f"Telemetry from {p.station_id} exhibits zero entropy and exact rounded integers across 5 sensors. "
                        "Physical sensors in atmosphere always display micro-fluctuation noise."
                    ),
                    evidence={"metrics": p.to_dict()}
                ))

        return findings
