"""Type definitions and data structures for ClimateTrust AI Oracle."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class AttackType(str, Enum):
    """Types of adversarial attacks or data tampering in climate pipelines."""
    NONE = "none"
    UNDER_REPORTING = "under_reporting"        # Fraudulent suppression of emission spikes to evade carbon tax
    DRIFT_POISONING = "drift_poisoning"        # Gradual stealth bias injection
    SENSOR_SPOOFING = "sensor_spoofing"        # Falsified location/station identity
    REPLAY_ATTACK = "replay_attack"            # Repeating stale low-emission data payloads
    SYNTHETIC_FLATLINE = "synthetic_flatline"  # Constant fake zero variance numbers


class VerificationStatus(str, Enum):
    """Verification outcome for climate telemetry."""
    VERIFIED = "verified"
    FLAGGED_ANOMALOUS = "flagged_anomalous"
    REJECTED_TAMPERED = "rejected_tampered"


@dataclass
class TelemetryPoint:
    """Individual environmental telemetry observation."""
    station_id: str
    timestamp: int                          # Unix timestamp in seconds
    latitude: float
    longitude: float
    co2_ppm: float                         # Carbon Dioxide (ppm)
    ch4_ppb: float                         # Methane (ppb)
    pm25_ugm3: float                       # PM2.5 particulate matter (ug/m3)
    temperature_c: float                   # Ambient temperature in Celsius
    humidity_pct: float                    # Relative humidity (0 - 100%)
    source_api: str                        # e.g. 'Copernicus-Sentinel5P', 'OpenAQ-GroundNode'
    attack_injected: AttackType = AttackType.NONE
    raw_signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "station_id": self.station_id,
            "timestamp": self.timestamp,
            "latitude": round(self.latitude, 5),
            "longitude": round(self.longitude, 5),
            "co2_ppm": round(self.co2_ppm, 2),
            "ch4_ppb": round(self.ch4_ppb, 2),
            "pm25_ugm3": round(self.pm25_ugm3, 2),
            "temperature_c": round(self.temperature_c, 2),
            "humidity_pct": round(self.humidity_pct, 2),
            "source_api": self.source_api,
            "attack_injected": self.attack_injected.value,
            "raw_signature": self.raw_signature,
            "metadata": self.metadata,
        }


@dataclass
class AuditFinding:
    """Specific adversarial anomaly or integrity violation discovered by AI verification."""
    rule_name: str
    severity: str                           # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float                       # 0.0 to 1.0
    station_id: str
    explanation: str
    metric_impacted: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "station_id": self.station_id,
            "explanation": self.explanation,
            "metric_impacted": self.metric_impacted,
            "evidence": self.evidence,
        }


@dataclass
class AttestationReport:
    """Full epoch attestation report ready for cryptographic sealing and smart contract attestation."""
    epoch_id: str
    timestamp: int
    total_samples: int
    verified_samples: int
    rejected_samples: int
    overall_integrity_score: float         # 0.0 to 1.0 (>= 0.85 passes verification threshold)
    status: VerificationStatus
    merkle_root: str
    oracle_signature: str
    findings: List[AuditFinding]
    telemetry_samples: List[TelemetryPoint] = field(default_factory=list)
    zk_proofs: List[Dict[str, Any]] = field(default_factory=list)
    ipfs_cid: Optional[str] = None
    ipfs_uri: Optional[str] = None
    tx_hash: Optional[str] = None
    block_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "timestamp": self.timestamp,
            "total_samples": self.total_samples,
            "verified_samples": self.verified_samples,
            "rejected_samples": self.rejected_samples,
            "overall_integrity_score": round(self.overall_integrity_score, 4),
            "status": self.status.value,
            "merkle_root": self.merkle_root,
            "oracle_signature": self.oracle_signature,
            "findings": [f.to_dict() for f in self.findings],
            "zk_proofs_count": len(self.zk_proofs),
            "ipfs_cid": self.ipfs_cid,
            "ipfs_uri": self.ipfs_uri,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "sample_count": len(self.telemetry_samples),
        }
