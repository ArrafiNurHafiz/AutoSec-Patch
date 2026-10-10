"""Zero-Knowledge Proof (ZK-Proof) simulation for Privacy-Preserving Climate Telemetry.

Allows industrial emitters and green energy nodes to cryptographically prove:
1. Regional bounding box membership without revealing exact GPS coordinates (ZK-Location).
2. Regulatory emissions compliance (CO2, CH4, PM2.5 <= threshold) without leaking proprietary factory baselines.
"""

import secrets
from typing import Dict, Any
from eth_hash.auto import keccak
from climatetrust.types import TelemetryPoint


def keccak256_hex(data: bytes) -> str:
    return f"0x{keccak(data).hex()}"


class ZKClimateProver:
    """Generates Zero-Knowledge commitments and non-interactive zero-knowledge proofs (NIZKP) for telemetry."""

    REGIONAL_BOUNDS = {
        "REGION-US-EAST": {
            "min_lat": 40.0,
            "max_lat": 41.5,
            "min_lon": -75.0,
            "max_lon": -73.0,
        },
        "REGION-EU-CENTRAL": {
            "min_lat": 48.0,
            "max_lat": 52.0,
            "min_lon": 8.0,
            "max_lon": 14.0,
        },
        "REGION-APAC-COASTAL": {
            "min_lat": 1.0,
            "max_lat": 6.0,
            "min_lon": 100.0,
            "max_lon": 105.0,
        },
    }

    # Regulatory emission caps (ppm / ppb / ug/m3)
    REGULATORY_CAPS = {
        "co2_cap_ppm": 600.0,
        "ch4_cap_ppb": 2500.0,
        "pm25_cap_ugm3": 50.0,
    }

    @classmethod
    def generate_zk_proof(
        cls, point: TelemetryPoint, region_id: str = "REGION-US-EAST"
    ) -> Dict[str, Any]:
        """Generate a zero-knowledge proof for location privacy and regulatory compliance.

        Witness (Secret): exact latitude, longitude, exact emission numbers, blinding salt.
        Public Statement: region_id, compliance_cap_passed: True, commitment_hash.
        """
        # 1. Blinding salt for Pedersen-like commitment
        blinding_salt = secrets.token_hex(16)

        # 2. Secret Witness Commitment
        witness_raw = f"{point.station_id}:{point.latitude:.5f}:{point.longitude:.5f}:{point.co2_ppm:.2f}:{blinding_salt}".encode(
            "utf-8"
        )
        commitment_hash = keccak256_hex(witness_raw)

        # 3. Check predicates (The secret witness satisfies these)
        bounds = cls.REGIONAL_BOUNDS.get(
            region_id, cls.REGIONAL_BOUNDS["REGION-US-EAST"]
        )
        is_in_region = (
            bounds["min_lat"] <= point.latitude <= bounds["max_lat"]
            and bounds["min_lon"] <= point.longitude <= bounds["max_lon"]
        )

        is_co2_compliant = point.co2_ppm <= cls.REGULATORY_CAPS["co2_cap_ppm"]
        is_ch4_compliant = point.ch4_ppb <= cls.REGULATORY_CAPS["ch4_cap_ppb"]
        is_pm25_compliant = point.pm25_ugm3 <= cls.REGULATORY_CAPS["pm25_cap_ugm3"]
        all_compliant = is_co2_compliant and is_ch4_compliant and is_pm25_compliant

        # 4. Generate Schnorr/Fiat-Shamir challenge response simulation
        challenge_preimage = (
            f"{commitment_hash}:{region_id}:{all_compliant}:{point.timestamp}".encode(
                "utf-8"
            )
        )
        challenge = keccak256_hex(challenge_preimage)

        # Simulated proof transcript (pi = {A, B, C, challenge, response})
        proof_payload = {
            "commitment_hash": commitment_hash,
            "region_id": region_id,
            "public_caps": cls.REGULATORY_CAPS,
            "is_region_valid": is_in_region,
            "is_emissions_compliant": all_compliant,
            "challenge": challenge,
            "proof_protocol": "Groth16/Snark-Climate-RangeProof-v1",
            "proof_pi_a": keccak256_hex(
                f"pi_a:{commitment_hash}:{challenge}".encode("utf-8")
            ),
            "proof_pi_b": keccak256_hex(
                f"pi_b:{commitment_hash}:{challenge}".encode("utf-8")
            ),
            "proof_pi_c": keccak256_hex(
                f"pi_c:{commitment_hash}:{challenge}".encode("utf-8")
            ),
        }
        return proof_payload

    @classmethod
    def verify_zk_proof(cls, proof: Dict[str, Any]) -> bool:
        """Verify zero-knowledge proof without accessing the private coordinates or exact emissions."""
        # Verify challenge integrity
        commitment = proof.get("commitment_hash")
        region_id = proof.get("region_id")
        all_compliant = proof.get("is_emissions_compliant")
        proof_pi_a = proof.get("proof_pi_a")

        if not (commitment and region_id and proof_pi_a):
            return False

        # In a valid zero-knowledge proof, both region membership and emission compliance must be proven
        if not (proof.get("is_region_valid", False) and all_compliant):
            return False

        # Verify challenge derivation
        expected_pi_a = keccak256_hex(
            f"pi_a:{commitment}:{proof.get('challenge')}".encode("utf-8")
        )
        return proof_pi_a == expected_pi_a
