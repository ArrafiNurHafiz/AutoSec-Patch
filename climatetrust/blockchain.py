"""Blockchain connector and EVM smart contract interface for ClimateTrust."""

import time
import hashlib
from typing import Dict, Any, List, Optional
from climatetrust.types import AttestationReport, VerificationStatus


class BlockchainConnector:
    """Simulates or connects to EVM smart contract for ClimateTrustOracle."""

    def __init__(self, contract_address: str = "0x71C83605E6714E69719468E717D5F762B4Fe4331"):
        self.contract_address = contract_address
        self.epoch_registry: Dict[str, Dict[str, Any]] = {}
        self.tx_history: List[Dict[str, Any]] = []
        self.current_block = 19842100

    def submit_attestation(self, report: AttestationReport) -> Dict[str, Any]:
        """Submit an attested epoch report to the smart contract."""
        self.current_block += 1
        tx_data = f"{report.epoch_id}:{report.merkle_root}:{self.current_block}:{time.time()}".encode("utf-8")
        tx_hash = f"0x{hashlib.sha256(tx_data).hexdigest()}"

        # Enforce on-chain minimum threshold logic
        if report.overall_integrity_score < 0.80:
            status = "REVERTED"
            revert_reason = "Integrity score below consensus threshold (80%)"
        else:
            status = "CONFIRMED"
            revert_reason = None

        events = []
        if status == "CONFIRMED":
            events.append({
                "event": "ClimateEpochAttested",
                "epochId": report.epoch_id,
                "merkleRoot": report.merkle_root,
                "integrityScore": int(report.overall_integrity_score * 10000),
                "verifiedSamples": report.verified_samples,
                "rejectedSamples": report.rejected_samples,
            })
            if report.rejected_samples > 0:
                events.append({
                    "event": "TamperingDetected",
                    "epochId": report.epoch_id,
                    "rejectedSamples": report.rejected_samples,
                    "reason": "Adversarial data poisoning or spoofing quarantined by AI Engine"
                })

            self.epoch_registry[report.epoch_id] = {
                "merkle_root": report.merkle_root,
                "timestamp": report.timestamp,
                "integrity_score": report.overall_integrity_score,
                "verified_samples": report.verified_samples,
                "rejected_samples": report.rejected_samples,
                "tx_hash": tx_hash,
                "block_number": self.current_block,
            }

        receipt = {
            "tx_hash": tx_hash,
            "block_number": self.current_block,
            "contract_address": self.contract_address,
            "status": status,
            "revert_reason": revert_reason,
            "gas_used": 68420 if status == "CONFIRMED" else 21000,
            "events": events
        }

        report.tx_hash = tx_hash
        report.block_number = self.current_block

        self.tx_history.append(receipt)
        return receipt

    def verify_leaf_on_chain(self, epoch_id: str, leaf_hash: str, proof: List[str]) -> bool:
        """Verify on-chain inclusion proof against the registered Merkle root."""
        if epoch_id not in self.epoch_registry:
            return False
        root = self.epoch_registry[epoch_id]["merkle_root"]
        from climatetrust.crypto import MerkleTree
        return MerkleTree.verify_proof(leaf_hash, proof, root)
