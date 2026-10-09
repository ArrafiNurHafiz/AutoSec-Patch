"""IPFS Serializer and Packaging Engine for ClimateTrust decentralized storage.

Generates standard IPFS Multihash CIDv0 (Base58 Qm...) envelopes containing:
- Verified telemetry batch observations
- Zero-Knowledge range and location proofs
- AI Adversarial Forensics logs
- Merkle root tree structure
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(raw_bytes: bytes) -> str:
    """Standard Base58 encoding without external dependency."""
    n = int.from_bytes(raw_bytes, "big")
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(BASE58_ALPHABET[r])
    encoded = "".join(reversed(res))
    # Leading zeros padding
    pad = 0
    for b in raw_bytes:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + encoded


def compute_ipfs_cidv0(data: bytes) -> str:
    """Compute standard IPFS CIDv0 (Base58 multihash 0x12 0x20 + SHA-256)."""
    digest = hashlib.sha256(data).digest()
    multihash = b"\x12\x20" + digest
    return base58_encode(multihash)


class IPFSSerializer:
    """Packages and serializes climate epoch data into IPFS JSON artifacts."""

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = Path(storage_dir or ".agentsroom/ipfs")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def package_epoch(
        self,
        epoch_id: str,
        merkle_root: str,
        integrity_score: float,
        timestamp: int,
        verified_points: List[Dict[str, Any]],
        zk_proofs: List[Dict[str, Any]],
        audit_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Bundle and persist full epoch data to IPFS storage artifact."""
        payload = {
            "schema": "ClimateTrust-Epoch-v1",
            "epoch_id": epoch_id,
            "timestamp": timestamp,
            "merkle_root": merkle_root,
            "integrity_score": round(integrity_score, 4),
            "verified_count": len(verified_points),
            "zk_proofs_count": len(zk_proofs),
            "findings_count": len(audit_findings),
            "verified_telemetry": verified_points,
            "zero_knowledge_proofs": zk_proofs,
            "audit_findings": audit_findings,
        }

        canonical_json = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
        cid = compute_ipfs_cidv0(canonical_json)
        uri = f"ipfs://{cid}"

        target_file = self.storage_dir / f"{cid}.json"
        target_file.write_bytes(canonical_json)

        return {
            "cid": cid,
            "uri": uri,
            "file_path": str(target_file),
            "size_bytes": len(canonical_json),
            "payload": payload,
        }
