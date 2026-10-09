"""Cryptographic primitives, EVM-compliant Keccak-256 Merkle Tree, and ECDSA signature engine for ClimateTrust."""

import json
from typing import List, Dict, Tuple, Optional, Union
from eth_hash.auto import keccak
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from climatetrust.types import TelemetryPoint


def keccak256_bytes(data: bytes) -> bytes:
    """Compute standard Ethereum Keccak-256 cryptographic digest returning 32 raw bytes."""
    return keccak(data)


def keccak256_hex(data: bytes) -> str:
    """Compute standard Ethereum Keccak-256 cryptographic digest returning 0x-prefixed hex string."""
    return f"0x{keccak(data).hex()}"


def to_bytes32(val: Union[str, bytes]) -> bytes:
    """Convert 0x-prefixed hex string or raw bytes to 32 bytes."""
    if isinstance(val, str):
        clean_hex = val[2:] if val.startswith("0x") or val.startswith("0X") else val
        b = bytes.fromhex(clean_hex)
    else:
        b = val
    if len(b) != 32:
        raise ValueError(f"Expected 32 bytes, got {len(b)} bytes: {val}")
    return b


def hash_telemetry_point(point: TelemetryPoint) -> str:
    """Deterministic Ethereum Keccak-256 hash of a verified telemetry observation."""
    serialized = json.dumps({
        "station_id": point.station_id,
        "timestamp": point.timestamp,
        "latitude": round(point.latitude, 5),
        "longitude": round(point.longitude, 5),
        "co2_ppm": round(point.co2_ppm, 2),
        "ch4_ppb": round(point.ch4_ppb, 2),
        "pm25_ugm3": round(point.pm25_ugm3, 2),
    }, sort_keys=True)
    return keccak256_hex(serialized.encode("utf-8"))


class MerkleTree:
    """EVM-compliant Binary Merkle Tree implementation using raw 32-byte concatenation and Keccak-256.
    
    Compatible with OpenZeppelin MerkleProof.sol and ClimateTrustOracle.sol.
    """

    def __init__(self, leaves: List[Union[str, bytes]]):
        if not leaves:
            raise ValueError("Cannot construct MerkleTree with empty leaves list.")
        # Store leaves as raw 32-byte arrays
        self.raw_leaves: List[bytes] = [to_bytes32(leaf) for leaf in leaves]
        self.raw_layers: List[List[bytes]] = [self.raw_leaves]
        self._build_tree()

    def _build_tree(self) -> None:
        current_layer = self.raw_leaves
        while len(current_layer) > 1:
            next_layer: List[bytes] = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                if i + 1 < len(current_layer):
                    right = current_layer[i + 1]
                else:
                    right = left  # Duplicate last leaf if odd count

                # OpenZeppelin sorting rule: abi.encodePacked(min(a,b), max(a,b))
                combined = min(left, right) + max(left, right)
                parent = keccak256_bytes(combined)
                next_layer.append(parent)
            self.raw_layers.append(next_layer)
            current_layer = next_layer

    @property
    def root(self) -> str:
        """The Merkle Root hash formatted as 0x-prefixed hex string."""
        return f"0x{self.raw_layers[-1][0].hex()}"

    @property
    def root_bytes(self) -> bytes:
        """The Merkle Root hash as raw 32 bytes."""
        return self.raw_layers[-1][0]

    def get_proof(self, leaf_index: int) -> List[str]:
        """Generate audit proof path for a specific leaf index (0x-prefixed hex strings)."""
        if leaf_index < 0 or leaf_index >= len(self.raw_leaves):
            raise IndexError("Leaf index out of bounds.")

        proof: List[str] = []
        idx = leaf_index
        for layer in self.raw_layers[:-1]:
            is_right_child = (idx % 2 == 1)
            pair_idx = idx - 1 if is_right_child else idx + 1
            if pair_idx < len(layer):
                proof.append(f"0x{layer[pair_idx].hex()}")
            else:
                proof.append(f"0x{layer[idx].hex()}")
            idx = idx // 2
        return proof

    @staticmethod
    def verify_proof(
        leaf: Union[str, bytes],
        proof: List[Union[str, bytes]],
        root: Union[str, bytes]
    ) -> bool:
        """Cryptographically verify leaf inclusion proof against root using OpenZeppelin/EVM rules."""
        current = to_bytes32(leaf)
        target_root = to_bytes32(root)

        for sibling_item in proof:
            sibling = to_bytes32(sibling_item)
            # Match Solidity: if (computedHash <= proofElement) ...
            combined = min(current, sibling) + max(current, sibling)
            current = keccak256_bytes(combined)

        return current == target_root


class OracleSigner:
    """ECDSA Oracle cryptographic signing service."""

    def __init__(self, private_key: Optional[ec.EllipticCurvePrivateKey] = None):
        self.private_key = private_key or ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def sign_attestation(self, epoch_id: str, merkle_root: str, integrity_score: float, timestamp: int) -> str:
        """Sign attestation payload with Oracle ECDSA key."""
        payload = f"{epoch_id}:{merkle_root}:{integrity_score:.4f}:{timestamp}".encode("utf-8")
        signature = self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        return f"0x{signature.hex()}"
