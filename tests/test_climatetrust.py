"""Unit and integration test suite for ClimateTrust AI Oracle (using unittest)."""

import unittest
from climatetrust.types import (
    TelemetryPoint,
    AttackType,
    VerificationStatus,
    AttestationReport,
)
from climatetrust.telemetry import ClimateTelemetryGenerator
from climatetrust.detector import (
    SpatialTemporalAnomalyDetector,
    AtmosphericPhysicsVerifier,
    EntropyAndReplayDetector,
)
from climatetrust.engine import ClimateTrustEngine
from climatetrust.crypto import MerkleTree, OracleSigner, hash_telemetry_point
from climatetrust.blockchain import BlockchainConnector
from climatetrust.reporter import ClimateDashboardReporter


class TestClimateTrust(unittest.TestCase):

    def test_telemetry_generation(self):
        generator = ClimateTelemetryGenerator(seed=123)
        points = generator.generate_epoch_telemetry(
            samples_per_cluster=3, inject_attacks=True
        )
        self.assertEqual(len(points), 9)
        self.assertTrue(any(p.attack_injected != AttackType.NONE for p in points))
        for p in points:
            self.assertGreater(p.co2_ppm, 0)
            self.assertGreater(p.ch4_ppb, 0)
            self.assertGreater(p.pm25_ugm3, 0)

    def test_spatial_anomaly_detector(self):
        detector = SpatialTemporalAnomalyDetector()
        points = [
            TelemetryPoint(
                station_id=f"STN-{i}",
                timestamp=1000,
                latitude=40.71,
                longitude=-74.00,
                co2_ppm=420.0,
                ch4_ppb=1800.0,
                pm25_ugm3=10.0,
                temperature_c=20.0,
                humidity_pct=50.0,
                source_api="test",
            )
            for i in range(4)
        ]
        outlier = TelemetryPoint(
            station_id="STN-OUTLIER",
            timestamp=1000,
            latitude=40.711,
            longitude=-74.001,
            co2_ppm=650.0,
            ch4_ppb=1800.0,
            pm25_ugm3=10.0,
            temperature_c=20.0,
            humidity_pct=50.0,
            source_api="test",
        )
        points.append(outlier)

        findings = detector.audit_spatial_coherence(points)
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any(f.station_id == "STN-OUTLIER" for f in findings))
        self.assertEqual(findings[0].rule_name, "SPATIAL_NEIGHBORHOOD_DIVERGENCE")

    def test_combustion_physics_detector(self):
        verifier = AtmosphericPhysicsVerifier()
        fraud_point = TelemetryPoint(
            station_id="STN-FRAUD",
            timestamp=1000,
            latitude=40.71,
            longitude=-74.00,
            co2_ppm=410.0,
            ch4_ppb=2350.0,
            pm25_ugm3=45.0,
            temperature_c=20.0,
            humidity_pct=50.0,
            source_api="test",
        )
        findings = verifier.audit_combustion_covariance([fraud_point])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "COMBUSTION_DECOUPLING_UNDER_REPORTING")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_entropy_detector(self):
        detector = EntropyAndReplayDetector()
        synthetic_point = TelemetryPoint(
            station_id="STN-FLAT",
            timestamp=1000,
            latitude=40.71,
            longitude=-74.00,
            co2_ppm=420.0,
            ch4_ppb=1900.0,
            pm25_ugm3=15.0,
            temperature_c=22.0,
            humidity_pct=50.0,
            source_api="test",
        )
        findings = detector.audit_entropy_and_flatlines([synthetic_point])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "SYNTHETIC_ZERO_ENTROPY_PAYLOAD")

    def test_merkle_tree_proof_verification(self):
        leaves = [f"0x{i:064x}" for i in range(1, 9)]
        tree = MerkleTree(leaves)
        self.assertTrue(tree.root.startswith("0x"))

        leaf_to_prove = leaves[3]
        proof = tree.get_proof(3)
        self.assertGreater(len(proof), 0)
        self.assertTrue(MerkleTree.verify_proof(leaf_to_prove, proof, tree.root))

        fake_leaf = "0x" + "f" * 64
        self.assertFalse(MerkleTree.verify_proof(fake_leaf, proof, tree.root))

    def test_evm_solidity_merkle_compatibility(self):
        """Verify byte-for-byte equivalence with Solidity's abi.encodePacked(min(a,b), max(a,b)) and keccak256."""
        from eth_hash.auto import keccak

        l0 = keccak(b"test-telemetry-node-0")
        l1 = keccak(b"test-telemetry-node-1")
        expected_solidity_parent = keccak(min(l0, l1) + max(l0, l1))

        tree = MerkleTree([l0, l1])
        self.assertEqual(tree.root_bytes, expected_solidity_parent)
        self.assertEqual(tree.root, "0x" + expected_solidity_parent.hex())
        self.assertTrue(MerkleTree.verify_proof(l0, tree.get_proof(0), tree.root))
        self.assertTrue(MerkleTree.verify_proof(l1, tree.get_proof(1), tree.root))

    def test_blockchain_connector(self):
        connector = BlockchainConnector()
        generator = ClimateTelemetryGenerator(seed=42)
        engine = ClimateTrustEngine()

        # When samples_per_cluster=5 (15 samples, 3 attacks -> 80% integrity score)
        points = generator.generate_epoch_telemetry(
            samples_per_cluster=5, inject_attacks=True
        )
        verified, rejected, findings, score = engine.audit_epoch(points)

        leaves = [hash_telemetry_point(p) for p in verified]
        tree = MerkleTree(leaves)
        signer = OracleSigner()
        sig = signer.sign_attestation("EPOCH-TEST", tree.root, score, 1000)

        report = AttestationReport(
            epoch_id="EPOCH-TEST",
            timestamp=1000,
            total_samples=len(points),
            verified_samples=len(verified),
            rejected_samples=len(rejected),
            overall_integrity_score=score,
            status=VerificationStatus.VERIFIED,
            merkle_root=tree.root,
            oracle_signature=sig,
            findings=findings,
            telemetry_samples=points,
        )

        receipt = connector.submit_attestation(report)
        self.assertEqual(receipt["status"], "CONFIRMED")
        self.assertGreater(receipt["block_number"], 0)
        self.assertTrue(receipt["tx_hash"].startswith("0x"))

        # Verify inclusion on chain
        leaf_0 = leaves[0]
        proof_0 = tree.get_proof(0)
        self.assertTrue(connector.verify_leaf_on_chain("EPOCH-TEST", leaf_0, proof_0))

        # Test threshold rejection (< 80% score)
        low_score_report = AttestationReport(
            epoch_id="EPOCH-LOW",
            timestamp=1000,
            total_samples=10,
            verified_samples=6,
            rejected_samples=4,
            overall_integrity_score=0.60,
            status=VerificationStatus.REJECTED_TAMPERED,
            merkle_root=tree.root,
            oracle_signature=sig,
            findings=findings,
            telemetry_samples=[],
        )
        reverted_receipt = connector.submit_attestation(low_score_report)
        self.assertEqual(reverted_receipt["status"], "REVERTED")
        self.assertIn("below consensus threshold", reverted_receipt["revert_reason"])

    def test_dashboard_generation(self):
        generator = ClimateTelemetryGenerator(seed=42)
        engine = ClimateTrustEngine()
        points = generator.generate_epoch_telemetry(
            samples_per_cluster=2, inject_attacks=True
        )
        verified, rejected, findings, score = engine.audit_epoch(points)
        leaves = [hash_telemetry_point(p) for p in verified]
        tree = MerkleTree(leaves)
        signer = OracleSigner()
        sig = signer.sign_attestation("EPOCH-HTML", tree.root, score, 1000)

        report = AttestationReport(
            epoch_id="EPOCH-HTML",
            timestamp=1000,
            total_samples=len(points),
            verified_samples=len(verified),
            rejected_samples=len(rejected),
            overall_integrity_score=score,
            status=VerificationStatus.VERIFIED,
            merkle_root=tree.root,
            oracle_signature=sig,
            findings=findings,
            telemetry_samples=points,
        )
        connector = BlockchainConnector()
        receipt = connector.submit_attestation(report)

        html = ClimateDashboardReporter.generate_html(report, receipt)
        self.assertIn("<title>ClimateTrust AI Oracle - Cockpit Dashboard</title>", html)
        self.assertIn("ClimateChain 2026", html)
        self.assertIn(report.merkle_root, html)

    def test_zk_climate_proof_generation_and_verification(self):
        from climatetrust.zk import ZKClimateProver

        point = TelemetryPoint(
            station_id="STN-ZK-01",
            timestamp=1000,
            latitude=40.71,
            longitude=-74.00,
            co2_ppm=430.0,
            ch4_ppb=1850.0,
            pm25_ugm3=12.0,
            temperature_c=21.0,
            humidity_pct=52.0,
            source_api="test",
        )
        proof = ZKClimateProver.generate_zk_proof(point, region_id="REGION-US-EAST")
        self.assertTrue(proof["is_region_valid"])
        self.assertTrue(proof["is_emissions_compliant"])
        self.assertTrue(ZKClimateProver.verify_zk_proof(proof))

        # Tampered proof challenge should fail verification
        tampered_proof = dict(proof)
        tampered_proof["challenge"] = "0x" + "0" * 64
        self.assertFalse(ZKClimateProver.verify_zk_proof(tampered_proof))

    def test_ipfs_serialization_and_cid(self, tmp_path=None):
        from climatetrust.ipfs import IPFSSerializer

        serializer = IPFSSerializer(storage_dir="/tmp/test_ipfs_climatetrust")
        res = serializer.package_epoch(
            epoch_id="EPOCH-IPFS-TEST",
            merkle_root="0x" + "a" * 64,
            integrity_score=0.95,
            timestamp=1000,
            verified_points=[{"station_id": "STN-01", "co2": 420.0}],
            zk_proofs=[{"proof_protocol": "Groth16"}],
            audit_findings=[],
        )
        self.assertTrue(res["cid"].startswith("Qm"))
        self.assertEqual(len(res["cid"]), 46)
        self.assertTrue(res["uri"].startswith("ipfs://Qm"))
        self.assertGreater(res["size_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
