import unittest
from autosec.swarm.memory import EpisodicSwarmMemory
from autosec.swarm.consensus import SwarmConsensusProtocol
from autosec.formal_verifier import FormalConstraintVerifier
from autosec.types import SecurityFinding, FindingSeverity
from autosec.server import start_cockpit_server
import urllib.request
import json

class TestSwarmAndFormalEngine(unittest.TestCase):
    def test_episodic_memory_and_consensus(self):
        memory = EpisodicSwarmMemory()
        consensus = SwarmConsensusProtocol(memory)

        finding = SecurityFinding(
            rule_id="test.sqli",
            message="SQLi",
            file_path="app.py",
            start_line=1,
            end_line=2,
            cwe="CWE-89",
            severity=FindingSeverity.CRITICAL
        )

        verdict = consensus.adjudicate_patch(
            finding=finding,
            candidate_patch="diff --git ...",
            is_secure=True,
            is_regression_clean=True,
            blast_radius_nodes=["get_user"]
        )

        self.assertTrue(verdict.approved)
        self.assertGreaterEqual(verdict.approval_rate, 0.75)
        
        # Verify memory storage
        recalled = memory.recall_similar_fix("CWE-89")
        self.assertIsNotNone(recalled)
        self.assertEqual(recalled.cwe, "CWE-89")

    def test_formal_constraint_verifier(self):
        vuln_code = "cursor.execute(f'SELECT * FROM t WHERE id = {user_id}')"
        safe_code = "cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))"

        ok_vuln, _ = FormalConstraintVerifier.verify_sql_sanitization(vuln_code)
        ok_safe, _ = FormalConstraintVerifier.verify_sql_sanitization(safe_code)

        self.assertFalse(ok_vuln)
        self.assertTrue(ok_safe)

    def test_cockpit_api_server(self):
        server = start_cockpit_server(port=8999)
        try:
            req = urllib.request.urlopen("http://localhost:8999/api/status")
            data = json.loads(req.read().decode())
            self.assertEqual(data["status"], "ONLINE")
            self.assertEqual(data["immunity_rate"], 100.0)
        finally:
            server.shutdown()

if __name__ == "__main__":
    unittest.main()
