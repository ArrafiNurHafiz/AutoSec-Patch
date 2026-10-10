import unittest
from autosec.risk_prioritizer import DynamicRiskPrioritizer
from autosec.types import SecurityFinding, FindingSeverity
from autosec.tree_patcher import TreeOfThoughtPatcher


class TestNextGenFeatures(unittest.TestCase):
    def test_risk_prioritizer_composite_score(self):
        finding = SecurityFinding(
            rule_id="test.sqli",
            message="SQLi",
            file_path="app.py",
            start_line=10,
            end_line=12,
            cwe="CWE-89",
            severity=FindingSeverity.CRITICAL,
        )
        profile = DynamicRiskPrioritizer.calculate_risk(
            finding, call_depth=1, epss_score=0.85
        )
        self.assertGreaterEqual(profile.composite_score, 8.0)
        self.assertIn("P0", profile.priority_level)
        self.assertTrue(profile.is_externally_reachable)

    def test_tree_of_thought_patcher_selection(self):
        finding = SecurityFinding(
            rule_id="rules.python.security.sqli",
            message="SQL injection",
            file_path="app.py",
            start_line=5,
            end_line=6,
            cwe="CWE-89",
        )
        sample_code = "def get_user(conn, username):\n    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    return conn.execute(query).fetchall()"

        tot = TreeOfThoughtPatcher()
        best_candidate = tot.explore_patch_tree(finding, sample_code, ["get_user"])

        self.assertIsNotNone(best_candidate)
        self.assertTrue(best_candidate.invariants_preserved)
        self.assertGreaterEqual(best_candidate.confidence_score, 0.90)
        self.assertIn(
            "SELECT * FROM users WHERE username = ?", best_candidate.patch_diff
        )


if __name__ == "__main__":
    unittest.main()
