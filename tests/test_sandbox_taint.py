import unittest
import os
from autosec.sandbox import WorktreeSandbox
from autosec.ast_analyzer import SemanticGraphAnalyzer

SAMPLE_TAINT_CODE = """
import sqlite3

def query_handler(user_input):
    formatted = f"SELECT * FROM tbl WHERE name = '{user_input}'"
    conn = sqlite3.connect(":memory:")
    return conn.execute(formatted).fetchall()
"""

class TestUpgradedFeatures(unittest.TestCase):
    def test_taint_path_extraction(self):
        analyzer = SemanticGraphAnalyzer(SAMPLE_TAINT_CODE)
        taint = analyzer.extract_taint_path("query_handler")
        self.assertTrue(any("SOURCE" in t for t in taint))

    def test_worktree_sandbox_lifecycle(self):
        with WorktreeSandbox(".") as sb_dir:
            self.assertTrue(os.path.exists(sb_dir))
            # Create a test file inside sandbox
            test_file = os.path.join(sb_dir, "temp_sandbox_file.txt")
            with open(test_file, "w") as f:
                f.write("sandboxed content")
            self.assertTrue(os.path.exists(test_file))
        # Verify sandbox cleanup
        self.assertFalse(os.path.exists(sb_dir))

if __name__ == "__main__":
    unittest.main()
