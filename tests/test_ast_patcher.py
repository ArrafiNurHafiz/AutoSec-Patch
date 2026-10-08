import unittest
from autosec.ast_patcher import AstSemanticPatcher

VULN_PYTHON_SQL = """import sqlite3

def get_user(conn, username):
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    return conn.cursor().execute(query).fetchone()
"""

VULN_PYTHON_CMD = """import subprocess

def run_ping(ip_address):
    res = subprocess.run(f"ping -c 1 {ip_address}", shell=True, capture_output=True)
    return res.stdout
"""

class TestAstSemanticPatcher(unittest.TestCase):
    def test_patch_sqli_sqlite(self):
        ok, patched_code, diff = AstSemanticPatcher.patch_sqli_sqlite(VULN_PYTHON_SQL, "get_user")
        self.assertTrue(ok)
        self.assertIn("SELECT id, username FROM users WHERE username = ?", patched_code)
        self.assertIn("-    query = f\"SELECT id, username FROM users WHERE username = '{username}'\"", diff)

    def test_patch_command_injection(self):
        ok, patched_code, diff = AstSemanticPatcher.patch_command_injection(VULN_PYTHON_CMD, "run_ping")
        self.assertTrue(ok)
        self.assertIn("shell=False", patched_code)

if __name__ == "__main__":
    unittest.main()
