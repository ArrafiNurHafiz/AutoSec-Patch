import unittest
from autosec.polyglot import PolyglotTaintAnalyzer
from autosec.contract_validator import ContractValidator
from autosec.sandbox import EnterpriseWorktreeSandbox

class TestEnterpriseEngine(unittest.TestCase):
    def test_polyglot_detection_and_sinks(self):
        self.assertEqual(PolyglotTaintAnalyzer.detect_language("server.js"), "javascript")
        self.assertEqual(PolyglotTaintAnalyzer.detect_language("main.go"), "go")
        
        js_code = "app.get('/search', (req, res) => { db.raw(req.query.q); });"
        sinks = PolyglotTaintAnalyzer.extract_polyglot_sinks(js_code, "javascript")
        self.assertTrue(len(sinks) > 0)

    def test_contract_validator_preservation(self):
        orig = "def secure_call(user_id, token):\n    return True"
        good_patch = "def secure_call(user_id, token):\n    if not token: return False\n    return True"
        bad_patch = "def secure_call(user_id):\n    return True"

        ok_good, _ = ContractValidator.verify_invariant_preservation(orig, good_patch)
        ok_bad, msg = ContractValidator.verify_invariant_preservation(orig, bad_patch)

        self.assertTrue(ok_good)
        self.assertFalse(ok_bad)
        self.assertIn("Signature Mismatch", msg)

    def test_sandbox_timeout_guard(self):
        sandbox = EnterpriseWorktreeSandbox(".", timeout_seconds=2)
        passed, out = sandbox.execute_safe_command("python3 -c 'import time; time.sleep(4)'")
        self.assertFalse(passed)
        self.assertIn("EXECUTION_TIMEOUT", out)

if __name__ == "__main__":
    unittest.main()
