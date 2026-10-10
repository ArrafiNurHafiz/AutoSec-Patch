import os
import unittest
from autosec.parser import parse_sarif_or_json
from autosec.patcher import extract_patch_block
from autosec.client import NebiusNemotronClient


class TestAutoSecCore(unittest.TestCase):
    def test_parse_sarif(self):
        sample_path = os.path.join(
            os.path.dirname(__file__), "../examples/sample_sarif.json"
        )
        findings = parse_sarif_or_json(sample_path)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(
            f.rule_id, "python.lang.security.audit.sqli.sqlite-cursor-execute"
        )
        self.assertEqual(f.file_path, "examples/vulnerable_app.py")
        self.assertEqual(f.start_line, 13)
        self.assertEqual(f.cwe, "CWE-89")

    def test_extract_patch_block(self):
        model_output = """Here is the fix:
```patch
--- a/test.py
+++ b/test.py
@@ -1,1 +1,1 @@
-bad()
+good()
```
Hope this helps!"""
        diff = extract_patch_block(model_output)
        self.assertTrue(diff.startswith("--- a/test.py"))
        self.assertTrue(diff.endswith("+good()"))

    def test_mock_client(self):
        client = NebiusNemotronClient(api_key="")
        res = client.chat_completion([{"role": "user", "content": "fix"}])
        self.assertIn("--- a/vulnerable.py", res)

    def test_parse_sarif_resilience(self):
        # Invalid JSON
        self.assertEqual(parse_sarif_or_json("{invalid_json:"), [])
        # Missing file
        self.assertEqual(parse_sarif_or_json("non_existent_file.sarif"), [])
        # Non-dict / corrupted schema
        self.assertEqual(parse_sarif_or_json('{"runs": null}'), [])
        self.assertEqual(parse_sarif_or_json('{"runs": [{"results": "bad_data"}]}'), [])
        self.assertEqual(
            parse_sarif_or_json('{"runs": [{"tool": null, "results": [null]}]}'), []
        )
        # Direct list
        findings = parse_sarif_or_json('[{"rule_id": "TEST-1", "file_path": "a.py"}]')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "TEST-1")

    def test_client_retry_and_error_handling(self):
        # When connection fails or times out, client should retry and gracefully fallback
        client = NebiusNemotronClient(
            api_key="mock-key-for-test",
            base_url="http://127.0.0.1:59999",
            max_retries=1,
            retry_delay=0.01,
        )
        res = client.chat_completion([{"role": "user", "content": "test"}])
        self.assertIn("--- a/vulnerable.py", res)


if __name__ == "__main__":
    unittest.main()
