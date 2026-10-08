import os
import unittest
from autosec.parser import parse_sarif_or_json
from autosec.patcher import extract_patch_block
from autosec.client import NebiusNemotronClient

class TestAutoSecCore(unittest.TestCase):
    def test_parse_sarif(self):
        sample_path = os.path.join(os.path.dirname(__file__), "../examples/sample_sarif.json")
        findings = parse_sarif_or_json(sample_path)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.rule_id, "python.lang.security.audit.sqli.sqlite-cursor-execute")
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

if __name__ == "__main__":
    unittest.main()
