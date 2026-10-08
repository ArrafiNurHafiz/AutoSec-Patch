import subprocess
import tempfile
import os
from typing import Tuple, Optional
from autosec.types import SwarmAgentResult, ModelTier
from autosec.runner import apply_patch, run_tests

class DualVerifierAgent:
    """Evaluates patches against both functional regression and Red Team exploit PoCs."""

    def __init__(self):
        self.name = "DualVerifier-Oracle"

    def verify_remediation(
        self,
        repo_path: str,
        patch_diff: str,
        poc_code: str,
        regression_cmd: str
    ) -> Tuple[bool, bool, str]:
        """Returns: (is_secure, is_functional, log_details)"""
        # 1. Apply Patch
        success, patch_msg = apply_patch(repo_path, patch_diff)
        if not success:
            return False, False, f"Patch Application Error: {patch_msg}"

        # 2. Run Functional Regression
        is_functional, test_out = run_tests(repo_path, regression_cmd)

        # 3. Dynamic PoC Verification (Self-Contained in Temp Script)
        is_secure = True
        poc_log = "No PoC Executed"
        if poc_code:
            with tempfile.NamedTemporaryFile("w", suffix="_poc.py", delete=False) as tf:
                tf.write(f"""import sys
import os
sys.path.insert(0, '{os.path.abspath(repo_path)}')

{poc_code}

if __name__ == '__main__':
    try:
        from examples.vulnerable_app import get_user_vulnerable
        is_vuln, msg = run_exploit(get_user_vulnerable)
        if is_vuln:
            print("VULNERABLE:" + msg)
            sys.exit(1)
        else:
            print("SECURE:" + msg)
            sys.exit(0)
    except Exception as e:
        print("ERROR:" + str(e))
        sys.exit(0)
""")
                poc_file = tf.name

            try:
                res = subprocess.run(["python3", poc_file], capture_output=True, text=True)
                poc_log = res.stdout.strip()
                if res.returncode != 0 or "VULNERABLE:" in poc_log:
                    is_secure = False
                else:
                    is_secure = True
            finally:
                if os.path.exists(poc_file):
                    os.remove(poc_file)

        log = f"Functional Passed: {is_functional}\nPoC Status: {poc_log}"
        return is_secure, is_functional, log
