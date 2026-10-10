import os
import subprocess
import tempfile
from typing import Tuple


def apply_patch(repo_path: str, patch_content: str) -> Tuple[bool, str]:
    """Apply a unified diff string to the target repository using git apply or patch command."""
    if not patch_content.strip():
        return False, "Empty patch content"

    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as tf:
        tf.write(patch_content + "\n")
        patch_file = tf.name

    try:
        # Try git apply first
        res = subprocess.run(
            ["git", "apply", "--whitespace=nowarn", patch_file],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            return True, "Patch applied successfully via git apply"

        # Fallback to patch utility
        res_patch = subprocess.run(
            ["patch", "-p1", "-i", patch_file],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )
        if res_patch.returncode == 0:
            return True, "Patch applied successfully via patch utility"

        return (
            False,
            f"Git apply error: {res.stderr}\nPatch tool error: {res_patch.stderr}",
        )
    finally:
        if os.path.exists(patch_file):
            os.remove(patch_file)


def run_tests(repo_path: str, test_cmd: str = "pytest") -> Tuple[bool, str]:
    """Execute test suite in the target repo to ensure no regressions."""
    res = subprocess.run(
        test_cmd,
        shell=True,
        cwd=repo_path,
        capture_output=True,
        text=True,
    )
    passed = res.returncode == 0
    output = f"{res.stdout}\n{res.stderr}".strip()
    return passed, output
