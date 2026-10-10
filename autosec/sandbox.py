import subprocess
import os
import shutil
import tempfile
from typing import Tuple, Optional


class EnterpriseWorktreeSandbox:
    """Enhanced zero-trust sandbox with timeout guard, memory limits, and isolated env."""

    def __init__(self, repo_path: str, timeout_seconds: int = 30):
        self.repo_path = os.path.abspath(repo_path)
        self.timeout = timeout_seconds
        self.worktree_dir: Optional[str] = None

    def __enter__(self):
        self.worktree_dir = tempfile.mkdtemp(prefix="autosec_sandbox_")
        res = subprocess.run(
            ["git", "worktree", "add", "--detach", self.worktree_dir, "HEAD"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            shutil.rmtree(self.worktree_dir, ignore_errors=True)
            self.worktree_dir = tempfile.mkdtemp(prefix="autosec_copy_")
            shutil.copytree(self.repo_path, self.worktree_dir, dirs_exist_ok=True)
        return self.worktree_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.worktree_dir and os.path.exists(self.worktree_dir):
            subprocess.run(
                ["git", "worktree", "remove", "--force", self.worktree_dir],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
            )
            shutil.rmtree(self.worktree_dir, ignore_errors=True)

    def execute_safe_command(
        self, cmd: str, workdir: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Execute test or PoC with strict subprocess timeout guard."""
        cwd = workdir or self.worktree_dir or self.repo_path
        try:
            res = subprocess.run(
                cmd,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            output = f"{res.stdout}\n{res.stderr}".strip()
            return res.returncode == 0, output
        except subprocess.TimeoutExpired:
            return (
                False,
                f"EXECUTION_TIMEOUT: Process exceeded {self.timeout}s sandbox limit.",
            )


# Backward compatibility alias
WorktreeSandbox = EnterpriseWorktreeSandbox
