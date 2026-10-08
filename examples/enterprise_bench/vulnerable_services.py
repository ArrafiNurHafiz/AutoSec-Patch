import subprocess
import os
from typing import Optional

def execute_system_command(user_input: str) -> str:
    """VULNERABLE: Direct command concatenation (CWE-78 / OS Command Injection)."""
    cmd = f"echo Ping target: {user_input}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout

def read_user_file(file_path: str) -> str:
    """VULNERABLE: Unsanitized path traversal (CWE-22 / Path Traversal)."""
    base_dir = "/tmp/sandbox"
    target = os.path.join(base_dir, file_path)
    try:
        with open(target, "r") as f:
            return f.read()
    except Exception as e:
        return str(e)
