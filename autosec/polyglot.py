import ast
import re
from typing import Dict, List, Set, Optional, Tuple

class PolyglotTaintAnalyzer:
    """Multi-language sink and scope analyzer (Python AST + JS/TS/Go Regex)."""

    LANG_SINKS = {
        "python": {"execute", "executemany", "raw", "run", "Popen", "system", "open", "eval", "exec"},
        "javascript": {"eval", "exec", "query", "raw", "execSync", "spawn", "readFile", "writeFileSync", "innerHTML"},
        "typescript": {"eval", "exec", "query", "raw", "execSync", "spawn", "readFile", "writeFileSync", "innerHTML"},
        "go": {"Exec", "Query", "QueryRow", "Command", "Open", "ReadFile"},
    }

    @classmethod
    def detect_language(cls, file_path: str) -> str:
        ext = file_path.split(".")[-1].lower() if "." in file_path else ""
        if ext in ("py", "pyw"):
            return "python"
        elif ext in ("js", "jsx", "mjs"):
            return "javascript"
        elif ext in ("ts", "tsx"):
            return "typescript"
        elif ext == "go":
            return "go"
        return "generic"

    @classmethod
    def extract_polyglot_sinks(cls, source_code: str, language: str) -> List[str]:
        sinks = cls.LANG_SINKS.get(language, cls.LANG_SINKS["python"])
        detected = []
        for line_no, line in enumerate(source_code.splitlines(), 1):
            for sink in sinks:
                if re.search(rf"\b{sink}\b", line):
                    detected.append(f"Line {line_no}: Sink '{sink}' -> {line.strip()[:60]}")
        return detected
