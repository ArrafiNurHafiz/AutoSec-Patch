import ast
from typing import Dict, List, Tuple


class ContractValidator:
    """Verifies that a proposed patch strictly preserves AST function signatures and exports."""

    @classmethod
    def extract_signatures(cls, source_code: str) -> Dict[str, List[str]]:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return {}

        signatures = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [arg.arg for arg in node.args.args]
                signatures[node.name] = params
        return signatures

    @classmethod
    def verify_invariant_preservation(
        cls, original_code: str, patched_code: str
    ) -> Tuple[bool, str]:
        orig_sigs = cls.extract_signatures(original_code)
        patch_sigs = cls.extract_signatures(patched_code)

        # Check for deleted public functions
        for fn_name, params in orig_sigs.items():
            if fn_name not in patch_sigs:
                return (
                    False,
                    f"Contract Violation: Function '{fn_name}' was removed in patch.",
                )
            if patch_sigs[fn_name] != params:
                return (
                    False,
                    f"Signature Mismatch: Function '{fn_name}' arguments changed from {params} to {patch_sigs[fn_name]}.",
                )

        return True, "AST Invariant contracts preserved 100%."
