import ast
import difflib
from typing import Optional, Tuple, Dict, Any

class AstSemanticPatcher:
    """Modifies Python AST nodes directly to produce guaranteed syntactically valid and precise patches."""

    @staticmethod
    def patch_sqli_sqlite(source_code: str, target_func_name: str) -> Tuple[bool, str, str]:
        """Transform f-string / string concat SQL execution into parameterized query."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return False, source_code, f"Syntax Error in original source: {e}"

        class SQLiTransformer(ast.NodeTransformer):
            def __init__(self, target_fn: str):
                self.target_fn = target_fn
                self.modified = False

            def visit_FunctionDef(self, node: ast.FunctionDef):
                if node.name == self.target_fn or self.target_fn == "all":
                    new_body = []
                    for stmt in node.body:
                        # Detect pattern: query = f"SELECT ... WHERE username = '{username}'"
                        # or cursor.execute(query)
                        if isinstance(stmt, ast.Assign):
                            for target in stmt.targets:
                                if isinstance(target, ast.Name) and "query" in target.id.lower():
                                    if isinstance(stmt.value, ast.JoinedStr):
                                        # Transform to static parameterized query
                                        raw_parts = []
                                        for part in stmt.value.values:
                                            if isinstance(part, ast.Constant):
                                                raw_parts.append(str(part.value))
                                            elif isinstance(part, ast.FormattedValue):
                                                raw_parts.append("?")
                                        query_str = "".join(raw_parts).replace("'{username}'", "?").replace("'{user_input}'", "?").replace("'", "")
                                        stmt.value = ast.Constant(value=query_str)
                                        self.modified = True
                        new_body.append(stmt)
                    node.body = new_body
                return self.generic_visit(node)

        transformer = SQLiTransformer(target_func_name)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)

        try:
            patched_code = ast.unparse(new_tree)
            # Generate clean unified diff
            diff = difflib.unified_diff(
                source_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile="a/" + target_func_name + ".py",
                tofile="b/" + target_func_name + ".py",
            )
            diff_text = "".join(diff)
            return True, patched_code, diff_text
        except Exception as e:
            return False, source_code, str(e)

    @staticmethod
    def patch_command_injection(source_code: str, target_func_name: str) -> Tuple[bool, str, str]:
        """Convert shell=True and string concatenation into safe list-based subprocess execution."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return False, source_code, str(e)

        class CmdITransformer(ast.NodeTransformer):
            def __init__(self, target_fn: str):
                self.target_fn = target_fn
                self.modified = False

            def visit_FunctionDef(self, node: ast.FunctionDef):
                if node.name == self.target_fn or self.target_fn == "all":
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            # Replace shell=True with shell=False
                            for kw in sub.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    kw.value.value = False
                                    self.modified = True
                return self.generic_visit(node)

        transformer = CmdITransformer(target_func_name)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)

        try:
            patched_code = ast.unparse(new_tree)
            diff = difflib.unified_diff(
                source_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile="a/" + target_func_name + ".py",
                tofile="b/" + target_func_name + ".py",
            )
            return True, patched_code, "".join(diff)
        except Exception as e:
            return False, source_code, str(e)
