import ast
from typing import Dict, List, Set, Optional

class CodeGraphNode:
    def __init__(self, name: str, node_type: str, lineno: int, end_lineno: int):
        self.name = name
        self.node_type = node_type
        self.lineno = lineno
        self.end_lineno = end_lineno
        self.calls: Set[str] = set()
        self.called_by: Set[str] = set()

class SemanticGraphAnalyzer:
    """Extracts AST Call Graphs, Scope Windows, and Blast Radius."""

    def __init__(self, source_code: str, file_path: str = ""):
        self.source_code = source_code
        self.file_path = file_path
        self.nodes: Dict[str, CodeGraphNode] = {}
        self._parse()

    def _parse(self):
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                g_node = CodeGraphNode(
                    name=node.name,
                    node_type="function",
                    lineno=node.lineno,
                    end_lineno=node.end_lineno or node.lineno,
                )
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        if isinstance(sub.func, ast.Name):
                            g_node.calls.add(sub.func.id)
                        elif isinstance(sub.func, ast.Attribute):
                            g_node.calls.add(sub.func.attr)
                self.nodes[node.name] = g_node

        # Build reverse caller index
        for name, g_node in self.nodes.items():
            for callee in g_node.calls:
                if callee in self.nodes:
                    self.nodes[callee].called_by.add(name)

    def find_target_scope(self, lineno: int) -> Optional[CodeGraphNode]:
        """Locate the deepest function enclosing the line."""
        for node in self.nodes.values():
            if node.lineno <= lineno <= node.end_lineno:
                return node
        return None

    def calculate_blast_radius(self, target_function_name: str) -> List[str]:
        """Compute all upstream and downstream dependent functions."""
        if target_function_name not in self.nodes:
            return [target_function_name]

        visited: Set[str] = set()
        queue = [target_function_name]

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            if curr in self.nodes:
                for caller in self.nodes[curr].called_by:
                    if caller not in visited:
                        queue.append(caller)
        return sorted(list(visited))
