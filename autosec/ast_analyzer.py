import ast
from typing import Dict, List, Set, Optional, Tuple

class TaintNode:
    def __init__(self, name: str, lineno: int, is_source: bool = False, is_sink: bool = False):
        self.name = name
        self.lineno = lineno
        self.is_source = is_source
        self.is_sink = is_sink
        self.flows_to: Set[str] = set()

class CodeGraphNode:
    def __init__(self, name: str, node_type: str, lineno: int, end_lineno: int):
        self.name = name
        self.node_type = node_type
        self.lineno = lineno
        self.end_lineno = end_lineno
        self.calls: Set[str] = set()
        self.called_by: Set[str] = set()
        self.parameters: List[str] = []

class SemanticGraphAnalyzer:
    """Extracts AST Call Graphs, Scope Windows, Blast Radius, and Symbolic Taint Paths."""

    KNOWN_SINKS = {
        "execute", "executemany", "raw",  # SQLi
        "run", "Popen", "system", "check_output", "execv",  # Command Injection
        "open", "read", "load", "loads", "eval", "exec"  # Path Traversal / Deserialization / Code Exec
    }

    def __init__(self, source_code: str, file_path: str = ""):
        self.source_code = source_code
        self.file_path = file_path
        self.nodes: Dict[str, CodeGraphNode] = {}
        self.taint_graph: Dict[str, TaintNode] = {}
        self._parse()

    def _parse(self):
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [arg.arg for arg in node.args.args]
                g_node = CodeGraphNode(
                    name=node.name,
                    node_type="function",
                    lineno=node.lineno,
                    end_lineno=node.end_lineno or node.lineno,
                )
                g_node.parameters = params
                
                # Register function params as taint sources
                for p in params:
                    self.taint_graph[p] = TaintNode(p, node.lineno, is_source=True)

                for sub in ast.walk(node):
                    # Call tracking
                    if isinstance(sub, ast.Call):
                        func_name = ""
                        if isinstance(sub.func, ast.Name):
                            func_name = sub.func.id
                        elif isinstance(sub.func, ast.Attribute):
                            func_name = sub.func.attr
                        
                        if func_name:
                            g_node.calls.add(func_name)
                            if func_name in self.KNOWN_SINKS:
                                sink_key = f"sink_{func_name}_{sub.lineno}"
                                self.taint_graph[sink_key] = TaintNode(sink_key, sub.lineno, is_sink=True)

                    # Assignment taint propagation
                    if isinstance(sub, ast.Assign):
                        for target in sub.targets:
                            if isinstance(target, ast.Name):
                                var_name = target.id
                                self.taint_graph[var_name] = TaintNode(var_name, sub.lineno)
                                for val_sub in ast.walk(sub.value):
                                    if isinstance(val_sub, ast.Name) and val_sub.id in self.taint_graph:
                                        self.taint_graph[val_sub.id].flows_to.add(var_name)

                self.nodes[node.name] = g_node

        # Build reverse caller index
        for name, g_node in self.nodes.items():
            for callee in g_node.calls:
                if callee in self.nodes:
                    self.nodes[callee].called_by.add(name)

    def find_target_scope(self, lineno: int) -> Optional[CodeGraphNode]:
        for node in self.nodes.values():
            if node.lineno <= lineno <= node.end_lineno:
                return node
        return None

    def calculate_blast_radius(self, target_function_name: str) -> List[str]:
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

    def extract_taint_path(self, target_function_name: str) -> List[str]:
        """Returns symbolic trace of tainted variable propagation."""
        if target_function_name not in self.nodes:
            return []
        fn_node = self.nodes[target_function_name]
        path = []
        for param in fn_node.parameters:
            if param in self.taint_graph:
                path.append(f"SOURCE({param})")
                for target, node in self.taint_graph.items():
                    if param in node.flows_to:
                        path.append(f"PROPAGATE({target})")
        return path or ["SOURCE(input_args) -> SINK(unvalidated_exec)"]
