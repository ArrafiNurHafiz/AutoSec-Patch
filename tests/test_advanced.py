import os
import unittest
from autosec.ast_analyzer import SemanticGraphAnalyzer
from autosec.router import ModelMeshRouter
from autosec.types import ModelTier, SecurityFinding
from autosec.engine import CoEvolutionEngine
from autosec.reporter import generate_interactive_html_dashboard

SAMPLE_CODE = """
import sqlite3

def helper_query(query):
    return query

def get_user_data(conn, username):
    q = helper_query(f"SELECT * FROM users WHERE username = '{username}'")
    return conn.execute(q).fetchone()

def main():
    conn = sqlite3.connect(":memory:")
    get_user_data(conn, "admin")
"""

class TestAutoSecAdvanced(unittest.TestCase):
    def test_ast_call_graph_and_scope(self):
        analyzer = SemanticGraphAnalyzer(SAMPLE_CODE)
        scope = analyzer.find_target_scope(8)
        self.assertIsNotNone(scope)
        self.assertEqual(scope.name, "get_user_data")

        # Blast radius of get_user_data should include caller 'main'
        blast = analyzer.calculate_blast_radius("get_user_data")
        self.assertIn("main", blast)
        self.assertIn("get_user_data", blast)

    def test_model_mesh_routing(self):
        router = ModelMeshRouter()
        self.assertEqual(router.route_agent_task("triage"), ModelTier.NANO.value)
        self.assertEqual(router.route_agent_task("red_team_exploit"), ModelTier.ULTRA.value)
        self.assertEqual(router.route_agent_task("blue_team_patch"), ModelTier.SUPER.value)

    def test_coevolution_engine_end_to_end(self):
        engine = CoEvolutionEngine(repo_path=".")
        results = engine.process_sarif("examples/sample_sarif.json", test_cmd="python3 -m unittest examples/test_vulnerable.py")
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertTrue(r.regression_passed)
        self.assertGreater(len(r.timeline), 0)

    def test_report_generation(self):
        engine = CoEvolutionEngine(repo_path=".")
        results = engine.process_sarif("examples/sample_sarif.json", test_cmd="python3 -m unittest examples/test_vulnerable.py")
        report_path = generate_interactive_html_dashboard(results, output_path="test_dashboard.html")
        self.assertTrue(os.path.exists(report_path))
        if os.path.exists("test_dashboard.html"):
            os.remove("test_dashboard.html")

if __name__ == "__main__":
    unittest.main()
