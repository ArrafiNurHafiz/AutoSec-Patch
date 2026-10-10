import unittest
from autosec.cost_tracker import NebiusCostTracker


class TestCostTracker(unittest.TestCase):
    def test_cost_calculation(self):
        cost = NebiusCostTracker.calculate_cost(
            "nvidia/llama-3.1-nemotron-nano", 1000, 500
        )
        self.assertGreater(cost, 0.0)

    def test_mesh_savings(self):
        res = NebiusCostTracker.calculate_mesh_savings(
            nano_tokens=10000, super_tokens=5000, ultra_tokens=2000
        )
        self.assertGreater(res.cost_savings_vs_monolithic_pct, 50.0)
        self.assertEqual(res.prompt_tokens, 17000)


if __name__ == "__main__":
    unittest.main()
