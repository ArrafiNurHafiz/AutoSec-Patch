from dataclasses import dataclass


@dataclass
class TokenCostEstimate:
    prompt_tokens: int
    completion_tokens: int
    estimated_cost_usd: float
    cost_savings_vs_monolithic_pct: float


class NebiusCostTracker:
    """Calculates Token Factory inference costs and optimization savings."""

    # Pricing per 1M tokens (est. standard benchmark)
    PRICING = {
        "nvidia/llama-3.1-nemotron-nano": {"prompt": 0.05, "completion": 0.15},
        "nvidia/llama-3.1-nemotron-70b-instruct": {"prompt": 0.35, "completion": 0.90},
        "nvidia/nemotron-3-ultra": {"prompt": 1.20, "completion": 3.50},
    }

    @classmethod
    def calculate_cost(
        cls, model: str, prompt_tokens: int, completion_tokens: int
    ) -> float:
        rates = cls.PRICING.get(model, {"prompt": 0.5, "completion": 1.0})
        return (
            prompt_tokens * rates["prompt"] + completion_tokens * rates["completion"]
        ) / 1_000_000

    @classmethod
    def calculate_mesh_savings(
        cls, nano_tokens: int, super_tokens: int, ultra_tokens: int
    ) -> TokenCostEstimate:
        actual_cost = (
            cls.calculate_cost(
                "nvidia/llama-3.1-nemotron-nano", nano_tokens, nano_tokens // 2
            )
            + cls.calculate_cost(
                "nvidia/llama-3.1-nemotron-70b-instruct",
                super_tokens,
                super_tokens // 2,
            )
            + cls.calculate_cost(
                "nvidia/nemotron-3-ultra", ultra_tokens, ultra_tokens // 2
            )
        )
        total_tokens = nano_tokens + super_tokens + ultra_tokens
        # Monolithic naive cost: routing all calls directly to Nemotron-Ultra
        monolithic_cost = cls.calculate_cost(
            "nvidia/nemotron-3-ultra", total_tokens, total_tokens // 2
        )
        savings_pct = (
            ((monolithic_cost - actual_cost) / monolithic_cost * 100)
            if monolithic_cost > 0
            else 0.0
        )

        return TokenCostEstimate(
            prompt_tokens=total_tokens,
            completion_tokens=total_tokens // 2,
            estimated_cost_usd=round(actual_cost, 5),
            cost_savings_vs_monolithic_pct=round(savings_pct, 2),
        )
