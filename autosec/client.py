import os
import json
import requests
from typing import Dict, Any, Optional

class NebiusNemotronClient:
    """Client for Nebius Token Factory serving NVIDIA Nemotron models."""

    DEFAULT_BASE_URL = "https://api.studio.nebius.ai/v1"
    DEFAULT_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("NEBIUS_API_KEY", "")
        self.base_url = (base_url or os.getenv("NEBIUS_BASE_URL", self.DEFAULT_BASE_URL)).rstrip("/")
        self.model = model or os.getenv("NEBIUS_MODEL", self.DEFAULT_MODEL)

    def chat_completion(self, messages: list, temperature: float = 0.1, max_tokens: int = 2048) -> str:
        """Call Nebius OpenAI-compatible Chat Completion API."""
        if not self.api_key:
            # ponytail: mock fallback for local testing without API key
            return self._mock_response(messages)

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        response = requests.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _mock_response(self, messages: list) -> str:
        """Fallback mock remediator when offline / testing."""
        user_content = messages[-1]["content"] if messages else ""
        return (
            "```patch\n"
            "--- a/vulnerable.py\n"
            "+++ b/vulnerable.py\n"
            "@@ -10,2 +10,2 @@\n"
            "-    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
            "+    query = \"SELECT * FROM users WHERE username = ?\"\n"
            "```"
        )
