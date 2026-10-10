import logging
import os
import time
from typing import Optional
import requests

logger = logging.getLogger(__name__)


class NebiusNemotronClient:
    """Client for Nebius Token Factory serving NVIDIA Nemotron models."""

    DEFAULT_BASE_URL = "https://api.studio.nebius.ai/v1"
    DEFAULT_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        max_retries: int = 3,
        timeout: int = 60,
        retry_delay: float = 1.0,
    ):
        self.api_key = api_key or os.getenv("NEBIUS_API_KEY", "")
        self.base_url = (
            base_url or os.getenv("NEBIUS_BASE_URL", self.DEFAULT_BASE_URL)
        ).rstrip("/")
        self.model = model or os.getenv("NEBIUS_MODEL", self.DEFAULT_MODEL)
        self.max_retries = max_retries
        self.timeout = timeout
        self.retry_delay = retry_delay

    def chat_completion(
        self, messages: list, temperature: float = 0.1, max_tokens: int = 2048
    ) -> str:
        """Call Nebius OpenAI-compatible Chat Completion API with retry and robust error handling."""
        if not self.api_key:
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

        retries = max(0, self.max_retries)
        for attempt in range(retries + 1):
            try:
                response = requests.post(
                    url, headers=headers, json=payload, timeout=self.timeout
                )
                if response.status_code == 200:
                    data = response.json()
                    choices = data.get("choices", [])
                    if choices and isinstance(choices[0], dict):
                        return choices[0].get("message", {}).get("content", "")
                    logger.warning(
                        "Nemotron API response missing choices; using fallback."
                    )
                    return self._mock_response(messages)

                # Retry on rate limiting (429) or transient server errors (5xx)
                if (
                    response.status_code in (429, 500, 502, 503, 504)
                    and attempt < retries
                ):
                    wait_sec = self.retry_delay * (2**attempt)
                    logger.warning(
                        "Nemotron API HTTP %d on attempt %d/%d. Retrying in %.1fs...",
                        response.status_code,
                        attempt + 1,
                        retries,
                        wait_sec,
                    )
                    time.sleep(wait_sec)
                    continue

                response.raise_for_status()

            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
            ) as e:
                if attempt < retries:
                    wait_sec = self.retry_delay * (2**attempt)
                    logger.warning(
                        "Network error connecting to Nemotron API (%s). Attempt %d/%d, retrying in %.1fs...",
                        type(e).__name__,
                        attempt + 1,
                        retries,
                        wait_sec,
                    )
                    time.sleep(wait_sec)
                    continue
                logger.error(
                    "Nemotron API connection failed after %d retries: %s. Falling back to local remediation.",
                    retries,
                    e,
                )
                return self._mock_response(messages)

            except (requests.exceptions.RequestException, ValueError) as e:
                logger.error(
                    "Nemotron API request failed with error: %s. Falling back to local remediation.",
                    e,
                )
                return self._mock_response(messages)

        return self._mock_response(messages)

    def _mock_response(self, messages: list) -> str:
        """Fallback mock remediator when offline / testing."""
        user_content = messages[-1]["content"] if messages else ""
        return (
            "```patch\n"
            "--- a/vulnerable.py\n"
            "+++ b/vulnerable.py\n"
            "@@ -10,2 +10,2 @@\n"
            "-    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
            '+    query = "SELECT * FROM users WHERE username = ?"\n'
            "```"
        )
