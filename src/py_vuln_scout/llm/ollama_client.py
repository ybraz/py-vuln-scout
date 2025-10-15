"""Ollama API client with retries and caching."""

import json
import time
from typing import Any

import requests

from py_vuln_scout.cache.disk_cache import DiskCache


class OllamaClient:
    """Client for interacting with Ollama API."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "qwen2.5-coder:7b",
        timeout: int = 120,
        max_retries: int = 3,
        cache_enabled: bool = True,
    ) -> None:
        """Initialize Ollama client.

        Args:
            base_url: Ollama API base URL
            model: Model name to use
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            cache_enabled: Whether to enable response caching
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache = DiskCache() if cache_enabled else None

    def generate(
        self,
        prompt: str,
        temperature: float = 0.0,
        max_tokens: int = 512,
        stream: bool = False,
    ) -> str:
        """Generate completion using Ollama.

        Args:
            prompt: Input prompt
            temperature: Sampling temperature (0.0 = deterministic)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response (not implemented)

        Returns:
            Generated text response

        Raises:
            OllamaError: If the request fails after retries
        """
        # Check cache first
        if self.cache and temperature == 0.0:  # Only cache deterministic responses
            cached = self.cache.get(prompt, self.model, temperature)
            if cached:
                return cached

        # Make API request with retries
        for attempt in range(self.max_retries):
            try:
                response = self._make_request(prompt, temperature, max_tokens)

                # Cache successful response
                if self.cache and temperature == 0.0:
                    self.cache.set(prompt, self.model, temperature, response)

                return response

            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    raise OllamaError(f"Failed after {self.max_retries} attempts: {e}") from e

                # Exponential backoff
                wait_time = 2**attempt
                time.sleep(wait_time)

        raise OllamaError("Unexpected error in retry loop")

    def _make_request(self, prompt: str, temperature: float, max_tokens: int) -> str:
        """Make a single API request to Ollama.

        Args:
            prompt: Input prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text response

        Raises:
            requests.exceptions.RequestException: If the request fails
        """
        url = f"{self.base_url}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        response = requests.post(
            url,
            json=payload,
            timeout=self.timeout,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

        data = response.json()
        return data.get("response", "")

    def validate_json_response(self, response: str) -> dict[str, Any] | None:
        """Validate and parse JSON response from LLM.

        Args:
            response: Raw LLM response

        Returns:
            Parsed JSON dict, or None if invalid
        """
        # Try to extract JSON from markdown code blocks
        response = response.strip()

        # Remove markdown code fences if present
        if response.startswith("```json"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]

        if response.endswith("```"):
            response = response[:-3]

        response = response.strip()

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return None


class OllamaError(Exception):
    """Exception raised for Ollama API errors."""

    pass
