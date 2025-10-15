"""Disk-based caching for LLM responses."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any


class DiskCache:
    """Simple disk-based cache for LLM responses."""

    def __init__(self, cache_dir: str = ".pvs_cache") -> None:
        """Initialize the cache.

        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, prompt: str, model: str, temperature: float) -> str:
        """Generate a cache key from prompt and parameters.

        Args:
            prompt: LLM prompt
            model: Model name
            temperature: Temperature parameter

        Returns:
            SHA256 hash as cache key
        """
        composite = f"{model}:{temperature}:{prompt}"
        return hashlib.sha256(composite.encode("utf-8")).hexdigest()

    def get(self, prompt: str, model: str, temperature: float) -> str | None:
        """Retrieve cached response.

        Args:
            prompt: LLM prompt
            model: Model name
            temperature: Temperature parameter

        Returns:
            Cached response or None if not found
        """
        key = self._get_cache_key(prompt, model, temperature)
        cache_file = self.cache_dir / f"{key}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("response")
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, prompt: str, model: str, temperature: float, response: str) -> None:
        """Store response in cache.

        Args:
            prompt: LLM prompt
            model: Model name
            temperature: Temperature parameter
            response: LLM response to cache
        """
        key = self._get_cache_key(prompt, model, temperature)
        cache_file = self.cache_dir / f"{key}.json"

        data = {
            "prompt": prompt[:500],  # Store truncated prompt for debugging
            "model": model,
            "temperature": temperature,
            "response": response,
        }

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass  # Silently fail if cache write fails

    def clear(self) -> None:
        """Clear all cached entries."""
        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                except OSError:
                    pass
