"""Ollama HTTP client for AI investigation."""

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class OllamaClientError(Exception):
    """Base error for Ollama client issues."""


class OllamaUnavailableError(OllamaClientError):
    """Ollama server is unreachable or timed out."""


class OllamaInferenceError(OllamaClientError):
    """Ollama returned an error status or invalid output."""


class OllamaClient:
    """Client for querying an Ollama instance running locally."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "qwen2.5-coder:7b",
        timeout_seconds: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._client = client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        return httpx.AsyncClient(timeout=self.timeout_seconds)

    async def is_available(self) -> bool:
        """Check if Ollama is running and responding."""
        try:
            if self._client is not None:
                resp = await self._client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        """Send a chat request expecting structured JSON in response."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        url = f"{self.base_url}/api/chat"
        client = await self._get_client()
        should_close = self._client is None

        try:
            response = await client.post(url, json=payload, timeout=self.timeout_seconds)
        except httpx.ConnectError as exc:
            raise OllamaUnavailableError(
                f"Cannot connect to Ollama at {self.base_url}: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise OllamaUnavailableError(
                f"Ollama request timed out after {self.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise OllamaInferenceError(f"HTTP error talking to Ollama: {exc}") from exc
        finally:
            if should_close:
                await client.aclose()

        if response.status_code != 200:
            raise OllamaInferenceError(
                f"Ollama returned HTTP {response.status_code}: {response.text[:500]}"
            )

        try:
            data = response.json()
            message_content = data["message"]["content"]
            parsed = json.loads(message_content)
            if not isinstance(parsed, dict):
                raise ValueError("Model output was not a JSON object")
            return parsed
        except (KeyError, json.JSONDecodeError, ValueError) as exc:
            raise OllamaInferenceError(f"Failed to parse Ollama JSON response: {exc}") from exc
