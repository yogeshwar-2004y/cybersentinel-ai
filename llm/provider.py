"""Replaceable LLM adapters with bounded network requests and explicit local fallback."""

from __future__ import annotations
from abc import ABC, abstractmethod
import logging
import time
import requests
from config import Config

log = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    pass


class LLMProvider(ABC):
    name: str

    @abstractmethod
    def complete(self, system: str, prompt: str, json_mode: bool = False) -> str:
        """Return provider content; adapters never execute model output."""


class LocalProvider(LLMProvider):
    name = "local"

    def complete(self, system: str, prompt: str, json_mode: bool = False) -> str:
        raise ProviderError("Local mode uses the grounded deterministic analysis engine.")


class HTTPProvider(LLMProvider):
    def __init__(self, config: Config) -> None:
        self.config = config

    def post(self, url: str, payload: dict, headers: dict | None = None) -> dict:
        for attempt in range(3):
            try:
                response = requests.post(
                    url, json=payload, headers=headers, timeout=(5, self.config.timeout), allow_redirects=False
                )
            except requests.RequestException as exc:
                # Exception strings may contain credential-bearing URLs; never log them.
                if attempt == 2:
                    raise ProviderError(f"{self.name} network request failed ({type(exc).__name__})") from None
                time.sleep(0.4 * (2**attempt))
                continue
            if response.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                time.sleep(0.4 * (2**attempt))
                continue
            if not 200 <= response.status_code < 300:
                raise ProviderError(f"{self.name} returned HTTP {response.status_code}")
            try:
                return response.json()
            except ValueError:
                raise ProviderError(f"{self.name} returned invalid JSON") from None
        raise ProviderError("Provider retries exhausted")


class OpenAIProvider(HTTPProvider):
    name = "openai"

    def complete(self, system: str, prompt: str, json_mode: bool = False) -> str:
        if not self.config.openai_key:
            raise ProviderError("OPENAI_API_KEY is not configured")
        payload = {
            "model": self.config.openai_model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        result = self.post(
            "https://api.openai.com/v1/chat/completions", payload, {"Authorization": f"Bearer {self.config.openai_key}"}
        )
        try:
            content = result["choices"][0]["message"]["content"]
            if not content or result["choices"][0].get("finish_reason") != "stop":
                raise ValueError()
            return content
        except (KeyError, IndexError, ValueError, TypeError):
            raise ProviderError("OpenAI returned missing or incomplete content") from None


class GeminiProvider(HTTPProvider):
    name = "gemini"

    def complete(self, system: str, prompt: str, json_mode: bool = False) -> str:
        if not self.config.gemini_key:
            raise ProviderError("GEMINI_API_KEY is not configured")
        if not self.config.gemini_model.replace("-", "").replace(".", "").isalnum():
            raise ProviderError("Invalid Gemini model name")
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1},
        }
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        result = self.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.gemini_model}:generateContent",
            payload,
            {"x-goog-api-key": self.config.gemini_key},
        )
        try:
            candidate = result["candidates"][0]
            if candidate.get("finishReason") != "STOP":
                raise ValueError()
            return "".join(p["text"] for p in candidate["content"]["parts"] if "text" in p)
        except (KeyError, IndexError, TypeError, ValueError):
            raise ProviderError("Gemini returned missing or incomplete content") from None


class OllamaProvider(HTTPProvider):
    name = "ollama"

    def complete(self, system: str, prompt: str, json_mode: bool = False) -> str:
        payload = {
            "model": self.config.ollama_model,
            "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "options": {"temperature": 0.1, "num_predict": 3000},
        }
        if json_mode:
            payload["format"] = "json"
        result = self.post(self.config.ollama_url.rstrip("/") + "/api/chat", payload)
        try:
            content = result["message"]["content"]
            if not content or result.get("done") is not True:
                raise ValueError()
            return content
        except (KeyError, TypeError, ValueError):
            raise ProviderError("Ollama returned missing or incomplete content") from None


def create_provider(config: Config) -> LLMProvider:
    providers = {"openai": OpenAIProvider, "gemini": GeminiProvider, "ollama": OllamaProvider}
    return LocalProvider() if config.provider == "local" else providers[config.provider](config)
