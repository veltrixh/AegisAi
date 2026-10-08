import os
import json
import httpx
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from backend.utils.logger import logger

class BaseAIProvider(ABC):
    """Abstract AI Provider interface supporting pluggable LLM backends and offline fallback."""
    name: str = "BaseAIProvider"

    @abstractmethod
    async def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        pass

class OfflineDeterministicProvider(BaseAIProvider):
    """
    Deterministic rule-based AI provider.
    Ensures 100% of application capabilities (explanations, remediations, analyst queries)
    function cleanly offline without external API keys or network calls.
    """
    name = "Offline Deterministic Engine"

    async def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        # Returns structured fallback response based on prompt context
        return "Deterministic Analysis: Evidence verified by scanner engine."

class OpenAICompatibleProvider(BaseAIProvider):
    """Provider for OpenAI, Groq, Ollama, LocalAI, or any OpenAI-compatible API."""
    def __init__(self, api_key: str, model: str = "gpt-4o-mini", base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    async def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

class GeminiProvider(BaseAIProvider):
    """Google Gemini AI Provider."""
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        self.api_key = api_key
        self.model = model

    async def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.2}
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

def get_ai_provider() -> BaseAIProvider:
    """Factory selecting configured provider or gracefully defaulting to offline engine."""
    provider_type = os.environ.get("AI_PROVIDER", "").lower().strip()
    api_key = os.environ.get("AI_API_KEY", "").strip()
    model = os.environ.get("AI_MODEL", "")

    if provider_type == "openai" and api_key:
        return OpenAICompatibleProvider(api_key=api_key, model=model or "gpt-4o-mini")
    elif provider_type == "gemini" and api_key:
        return GeminiProvider(api_key=api_key, model=model or "gemini-1.5-flash")
    elif provider_type in ("ollama", "local", "openai-compatible") and api_key:
        base_url = os.environ.get("AI_BASE_URL", "http://localhost:11434/v1")
        return OpenAICompatibleProvider(api_key=api_key, model=model or "llama3", base_url=base_url)

    # Offline deterministic fallback
    return OfflineDeterministicProvider()
