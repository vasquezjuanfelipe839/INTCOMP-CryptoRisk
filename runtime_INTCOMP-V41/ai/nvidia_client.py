"""Cliente de NVIDIA Build (NIM), vía su endpoint compatible con OpenAI.

No hardcodea ninguna API key: todo viene de variables de entorno. Si algo
falla (sin key, timeout, error HTTP), lanza AIClientError — nunca deja que
una excepción de red se propague sin control hacia quien lo llama.
"""

from __future__ import annotations

import os

import requests

from ai.client import AIClient, AIClientError
from ai.prompts.templates import (
    SYSTEM_PROMPT,
    alternative_explanation_prompt,
    asset_explanation_prompt,
    contrast_explanation_prompt,
)

DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_TIMEOUT_SECONDS = 20


class NVIDIAClient(AIClient):
    def __init__(self, api_key: str = None, base_url: str = None, model: str = None):
        self.api_key = api_key or os.getenv("NVIDIA_API_KEY", "")
        self.base_url = base_url or os.getenv("NVIDIA_API_BASE_URL", DEFAULT_BASE_URL)
        self.model = model or os.getenv("NVIDIA_MODEL_NAME", "meta/llama-3.1-8b-instruct")

        if not self.api_key:
            raise AIClientError("NVIDIA_API_KEY no está configurada.")

    def _chat(self, user_prompt: str) -> str:
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 300,
                },
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        except requests.RequestException as exc:
            raise AIClientError(f"Fallo de red hacia NVIDIA: {exc}") from exc
        except (KeyError, IndexError, ValueError) as exc:
            raise AIClientError(f"Respuesta inesperada de NVIDIA: {exc}") from exc

    def explain_asset(self, context: dict) -> str:
        return self._chat(asset_explanation_prompt(context))

    def explain_contrast(self, context: dict) -> str:
        return self._chat(contrast_explanation_prompt(context))

    def explain_alternative(self, context: dict) -> str:
        return self._chat(alternative_explanation_prompt(context))
