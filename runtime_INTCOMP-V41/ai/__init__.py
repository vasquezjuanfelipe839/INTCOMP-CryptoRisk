"""Punto único para obtener un AIClient. El resto del sistema llama a
get_default_ai_client() y no le importa qué proveedor hay detrás.
"""

from __future__ import annotations

import os

from ai.client import AIClient, AIClientError
from ai.fallback_client import FallbackClient
from ai.nvidia_client import NVIDIAClient


def get_default_ai_client() -> AIClient:
    ai_enabled = os.getenv("AI_ENABLED", "true").strip().lower() != "false"
    api_key = os.getenv("NVIDIA_API_KEY", "").strip()

    if ai_enabled and api_key:
        try:
            return NVIDIAClient(api_key=api_key)
        except AIClientError:
            return FallbackClient()

    return FallbackClient()


__all__ = ["AIClient", "AIClientError", "FallbackClient", "NVIDIAClient", "get_default_ai_client"]
