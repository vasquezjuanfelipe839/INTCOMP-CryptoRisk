"""Interfaz que debe cumplir cualquier proveedor de IA.

core/ nunca importa NVIDIAClient directamente: recibe algo que cumple esta
interfaz. Así se puede cambiar de proveedor sin tocar el resto del sistema.

Ningún método de esta interfaz calcula ni modifica scores. Todos reciben un
`context` con números ya calculados por core/ y devuelven texto que los
interpreta o explica.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class AIClientError(Exception):
    """Cualquier falla al pedirle una explicación a un proveedor de IA."""


class AIClient(ABC):
    @abstractmethod
    def explain_asset(self, context: dict) -> str:
        """Explica en lenguaje natural el desglose de scores de un activo."""

    @abstractmethod
    def explain_contrast(self, context: dict) -> str:
        """Explica el veredicto de la etapa Contrast del Decision Stress Test."""

    @abstractmethod
    def explain_alternative(self, context: dict) -> str:
        """Explica la secuencia alternativa recomendada."""
