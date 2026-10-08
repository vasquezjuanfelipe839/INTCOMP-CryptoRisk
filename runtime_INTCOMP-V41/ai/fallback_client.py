"""Cliente de respaldo: implementa AIClient sin llamar a ninguna API.

Se usa automáticamente si no hay NVIDIA_API_KEY, si AI_ENABLED=false, o si
NVIDIAClient falla. Garantiza que el sistema completo funcione sin internet.
"""

from __future__ import annotations

from ai.client import AIClient


class FallbackClient(AIClient):
    def explain_asset(self, context: dict) -> str:
        parts = [
            f"[Explicación por plantilla] {context.get('asset_id')} tiene Migration "
            f"Priority {context.get('migration_priority')}/100"
        ]
        if context.get("classical_risk") is not None:
            parts.append(f"Classical Risk {context.get('classical_risk')}/100")
        if context.get("quantum_exposure") is not None:
            parts.append(f"Quantum Exposure {context.get('quantum_exposure')}/100")
        parts.append(
            f"Risk Score {context.get('risk_score')}/100, Strategic Impact "
            f"{context.get('strategic_impact')}/100 y Crypto Agility Estimate "
            f"(heurística) {context.get('agility_estimate')}/100"
        )
        if context.get("migration_status"):
            parts.append(f"Migration Status: {context.get('migration_status')}")
        return ". ".join(parts) + "."

    def explain_contrast(self, context: dict) -> str:
        if not context.get("has_conflict"):
            return (
                "[Explicación por plantilla] No se detectaron conflictos: la "
                "decisión es consistente con el grafo de dependencias y Migration Status."
            )
        reasons = "; ".join(context.get("reasons", []))
        return f"[Explicación por plantilla] CONFLICT DETECTED. {reasons}"

    def explain_alternative(self, context: dict) -> str:
        return f"[Explicación por plantilla] {context.get('rationale')}"
