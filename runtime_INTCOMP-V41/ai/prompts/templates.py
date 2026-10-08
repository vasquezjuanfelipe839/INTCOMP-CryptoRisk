"""Plantillas de prompts. Separadas del cliente para poder ajustarlas sin
tocar la lógica de llamada a la API.

SYSTEM_PROMPT es la instrucción de grounding: le prohíbe al modelo inventar
o modificar cualquier número.
"""

SYSTEM_PROMPT = (
    "You are an assistant that interprets results from a deterministic "
    "cryptographic risk prioritization model called INTCOMP CryptoRisk. "
    "Do not generate, modify, or correct any scores: the scores you receive "
    "are already computed and final. Your only task is to explain them clearly "
    "and briefly for a non-expert audience. Reply in the same language as the "
    "user context (Spanish or English). Never claim an asset 'will be hacked' "
    "or give an attack probability: always speak in terms of relative priority "
    "within the model. Classical Cryptographic Risk and Quantum Exposure are "
    "heuristic indicators, not probabilities. Do not invent dates about quantum computers."
)


def asset_explanation_prompt(context: dict) -> str:
    return (
        f"Activo: {context.get('asset_id')}\n"
        f"Classical Cryptographic Risk: {context.get('classical_risk', 'N/A')}/100\n"
        f"Quantum Exposure: {context.get('quantum_exposure', 'N/A')}/100\n"
        f"Risk Score: {context.get('risk_score')}/100\n"
        f"Crypto Agility Estimate: {context.get('agility_estimate')}/100 (heurística)\n"
        f"Strategic Impact: {context.get('strategic_impact')}/100\n"
        f"Dependency Impact: {context.get('dependency_impact')}/100\n"
        f"Migration Priority Score: {context.get('migration_priority')}/100\n"
        f"Migration Status: {context.get('migration_status', 'N/A')}\n\n"
        "Explicá en 2-3 frases por qué este activo tiene esta prioridad, "
        "usando solo estos números. Recordá que Migration Status no es lo "
        "mismo que Migration Priority."
    )


def contrast_explanation_prompt(context: dict) -> str:
    conflict = "sí" if context.get("has_conflict") else "no"
    reasons = "; ".join(context.get("reasons", []))
    return (
        f"Activo evaluado: {context.get('asset_id')}\n"
        f"¿Hay conflicto?: {conflict}\n"
        f"Motivos detectados por las reglas determinísticas: {reasons}\n\n"
        "Explicá este resultado en 2-3 frases, en lenguaje simple. "
        "No cambies el veredicto: solo interpretá lo que ya se calculó."
    )


def alternative_explanation_prompt(context: dict) -> str:
    sequence = " → ".join(context.get("sequence", []))
    return (
        f"Secuencia recomendada (ya calculada, no la cambies): {sequence}\n"
        f"Motivo determinístico: {context.get('rationale')}\n\n"
        "Redactá esto en 2-3 frases claras para mostrarlo en la interfaz."
    )
