"""UI and user-facing string catalog: Spanish (es) and English (en)."""

from __future__ import annotations

from typing import Any

TRANSLATIONS: dict[str, dict[str, str]] = {
    'app.title': {
        'es': 'INTCOMP CryptoRisk',
        'en': 'INTCOMP CryptoRisk',
    },
    'app.tagline': {
        'es': "Don't just find cryptographic risk. Decide what to do about it.",
        'en': "Don't just find cryptographic risk. Decide what to do about it.",
    },
    'app.methodology': {
        'es': '**Metodología:** Evidence → Analysis → Contrast → Decision → Action  ·  La IA interpreta; los motores determinísticos deciden.',
        'en': '**Methodology:** Evidence → Analysis → Contrast → Decision → Action  ·  AI interprets; deterministic engines decide.',
    },
    'app.ai_fallback': {
        'es': 'IA en modo respaldo (FallbackClient): no hay NVIDIA_API_KEY configurada, o AI_ENABLED=false. El sistema funciona igual — las explicaciones usan plantillas.',
        'en': 'AI in fallback mode (FallbackClient): no NVIDIA_API_KEY configured, or AI_ENABLED=false. The system works the same — explanations use templates.',
    },
    'app.ai_active': {
        'es': 'IA activa vía NVIDIA Build (NIM).',
        'en': 'AI active via NVIDIA Build (NIM).',
    },
    'app.lang_label': {
        'es': 'Idioma',
        'en': 'Language',
    },
    'tab.stress': {
        'es': 'Decision Stress Test',
        'en': 'Decision Stress Test',
    },
    'tab.inventory': {
        'es': 'Inventario',
        'en': 'Inventory',
    },
    'tab.dashboard': {
        'es': 'Dashboard',
        'en': 'Dashboard',
    },
    'tab.detail': {
        'es': 'Detalle de activo',
        'en': 'Asset detail',
    },
    'inv.title': {
        'es': 'Cargar inventario criptográfico',
        'en': 'Load cryptographic inventory',
    },
    'inv.upload': {
        'es': 'Subí un CSV con tu inventario',
        'en': 'Upload a CSV with your inventory',
    },
    'inv.demo': {
        'es': 'Usar dataset de demo',
        'en': 'Use demo dataset',
    },
    'inv.empty': {
        'es': 'Subí un CSV o usá el dataset de demo para empezar.',
        'en': 'Upload a CSV or use the demo dataset to get started.',
    },
    'inv.loaded': {
        'es': '{n} activo(s) cargados correctamente.',
        'en': '{n} asset(s) loaded successfully.',
    },
    'inv.errors': {
        'es': 'Errores al validar el CSV:',
        'en': 'Errors validating the CSV:',
    },
    'inv.warnings': {
        'es': '{n} advertencia(s) de datos',
        'en': '{n} data warning(s)',
    },
    'inv.status_note': {
        'es': 'Migration Status es el estado real de migración; Migration Priority es un score heurístico de orden. No son lo mismo.',
        'en': 'Migration Status is the real migration state; Migration Priority is a heuristic ordering score. They are not the same.',
    },
    'dash.need_inventory': {
        'es': "Cargá un inventario en la pestaña 'Inventario' para ver el dashboard.",
        'en': 'Load an inventory in the Inventory tab to see the dashboard.',
    },
    'dash.priority_title': {
        'es': 'Migration Priority Score',
        'en': 'Migration Priority Score',
    },
    'dash.priority_caption': {
        'es': 'El número de orden sugerido. Distinto de Migration Status (estado real).',
        'en': 'Suggested ordering score. Distinct from Migration Status (real state).',
    },
    'dash.classical': {
        'es': 'Classical Cryptographic Risk',
        'en': 'Classical Cryptographic Risk',
    },
    'dash.classical_cap': {
        'es': 'Debilidad frente a ataques clásicos (heurístico).',
        'en': 'Weakness against classical attacks (heuristic).',
    },
    'dash.quantum': {
        'es': 'Quantum Exposure',
        'en': 'Quantum Exposure',
    },
    'dash.quantum_cap': {
        'es': 'Exposición heurística a amenazas cuánticas conocidas. No predice fechas de Q-day ni probabilidades de ataque.',
        'en': 'Heuristic exposure to known quantum threats. Does not predict Q-day dates or attack probabilities.',
    },
    'dash.strategic': {
        'es': 'Strategic Impact',
        'en': 'Strategic Impact',
    },
    'dash.agility': {
        'es': 'Crypto Agility Estimate',
        'en': 'Crypto Agility Estimate',
    },
    'dash.agility_cap': {
        'es': 'Estimación heurística, no una medición objetiva.',
        'en': 'Heuristic estimate, not an objective measurement.',
    },
    'dash.scatter': {
        'es': 'Classical Risk vs Quantum Exposure',
        'en': 'Classical Risk vs Quantum Exposure',
    },
    'dash.communities': {
        'es': 'Comunidades del grafo (determinístico)',
        'en': 'Graph communities (deterministic)',
    },
    'dash.communities_cap': {
        'es': 'Agrupación por modularidad greedy (Louvain-like). No modifica scores ni prioridades; sirve para olas de migración.',
        'en': 'Grouping by greedy modularity (Louvain-like). Does not change scores or priorities; useful for migration waves.',
    },
    'dash.modularity': {
        'es': 'Modularidad Q ≈ {q:.4f}',
        'en': 'Modularity Q ≈ {q:.4f}',
    },
    'dash.communities_fail': {
        'es': 'No se pudieron calcular comunidades: {exc}',
        'en': 'Could not compute communities: {exc}',
    },
    'detail.need_inventory': {
        'es': "Cargá un inventario en la pestaña 'Inventario' para ver el detalle de un activo.",
        'en': 'Load an inventory in the Inventory tab to see asset detail.',
    },
    'detail.pick': {
        'es': 'Elegí un activo',
        'en': 'Choose an asset',
    },
    'detail.algorithm': {
        'es': 'Algoritmo',
        'en': 'Algorithm',
    },
    'detail.protocol': {
        'es': 'Protocolo',
        'en': 'Protocol',
    },
    'detail.criticality': {
        'es': 'Criticidad',
        'en': 'Criticality',
    },
    'detail.exposed': {
        'es': 'Expuesto a internet',
        'en': 'Internet exposed',
    },
    'detail.yes': {
        'es': 'Sí',
        'en': 'Yes',
    },
    'detail.no': {
        'es': 'No',
        'en': 'No',
    },
    'detail.status': {
        'es': 'Migration Status',
        'en': 'Migration Status',
    },
    'detail.deterministic': {
        'es': 'DETERMINISTIC ANALYSIS',
        'en': 'DETERMINISTIC ANALYSIS',
    },
    'detail.classical': {
        'es': 'Classical Cryptographic Risk',
        'en': 'Classical Cryptographic Risk',
    },
    'detail.classical_disc': {
        'es': 'Indicador heurístico de debilidad clásica; no es probabilidad de ataque.',
        'en': 'Heuristic indicator of classical weakness; not an attack probability.',
    },
    'detail.quantum': {
        'es': 'Quantum Exposure',
        'en': 'Quantum Exposure',
    },
    'detail.quantum_disc': {
        'es': 'Indicador heurístico de exposición cuántica relativa. No predice fechas de computadoras cuánticas ni probabilidades de ataque.',
        'en': 'Heuristic indicator of relative quantum exposure. Does not predict quantum-computer timelines or attack probabilities.',
    },
    'detail.risk': {
        'es': 'Risk Score (compuesto)',
        'en': 'Risk Score (composite)',
    },
    'detail.agility': {
        'es': 'Crypto Agility Estimate',
        'en': 'Crypto Agility Estimate',
    },
    'detail.agility_disc': {
        'es': 'Estimación heurística, no una medición objetiva.',
        'en': 'Heuristic estimate, not an objective measurement.',
    },
    'detail.dep_impact': {
        'es': 'Dependency Impact',
        'en': 'Dependency Impact',
    },
    'detail.strategic': {
        'es': 'Strategic Impact',
        'en': 'Strategic Impact',
    },
    'detail.priority': {
        'es': 'Migration Priority',
        'en': 'Migration Priority',
    },
    'detail.ai_section': {
        'es': 'AI Interpretation',
        'en': 'AI Interpretation',
    },
    'detail.ai_button': {
        'es': 'Explicar con IA',
        'en': 'Explain with AI',
    },
    'detail.ai_fail': {
        'es': 'No se pudo generar la explicación con IA ({exc}). Usá el desglose de arriba.',
        'en': 'Could not generate AI explanation ({exc}). Use the breakdown above.',
    },
    'detail.ai_cap': {
        'es': 'AI Interpretation — no reemplaza los números de arriba.',
        'en': 'AI Interpretation — does not replace the numbers above.',
    },
    'st.need_inventory': {
        'es': "Cargá un inventario en la pestaña 'Inventario' para poder correr un Decision Stress Test.",
        'en': 'Load an inventory in the Inventory tab to run a Decision Stress Test.',
    },
    'st.title': {
        'es': 'Decision Stress Test',
        'en': 'Decision Stress Test',
    },
    'st.caption': {
        'es': 'Centro de decisión estratégica. Metodología: Evidence → Analysis → Contrast → Decision → Action. La IA solo interpreta resultados ya calculados; no decide ni modifica scores.',
        'en': 'Strategic decision center. Methodology: Evidence → Analysis → Contrast → Decision → Action. AI only interprets already-computed results; it does not decide or change scores.',
    },
    'st.decision_label': {
        'es': 'Tu decisión',
        'en': 'Your decision',
    },
    'st.example': {
        'es': 'Quiero migrar Payment API primero',
        'en': 'I want to migrate Payment API first',
    },
    'st.run': {
        'es': 'Ejecutar Decision Stress Test',
        'en': 'Run Decision Stress Test',
    },
    'st.flow_hint': {
        'es': '**Flujo del sistema**\n\nUSER DECISION → EVIDENCE ✓ → ANALYSIS ✓ → CONTRAST ⚠ → DECISION → ACTION\n\nEscribí una decisión y ejecutá el test.',
        'en': '**System flow**\n\nUSER DECISION → EVIDENCE ✓ → ANALYSIS ✓ → CONTRAST ⚠ → DECISION → ACTION\n\nEnter a decision and run the test.',
    },
    'st.step_user': {
        'es': 'USER DECISION',
        'en': 'USER DECISION',
    },
    'st.step_evidence': {
        'es': 'EVIDENCE',
        'en': 'EVIDENCE',
    },
    'st.step_analysis': {
        'es': 'ANALYSIS',
        'en': 'ANALYSIS',
    },
    'st.step_contrast': {
        'es': 'CONTRAST',
        'en': 'CONTRAST',
    },
    'st.step_decision': {
        'es': 'DECISION',
        'en': 'DECISION',
    },
    'st.step_action': {
        'es': 'ACTION',
        'en': 'ACTION',
    },
    'st.deterministic': {
        'es': 'DETERMINISTIC ANALYSIS',
        'en': 'DETERMINISTIC ANALYSIS',
    },
    'st.heuristic_note': {
        'es': 'Indicadores heurísticos. Classical Risk y Quantum Exposure no son probabilidades de ataque. Migration Status ≠ Migration Priority.',
        'en': 'Heuristic indicators. Classical Risk and Quantum Exposure are not attack probabilities. Migration Status ≠ Migration Priority.',
    },
    'st.deps': {
        'es': 'Dependencias (prerequisitos)',
        'en': 'Dependencies (prerequisites)',
    },
    'st.deps_none': {
        'es': 'Sin dependencias declaradas.',
        'en': 'No declared dependencies.',
    },
    'st.dependents': {
        'es': 'Dependientes directos',
        'en': 'Direct dependents',
    },
    'st.dependents_none': {
        'es': 'Ningún activo depende directamente de este.',
        'en': 'No asset depends directly on this one.',
    },
    'st.satisfied': {
        'es': 'DEPENDENCY SATISFIED',
        'en': 'DEPENDENCY SATISFIED',
    },
    'st.unresolved': {
        'es': 'UNRESOLVED DEPENDENCY',
        'en': 'UNRESOLVED DEPENDENCY',
    },
    'st.missing': {
        'es': 'MISSING',
        'en': 'MISSING',
    },
    'st.conflict': {
        'es': 'CONFLICT DETECTED',
        'en': 'CONFLICT DETECTED',
    },
    'st.warning': {
        'es': 'WARNING (no bloquea automáticamente)',
        'en': 'WARNING (does not auto-block)',
    },
    'st.no_sequence': {
        'es': 'No hay secuencia válida (p. ej. ciclo de dependencias).',
        'en': 'No valid sequence (e.g. dependency cycle).',
    },
    'st.jury_blurb': {
        'es': '**INTCOMP no delega la decisión a la IA.** Scores, conflictos y secuencias son determinísticos. La IA solo interpreta.',
        'en': '**INTCOMP does not delegate decisions to AI.** Scores, conflicts and sequences are deterministic. AI only interprets.',
    },
    'st.no_conflict': {
        'es': 'NO CONFLICT',
        'en': 'NO CONFLICT',
    },
    'st.info_notes': {
        'es': 'Avisos informativos (no bloquean):',
        'en': 'Informational notes (non-blocking):',
    },
    'st.ai_interp': {
        'es': 'AI Interpretation',
        'en': 'AI Interpretation',
    },
    'st.ai_contrast_cap': {
        'es': 'La IA solo explica el veredicto determinístico; no decide si hay conflicto.',
        'en': 'AI only explains the deterministic verdict; it does not decide whether there is a conflict.',
    },
    'st.confirmed': {
        'es': '**{label}** — se puede proceder con `{asset}`.',
        'en': '**{label}** — you may proceed with `{asset}`.',
    },
    'st.alt_seq': {
        'es': 'Secuencia alternativa (determinística, según Migration Priority y estados):',
        'en': 'Alternative sequence (deterministic, by Migration Priority and statuses):',
    },
    'st.action_seq': {
        'es': 'Secuencia de migración recomendada',
        'en': 'Recommended migration sequence',
    },
    'st.ai_action_cap': {
        'es': 'Interpretación de la secuencia ya calculada por los motores determinísticos.',
        'en': 'Interpretation of the sequence already computed by deterministic engines.',
    },
    'st.stop_evidence': {
        'es': 'El flujo se detiene acá: no se le pasa nada inventado a la IA.',
        'en': 'Flow stops here: nothing invented is passed to the AI.',
    },
    'st.metric.classical': {
        'es': 'Classical Cryptographic Risk',
        'en': 'Classical Cryptographic Risk',
    },
    'st.metric.quantum': {
        'es': 'Quantum Exposure',
        'en': 'Quantum Exposure',
    },
    'st.metric.risk': {
        'es': 'Risk Score',
        'en': 'Risk Score',
    },
    'st.metric.agility': {
        'es': 'Crypto Agility Estimate',
        'en': 'Crypto Agility Estimate',
    },
    'st.metric.dep': {
        'es': 'Dependency Impact',
        'en': 'Dependency Impact',
    },
    'st.metric.strategic': {
        'es': 'Strategic Impact',
        'en': 'Strategic Impact',
    },
    'st.metric.priority': {
        'es': 'Migration Priority',
        'en': 'Migration Priority',
    },
    'st.metric.status': {
        'es': 'Migration Status',
        'en': 'Migration Status',
    },
    'crit.low': {
        'es': 'Baja',
        'en': 'Low',
    },
    'crit.medium': {
        'es': 'Media',
        'en': 'Medium',
    },
    'crit.high': {
        'es': 'Alta',
        'en': 'High',
    },
    'crit.critical': {
        'es': 'Crítica',
        'en': 'Critical',
    },
    "export.section": {
        "es": "Exportar plan de tareas",
        "en": "Export task plan",
    },
    "export.caption": {
        "es": "CSV y Markdown listos para Jira, Linear, Azure Boards o GitHub Projects. Generados de forma determinística.",
        "en": "CSV and Markdown ready for Jira, Linear, Azure Boards, or GitHub Projects. Generated deterministically.",
    },
    "export.csv_btn": {
        "es": "Descargar CSV de tareas",
        "en": "Download tasks CSV",
    },
    "export.md_btn": {
        "es": "Descargar Markdown de tareas",
        "en": "Download tasks Markdown",
    },
    "export.stress_md": {
        "es": "Descargar checklist del Stress Test",
        "en": "Download Stress Test checklist",
    },
    "zta.section": {
        "es": "Validación NIST SP 800-207 (Zero Trust)",
        "en": "NIST SP 800-207 validation (Zero Trust)",
    },
    "zta.caption": {
        "es": "Alineación heurística con los 7 tenets de SP 800-207. NO es una certificación formal de Zero Trust.",
        "en": "Heuristic alignment with the 7 SP 800-207 tenets. NOT a formal Zero Trust certification.",
    },
    "zta.alignment": {
        "es": "Alineación del inventario: {score}/100",
        "en": "Inventory alignment: {score}/100",
    },
    "zta.download": {
        "es": "Descargar informe ZTA (Markdown)",
        "en": "Download ZTA report (Markdown)",
    },
}


def normalize_lang(lang: str | None) -> str:
    if not lang:
        return "es"
    lang = lang.strip().lower()
    if lang.startswith("en"):
        return "en"
    return "es"


def t(key: str, lang: str = "es", **kwargs: Any) -> str:
    """Translate key to lang; fallback to Spanish then to key itself."""
    lang = normalize_lang(lang)
    entry = TRANSLATIONS.get(key, {})
    text = entry.get(lang) or entry.get("es") or key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError):
            return text
    return text
