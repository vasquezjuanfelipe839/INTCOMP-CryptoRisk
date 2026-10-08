"""Risk Engine: Classical Cryptographic Risk, Quantum Exposure y Risk Score compuesto.

Importante: estos scores NUNCA representan una probabilidad de ataque. Son
prioridades relativas / indicadores heurísticos dentro de este modelo.

Classical Cryptographic Risk: debilidades frente a ataques clásicos
(algoritmos deprecados, colisiones, key size insuficiente) + contexto operativo.

Quantum Exposure (V3.1):
  - Quantum Cryptographic Exposure: algoritmo (Shor/Grover) + data lifetime / HNDL
  - Operational Context: internet exposure + criticality (contexto de negocio/red,
    NO causa de vulnerabilidad cuántica del algoritmo)

Cuando Classical y Quantum alimentan la dimensión algorítmica del Risk Score
compuesto, se usa max(classical_algo, quantum_algo) — NO la suma — para evitar
doble contabilización (ver score_algorithm / compute_risk).

Fuentes: NIST PQC guidance, NIST SP 800-57 / 800-131A (ver algorithm_catalog).
"""

from __future__ import annotations

from core.config import (
    RISK_CRITICALITY_POINTS,
    RISK_DATA_LIFETIME_CAP_YEARS,
    RISK_MAX_DATA_LIFETIME,
    RISK_MAX_DEPENDENCIES,
)
from core.dependency_engine import DependencyGraph
from core.models import CryptoAsset, ScoreBreakdown
from crypto.algorithm_catalog import (
    get_algorithm_profile,
    score_algorithm,
    score_classical_algorithm,
    score_quantum_algorithm,
)


def _score_data_lifetime(years: int) -> int:
    capped = min(years, RISK_DATA_LIFETIME_CAP_YEARS)
    return round(capped / RISK_DATA_LIFETIME_CAP_YEARS * RISK_MAX_DATA_LIFETIME)


def _score_dependencies(asset_id: str, graph: DependencyGraph) -> int:
    """Cuántos activos dependen de este (fan-in directo), escalado a 15 pts."""
    dependents = len(graph.fan_in_direct(asset_id))
    if dependents == 0:
        return 0
    if dependents <= 2:
        return 5
    if dependents <= 5:
        return 10
    return RISK_MAX_DEPENDENCIES


def compute_classical_risk(asset: CryptoAsset, graph: DependencyGraph) -> ScoreBreakdown:
    """Classical Cryptographic Risk 0-100: debilidad clásica + contexto.

    Heurístico. No es probabilidad de ataque.
    """
    algo_points, algo_note = score_classical_algorithm(asset.algorithm, asset.key_size)
    exposure_points = 15 if asset.internet_exposed else 0
    criticality_points = {
        "low": 4,
        "medium": 8,
        "high": 12,
        "critical": 15,
    }[asset.criticality.value]
    protocol_key = asset.protocol.strip().upper()
    protocol_points = {
        "TLS 1.0": 15,
        "TLS 1.1": 12,
        "PROPRIETARY": 15,
        "TLS 1.2": 5,
        "IPSEC": 6,
        "TLS 1.3": 2,
        "SSH-2": 4,
    }.get(protocol_key, 8)
    dependencies_points = min(15, _score_dependencies(asset.asset_id, graph))

    total = (
        algo_points
        + exposure_points
        + criticality_points
        + protocol_points
        + dependencies_points
    )

    return ScoreBreakdown(
        total=min(100, total),
        factors={
            "algorithm_classical": algo_points,
            "exposure": exposure_points,
            "criticality": criticality_points,
            "protocol": protocol_points,
            "dependencies": dependencies_points,
        },
        notes={
            "algorithm_classical": algo_note,
            "exposure": "Expuesto a internet." if asset.internet_exposed else "No expuesto a internet.",
            "criticality": f"Criticidad declarada: {asset.criticality.value}.",
            "protocol": f"Protocolo: {asset.protocol}.",
            "dependencies": "Basado en cuántos activos dependen directamente de este.",
            "_disclaimer": (
                "Indicador heurístico de debilidad criptográfica clásica; "
                "no es probabilidad de ataque."
            ),
        },
    )


def compute_quantum_exposure(asset: CryptoAsset, graph: DependencyGraph) -> ScoreBreakdown:
    """Quantum Exposure 0-100 (heurístico).

    Quantum Cryptographic Exposure (núcleo):
      - algoritmo / vulnerabilidad a algoritmos cuánticos conocidos (Shor/Grover)
      - data_lifetime_years (HNDL) cuando aplica

    Operational Context (no es vulnerabilidad cuántica del algoritmo):
      - internet exposure
      - criticality

    Participa en Migration Priority vía el Risk Score compuesto. No afirma
    probabilidades reales de ataque ni fechas de Q-day.
    """
    algo_points, algo_note = score_quantum_algorithm(asset.algorithm, asset.key_size)
    profile = get_algorithm_profile(asset.algorithm)

    lifetime_raw = _score_data_lifetime(asset.data_lifetime_years)  # 0-15
    if profile.quantum_vulnerable:
        lifetime_points = min(25, round(lifetime_raw * 25 / 15))
        hndl_note = (
            f"Datos deben permanecer seguros {asset.data_lifetime_years} año(s). "
            "Con algoritmo vulnerable a Shor, aplica el riesgo de "
            "'harvest now, decrypt later' (heurístico)."
        )
    else:
        lifetime_points = min(15, lifetime_raw)
        hndl_note = (
            f"Datos deben permanecer seguros {asset.data_lifetime_years} año(s). "
            "Algoritmo no clasificado como vulnerable a Shor; lifetime aporta "
            "menos al indicador de exposición cuántica."
        )

    # Operational context — explícitamente NO es causa de vulnerabilidad cuántica
    op_exposure = 15 if asset.internet_exposed else 0
    op_criticality = {
        "low": 3,
        "medium": 6,
        "high": 10,
        "critical": 15,
    }[asset.criticality.value]

    total = algo_points + lifetime_points + op_exposure + op_criticality

    return ScoreBreakdown(
        total=min(100, total),
        factors={
            "algorithm_quantum": algo_points,
            "data_lifetime_hndl": lifetime_points,
            "operational_context_exposure": op_exposure,
            "operational_context_criticality": op_criticality,
        },
        notes={
            "algorithm_quantum": algo_note,
            "data_lifetime_hndl": hndl_note,
            "operational_context_exposure": (
                "Contexto operativo: expuesto a internet. "
                "No implica vulnerabilidad cuántica del algoritmo."
                if asset.internet_exposed
                else "Contexto operativo: no expuesto a internet."
            ),
            "operational_context_criticality": (
                f"Contexto operativo: criticidad declarada {asset.criticality.value}. "
                "Pondera prioridad de migración, no la debilidad cuántica del algoritmo."
            ),
            "_disclaimer": (
                "Indicador heurístico de exposición relativa. "
                "No es una probabilidad de ataque ni una predicción de cuándo "
                "existirá un computador cuántico capaz de romper el algoritmo."
            ),
            "_structure": (
                "Quantum Cryptographic Exposure = algorithm + HNDL/lifetime. "
                "Operational Context = internet exposure + criticality."
            ),
        },
    )


def compute_risk(asset: CryptoAsset, graph: DependencyGraph) -> ScoreBreakdown:
    """Risk Score compuesto 0-100 (compatible con Migration Priority).

    Dimensión algorítmica: max(classical_algo, quantum_algo) vía score_algorithm,
    NO la suma — evita doble contabilización cuando un algoritmo es débil en
    ambos ejes. Heurístico; no es probabilidad de ataque.
    """
    algorithm_points, algorithm_note = score_algorithm(asset.algorithm, asset.key_size)
    exposure_points = 20 if asset.internet_exposed else 0
    criticality_points = RISK_CRITICALITY_POINTS[asset.criticality.value]
    data_lifetime_points = _score_data_lifetime(asset.data_lifetime_years)
    dependencies_points = _score_dependencies(asset.asset_id, graph)

    total = (
        algorithm_points
        + exposure_points
        + criticality_points
        + data_lifetime_points
        + dependencies_points
    )

    classical_pts, _ = score_classical_algorithm(asset.algorithm, asset.key_size)
    quantum_pts, _ = score_quantum_algorithm(asset.algorithm, asset.key_size)

    return ScoreBreakdown(
        total=min(100, total),
        factors={
            "algorithm": algorithm_points,
            "exposure": exposure_points,
            "criticality": criticality_points,
            "data_lifetime": data_lifetime_points,
            "dependencies": dependencies_points,
        },
        notes={
            "algorithm": algorithm_note,
            "algorithm_combine_rule": (
                "Dimensión algorítmica = max(classical, quantum) escalado; "
                "no se suman para evitar doble contabilización. "
                f"classical={classical_pts}, quantum={quantum_pts}, rule=max."
            ),
            "exposure": "Expuesto a internet." if asset.internet_exposed else "No expuesto a internet.",
            "criticality": f"Criticidad declarada: {asset.criticality.value}.",
            "data_lifetime": f"Los datos deben permanecer seguros {asset.data_lifetime_years} año(s).",
            "dependencies": "Basado en cuántos activos dependen directamente de este.",
            "_disclaimer": "Indicador heurístico; no es probabilidad de ataque.",
        },
    )
