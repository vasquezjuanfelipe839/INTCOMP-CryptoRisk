"""Crypto Agility Estimate: 0-100, más alto = más fácil de migrar.

Es una ESTIMACIÓN HEURÍSTICA, no una medición objetiva ni un cálculo de
horas de esfuerzo real. Esa aclaración debe repetirse siempre que se
muestre este número (ver app/sections y README).
"""

from __future__ import annotations

from core.config import (
    AGILITY_COUPLING_BUCKETS,
    AGILITY_COUPLING_DEFAULT,
    AGILITY_CRITICALITY_POINTS,
    AGILITY_PREREQUISITE_BUCKETS,
    AGILITY_PREREQUISITE_DEFAULT,
    AGILITY_PROTOCOL_DEFAULT,
    AGILITY_PROTOCOL_POINTS,
    bucket_lookup,
)
from core.dependency_engine import DependencyGraph
from core.models import CryptoAsset, ScoreBreakdown

HEURISTIC_DISCLAIMER = (
    "Estimación heurística basada en patrones típicos de migración, "
    "no una medición objetiva verificada."
)


def compute_agility_estimate(asset: CryptoAsset, graph: DependencyGraph) -> ScoreBreakdown:
    dependents = len(graph.fan_in_direct(asset.asset_id))
    coupling_points = bucket_lookup(dependents, AGILITY_COUPLING_BUCKETS, AGILITY_COUPLING_DEFAULT)

    prerequisites = len(graph.fan_out(asset.asset_id))
    prerequisite_points = bucket_lookup(
        prerequisites, AGILITY_PREREQUISITE_BUCKETS, AGILITY_PREREQUISITE_DEFAULT
    )

    criticality_points = AGILITY_CRITICALITY_POINTS[asset.criticality.value]

    protocol_key = asset.protocol.strip().upper()
    protocol_points = AGILITY_PROTOCOL_POINTS.get(protocol_key, AGILITY_PROTOCOL_DEFAULT)

    total = coupling_points + prerequisite_points + criticality_points + protocol_points

    return ScoreBreakdown(
        total=min(100, total),
        factors={
            "coupling": coupling_points,
            "prerequisites": prerequisite_points,
            "criticality": criticality_points,
            "protocol_modernity": protocol_points,
        },
        notes={
            "coupling": f"{dependents} activo(s) dependen directamente de este.",
            "prerequisites": f"Este activo depende de {prerequisites} activo(s).",
            "criticality": f"Criticidad declarada: {asset.criticality.value}.",
            "protocol_modernity": f"Protocolo: {asset.protocol}.",
            "_disclaimer": HEURISTIC_DISCLAIMER,
        },
    )
