"""Strategic Impact: 0-100, cuánto le importa al sistema en su conjunto
que este activo específico falle o se retrase.

Distinto de Risk (qué tan riesgoso es) y de Agility Estimate (qué tan
difícil es migrarlo). 100% determinístico, calculado a partir del grafo
de dependencias y los campos del CSV — la IA no participa acá.
"""

from __future__ import annotations

from core.config import (
    STRATEGIC_CRITICALITY_POINTS,
    STRATEGIC_MAX_GRAPH_POSITION,
    STRATEGIC_OWN_DEPENDENCIES_BUCKETS,
    STRATEGIC_OWN_DEPENDENCIES_DEFAULT,
    STRATEGIC_SERVICES_AFFECTED_BUCKETS,
    STRATEGIC_SERVICES_AFFECTED_DEFAULT,
    bucket_lookup,
)
from core.dependency_engine import DependencyGraph
from core.models import CryptoAsset, ScoreBreakdown


def _score_graph_position(asset_id: str, graph: DependencyGraph) -> int:
    """Qué tan 'aguas arriba' está: más dependientes y menos prerequisitos
    propios = más fundacional = más puntos. Usa una razón, no un conteo
    crudo, para no duplicar el factor 'servicios afectados'."""
    fan_in = len(graph.fan_in_transitive(asset_id))
    fan_out = len(graph.fan_out(asset_id))
    ratio = fan_in / (fan_in + fan_out + 1)
    return round(ratio * STRATEGIC_MAX_GRAPH_POSITION)


def compute_strategic_impact(asset: CryptoAsset, graph: DependencyGraph) -> ScoreBreakdown:
    affected = len(graph.fan_in_transitive(asset.asset_id))
    services_points = bucket_lookup(
        affected, STRATEGIC_SERVICES_AFFECTED_BUCKETS, STRATEGIC_SERVICES_AFFECTED_DEFAULT
    )

    criticality_points = STRATEGIC_CRITICALITY_POINTS[asset.criticality.value]

    position_points = _score_graph_position(asset.asset_id, graph)

    own_deps = len(graph.fan_out(asset.asset_id))
    own_deps_points = bucket_lookup(
        own_deps, STRATEGIC_OWN_DEPENDENCIES_BUCKETS, STRATEGIC_OWN_DEPENDENCIES_DEFAULT
    )

    total = services_points + criticality_points + position_points + own_deps_points

    return ScoreBreakdown(
        total=min(100, total),
        factors={
            "services_affected": services_points,
            "criticality": criticality_points,
            "graph_position": position_points,
            "own_dependencies": own_deps_points,
        },
        notes={
            "services_affected": f"{affected} activo(s) se verían afectados (fan-in transitivo).",
            "criticality": f"Criticidad declarada: {asset.criticality.value}.",
            "graph_position": "Más alto cuanto más 'fundacional' es el activo en la red.",
            "own_dependencies": f"Este activo depende de {own_deps} activo(s) a su vez.",
        },
    )
