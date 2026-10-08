"""Calcula las dimensiones (Classical Risk, Quantum Exposure, Risk, Agility
Estimate, Dependency Impact, Strategic Impact, Migration Priority) para
todos los activos de un inventario. Es el único punto donde se llaman los
motores en orden.
"""

from __future__ import annotations

from typing import Dict, List

from core.agility_engine import compute_agility_estimate
from core.dependency_engine import build_graph, compute_dependency_impact
from core.migration_priority_engine import compute_migration_priority
from core.models import AssetScores, CryptoAsset
from core.risk_engine import (
    compute_classical_risk,
    compute_quantum_exposure,
    compute_risk,
)
from core.strategic_impact_engine import compute_strategic_impact


def score_inventory(assets: List[CryptoAsset]) -> Dict[str, AssetScores]:
    graph = build_graph(assets)
    results: Dict[str, AssetScores] = {}

    for asset in assets:
        classical = compute_classical_risk(asset, graph)
        quantum = compute_quantum_exposure(asset, graph)
        risk = compute_risk(asset, graph)
        agility = compute_agility_estimate(asset, graph)
        dependency_impact = compute_dependency_impact(asset.asset_id, graph)
        strategic_impact = compute_strategic_impact(asset, graph)
        migration_priority = compute_migration_priority(
            risk_score=risk.total,
            strategic_impact_score=strategic_impact.total,
            dependency_impact_score=dependency_impact.total,
            agility_estimate_score=agility.total,
        )
        results[asset.asset_id] = AssetScores(
            asset_id=asset.asset_id,
            classical_risk=classical,
            quantum_exposure=quantum,
            risk=risk,
            agility_estimate=agility,
            dependency_impact=dependency_impact,
            strategic_impact=strategic_impact,
            migration_priority=migration_priority,
        )

    return results
