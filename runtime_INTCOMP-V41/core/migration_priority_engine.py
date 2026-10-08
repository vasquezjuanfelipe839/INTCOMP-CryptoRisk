"""Migration Priority Score: 0-100, combina Risk + Strategic Impact +
Dependency Impact + Crypto Agility Estimate (invertida) en un único número
determinístico, configurable y explicable.

La Agility Estimate se invierte (100 - estimate) porque un activo difícil
de migrar necesita más tiempo de preparación, así que conviene empezarlo
antes. Es una decisión de diseño documentada, no un hecho objetivo — por
eso su peso es configurable en core/config.py.
"""

from __future__ import annotations

from core.config import MIGRATION_PRIORITY_WEIGHTS
from core.models import ScoreBreakdown


def compute_migration_priority(
    risk_score: int,
    strategic_impact_score: int,
    dependency_impact_score: int,
    agility_estimate_score: int,
    weights: dict = None,
) -> ScoreBreakdown:
    w = weights or MIGRATION_PRIORITY_WEIGHTS
    agility_inverted = 100 - agility_estimate_score

    risk_contribution = w["risk"] * risk_score
    strategic_contribution = w["strategic_impact"] * strategic_impact_score
    dependency_contribution = w["dependency_impact"] * dependency_impact_score
    agility_contribution = w["agility_inverted"] * agility_inverted

    total = (
        risk_contribution
        + strategic_contribution
        + dependency_contribution
        + agility_contribution
    )

    return ScoreBreakdown(
        total=round(min(100, total)),
        factors={
            "risk": round(risk_contribution, 1),
            "strategic_impact": round(strategic_contribution, 1),
            "dependency_impact": round(dependency_contribution, 1),
            "agility_inverted": round(agility_contribution, 1),
        },
        notes={
            "risk": f"Risk Score {risk_score}/100, peso {w['risk']:.0%}.",
            "strategic_impact": f"Strategic Impact {strategic_impact_score}/100, peso {w['strategic_impact']:.0%}.",
            "dependency_impact": f"Dependency Impact {dependency_impact_score}/100, peso {w['dependency_impact']:.0%}.",
            "agility_inverted": (
                f"Agility Estimate {agility_estimate_score}/100 invertida "
                f"a {agility_inverted}/100, peso {w['agility_inverted']:.0%}."
            ),
        },
    )
