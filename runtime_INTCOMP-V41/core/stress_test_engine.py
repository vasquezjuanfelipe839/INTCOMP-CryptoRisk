"""Decision Stress Test — motor de decisión INTCOMP V4 (Integrity & Decision Engine).

Flujo fijo (metodología INTCOMP):
1. USER DECISION
2. EVIDENCE
3. ANALYSIS
4. CONTRAST  ← Policy Engine (políticas explícitas y auditables)
5. DECISION
6. ACTION

CONTRAST distingue:
  NO_CONFLICT | WARNING | CONFLICT

- Violación estructural de dependencia (not_started / missing) → CONFLICT
- planned / in_progress → WARNING (no se convierte en CONFLICT)
- Scores altos (quantum, strategic, risk) o agility baja → WARNING
- Los scores NUNCA crean conflicto estructural por sí solos

La IA solo interpreta resultados ya calculados; no decide conflictos ni
modifica secuencias/scores/estados.

Regla absoluta V4:
  AI OUTPUT MUST NEVER HAVE AUTHORITY OVER THE DECISION.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

from core.config import STRESS_TEST_LOW_AGILITY_THRESHOLD
from core.decision_audit import DecisionAuditRecord, build_decision_audit
from core.dependency_engine import DependencyGraph, build_graph
from core.models import AssetScores, CryptoAsset, MigrationStatus
from core.policy_engine import (
    PolicyHit,
    evaluate_policies,
    severity_from_policies,
    triggered_policies,
)
from core.security_controls import audit_event

if TYPE_CHECKING:
    from ai.client import AIClient


# ---------------------------------------------------------------------------
# Severity labels (Contrast)
# ---------------------------------------------------------------------------
SEVERITY_NO_CONFLICT = "NO_CONFLICT"
SEVERITY_WARNING = "WARNING"
SEVERITY_CONFLICT = "CONFLICT"


# ---------------------------------------------------------------------------
# Resultado de cada etapa
# ---------------------------------------------------------------------------
@dataclass
class EvidenceResult:
    found: bool
    asset: Optional[CryptoAsset]
    message: str
    resolution: str = "FOUND"  # FOUND | AMBIGUOUS | NOT_FOUND
    candidates: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    classical_risk: int
    quantum_exposure: int
    risk_score: int
    agility_estimate: int
    dependency_impact: int
    strategic_impact: int
    migration_priority: int
    migration_status: str
    dependencies: List[str]
    dependents: List[str]
    dependency_statuses: Dict[str, str]
    message: str


@dataclass
class DependencyStatusDetail:
    asset_id: str
    status: str
    label: str  # BLOCKING | WARNING | SATISFIED | MISSING


@dataclass
class ContrastResult:
    has_conflict: bool
    severity: str  # NO_CONFLICT | WARNING | CONFLICT
    reasons: List[str]
    warnings: List[str] = field(default_factory=list)
    dependency_details: List[DependencyStatusDetail] = field(default_factory=list)
    message: str = ""
    policy_hits: List[PolicyHit] = field(default_factory=list)
    policies_triggered: List[str] = field(default_factory=list)


@dataclass
class DecisionOutcome:
    endorsed: bool
    label: str  # CONFIRMED DECISION | RECOMMENDED ALTERNATIVE | AMBIGUOUS DECISION | ASSET NOT FOUND | DEPENDENCY CYCLE DETECTED
    recommended_sequence: List[str]


@dataclass
class ActionResult:
    sequence: List[str]
    rationale: str


@dataclass
class StressTestResult:
    decision_text: str
    evidence: EvidenceResult
    analysis: Optional[AnalysisResult] = None
    contrast: Optional[ContrastResult] = None
    decision: Optional[DecisionOutcome] = None
    action: Optional[ActionResult] = None
    dependency: Optional[object] = None
    risk: Optional[object] = None
    agility: Optional[object] = None
    alternative_action: Optional[ActionResult] = None
    contrast_explanation: str = ""
    alternative_explanation: str = ""
    audit: Optional[DecisionAuditRecord] = None
    ai_explanation_conflict: bool = False
    core_decision_snapshot: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Decision entity resolution (sin IA)
# ---------------------------------------------------------------------------
def _normalize_token(text: str) -> str:
    t = text.lower().strip()
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


@dataclass
class EntityResolution:
    status: str  # FOUND | AMBIGUOUS | NOT_FOUND
    asset: Optional[CryptoAsset]
    candidates: List[CryptoAsset]
    message: str


def resolve_decision_entity(
    decision_text: str, assets: Sequence[CryptoAsset]
) -> EntityResolution:
    """Resuelve el activo mencionado sin IA.

    Orden determinístico:
      1. asset_id exacto (token)
      2. nombre exacto (token / igualdad)
      3. alias explícito del inventario
      4. coincidencia normalizada
      5. varios candidatos → AMBIGUOUS
      6. ninguno → NOT_FOUND
    """
    raw = decision_text.strip()
    lower = raw.lower()

    def _unique(hits: List[CryptoAsset]) -> List[CryptoAsset]:
        seen = set()
        out: List[CryptoAsset] = []
        for a in hits:
            if a.asset_id not in seen:
                seen.add(a.asset_id)
                out.append(a)
        return out

    # 1) asset_id exacto como token
    exact_id = [
        a for a in assets
        if re.search(rf"\b{re.escape(a.asset_id)}\b", decision_text, re.I)
    ]
    exact_id = _unique(exact_id)
    if len(exact_id) == 1:
        return EntityResolution("FOUND", exact_id[0], exact_id, f"Activo encontrado: {exact_id[0].asset_id}")
    if len(exact_id) > 1:
        return EntityResolution(
            "AMBIGUOUS", None, exact_id,
            "AMBIGUOUS DECISION: varios asset_id coinciden: "
            + ", ".join(a.asset_id for a in exact_id),
        )

    # 2) nombre exacto
    exact_name = [a for a in assets if a.name.lower() == lower]
    if not exact_name:
        exact_name = [
            a for a in assets
            if re.search(rf"\b{re.escape(a.name)}\b", decision_text, re.I)
        ]
    exact_name = _unique(exact_name)
    if len(exact_name) == 1:
        return EntityResolution("FOUND", exact_name[0], exact_name, f"Activo encontrado: {exact_name[0].asset_id}")
    if len(exact_name) > 1:
        return EntityResolution(
            "AMBIGUOUS", None, exact_name,
            "AMBIGUOUS DECISION: varios nombres coinciden: "
            + ", ".join(a.asset_id for a in exact_name),
        )

    # 3) alias explícito (campo aliases del activo)
    alias_hits: List[CryptoAsset] = []
    for a in assets:
        for alias in a.aliases or []:
            al = alias.strip()
            if not al:
                continue
            if al.lower() == lower or re.search(rf"\b{re.escape(al)}\b", decision_text, re.I):
                alias_hits.append(a)
                break
    alias_hits = _unique(alias_hits)
    if len(alias_hits) == 1:
        return EntityResolution(
            "FOUND", alias_hits[0], alias_hits,
            f"Activo encontrado vía alias: {alias_hits[0].asset_id}",
        )
    if len(alias_hits) > 1:
        return EntityResolution(
            "AMBIGUOUS", None, alias_hits,
            "AMBIGUOUS DECISION: varios aliases coinciden: "
            + ", ".join(a.asset_id for a in alias_hits),
        )

    # 4) coincidencia normalizada
    norm_text = _normalize_token(decision_text)
    norm_hits: List[CryptoAsset] = []
    for a in assets:
        tokens = [_normalize_token(a.asset_id), _normalize_token(a.name)]
        tokens.extend(_normalize_token(al) for al in (a.aliases or []) if al)
        for tok in tokens:
            if tok and tok in norm_text:
                norm_hits.append(a)
                break
    norm_hits = _unique(norm_hits)
    if len(norm_hits) == 1:
        return EntityResolution("FOUND", norm_hits[0], norm_hits, f"Activo encontrado: {norm_hits[0].asset_id}")
    if len(norm_hits) > 1:
        return EntityResolution(
            "AMBIGUOUS", None, norm_hits,
            "AMBIGUOUS DECISION: múltiples candidatos — "
            + ", ".join(a.asset_id for a in norm_hits),
        )

    return EntityResolution(
        "NOT_FOUND", None, [],
        "ASSET NOT FOUND: ningún activo coincide con la decisión.",
    )


def _match_asset(decision_text: str, assets: List[CryptoAsset]) -> Optional[CryptoAsset]:
    """Compatibilidad: devuelve el activo solo si la resolución es unívoca."""
    res = resolve_decision_entity(decision_text, assets)
    return res.asset if res.status == "FOUND" else None


def evidence_check(decision_text: str, assets: List[CryptoAsset]) -> EvidenceResult:
    res = resolve_decision_entity(decision_text, assets)
    if res.status == "FOUND" and res.asset is not None:
        return EvidenceResult(
            found=True,
            asset=res.asset,
            message=res.message,
            resolution="FOUND",
            candidates=[res.asset.asset_id],
        )
    if res.status == "AMBIGUOUS":
        ids = [a.asset_id for a in res.candidates]
        return EvidenceResult(
            found=False,
            asset=None,
            message=res.message,
            resolution="AMBIGUOUS",
            candidates=ids,
        )
    return EvidenceResult(
        found=False,
        asset=None,
        message=res.message,
        resolution="NOT_FOUND",
        candidates=[],
    )


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _status_label(status: MigrationStatus) -> str:
    if status == MigrationStatus.MIGRATED:
        return "SATISFIED"
    if status == MigrationStatus.NOT_STARTED:
        return "BLOCKING"
    # planned / in_progress
    return "WARNING"


def analyze_asset(
    asset: CryptoAsset,
    assets: List[CryptoAsset],
    scores: Dict[str, AssetScores],
    graph: DependencyGraph,
) -> AnalysisResult:
    by_id = {a.asset_id: a for a in assets}
    sc = scores[asset.asset_id]
    dep_statuses: Dict[str, str] = {}
    for dep_id in asset.dependencies:
        if dep_id not in by_id:
            dep_statuses[dep_id] = "MISSING"
        else:
            dep_statuses[dep_id] = by_id[dep_id].migration_status.value

    return AnalysisResult(
        classical_risk=sc.classical_risk.total,
        quantum_exposure=sc.quantum_exposure.total,
        risk_score=sc.risk.total,
        agility_estimate=sc.agility_estimate.total,
        dependency_impact=sc.dependency_impact.total,
        strategic_impact=sc.strategic_impact.total,
        migration_priority=sc.migration_priority.total,
        migration_status=asset.migration_status.value,
        dependencies=list(asset.dependencies),
        dependents=sorted(graph.fan_in_direct(asset.asset_id)),
        dependency_statuses=dep_statuses,
        message=(
            f"Análisis determinístico de {asset.asset_id}: "
            f"classical={sc.classical_risk.total}, quantum={sc.quantum_exposure.total}, "
            f"priority={sc.migration_priority.total}, status={asset.migration_status.value}."
        ),
    )


# ---------------------------------------------------------------------------
# Contrast — CONFLICT vs WARNING vs NO_CONFLICT
# ---------------------------------------------------------------------------

def _cycles_affecting_target(
    asset_id: str, graph: DependencyGraph
) -> List[List[str]]:
    """Ciclos que involucran el activo o sus prerequisitos transitivos."""
    scope = graph.fan_out_transitive(asset_id) | {asset_id}
    relevant: List[List[str]] = []
    for cycle in graph.detect_cycles():
        nodes = set(cycle)
        # quitar el cierre duplicado del último elemento si path[0]==path[-1]
        core = set(cycle[:-1]) if len(cycle) >= 2 and cycle[0] == cycle[-1] else nodes
        if core & scope:
            relevant.append(cycle)
    return relevant


def contrast_decision(
    asset: CryptoAsset,
    analysis: AnalysisResult,
    assets: List[CryptoAsset],
    scores: Dict[str, AssetScores],
    graph: DependencyGraph,
) -> ContrastResult:
    """Contrast via INTCOMP Policy Engine (V4).

    Las políticas son la fuente de verdad. dependency_details se mantiene
    por compatibilidad con la UI y tests existentes.
    """
    by_id = {a.asset_id: a for a in assets}
    details: List[DependencyStatusDetail] = []

    # Dependency details (UI / backward compatibility)
    for dep_id in analysis.dependencies:
        status_str = analysis.dependency_statuses.get(dep_id, "MISSING")
        if status_str == "MISSING":
            details.append(DependencyStatusDetail(dep_id, "MISSING", "MISSING"))
            continue
        status = MigrationStatus(status_str)
        label = _status_label(status)
        details.append(DependencyStatusDetail(dep_id, status_str, label))

    # Policy Engine — deterministic evaluation
    policy_hits = evaluate_policies(
        asset,
        assets,
        scores,
        graph,
        low_agility_threshold=STRESS_TEST_LOW_AGILITY_THRESHOLD,
    )
    triggered = triggered_policies(policy_hits)
    severity = severity_from_policies(policy_hits)
    has_conflict = severity == SEVERITY_CONFLICT

    conflict_reasons: List[str] = []
    warning_reasons: List[str] = []
    for h in triggered:
        if h.decision_effect == "CONFLICT":
            conflict_reasons.append(h.message or f"{h.policy_id} TRIGGERED")
        else:
            warning_reasons.append(h.message or f"{h.policy_id} TRIGGERED")

    if severity == SEVERITY_CONFLICT:
        message = "🔴 CONFLICT: " + " ".join(conflict_reasons)
    elif severity == SEVERITY_WARNING:
        message = "🟡 WARNING: " + " ".join(warning_reasons)
    else:
        message = "🟢 NO CONFLICT: la decisión es consistente con el estado y el grafo."

    return ContrastResult(
        has_conflict=has_conflict,
        severity=severity,
        reasons=conflict_reasons + warning_reasons,
        warnings=warning_reasons,
        dependency_details=details,
        message=message,
        policy_hits=list(policy_hits),
        policies_triggered=[h.policy_id for h in triggered],
    )



# ---------------------------------------------------------------------------
# Decision + Action (dependency-safe sequence)
# ---------------------------------------------------------------------------
def _unresolved_for_sequence(
    asset: CryptoAsset, assets: List[CryptoAsset], graph: DependencyGraph
) -> List[str]:
    """Prerequisitos transitivos aún no migrated."""
    by_id = {a.asset_id: a for a in assets}
    result = []
    for dep_id in graph.fan_out_transitive(asset.asset_id):
        if dep_id not in by_id:
            result.append(dep_id)
            continue
        if by_id[dep_id].migration_status != MigrationStatus.MIGRATED:
            result.append(dep_id)
    return result


def _recommended_sequence(
    asset: CryptoAsset,
    assets: List[CryptoAsset],
    scores: Dict[str, AssetScores],
    graph: DependencyGraph,
) -> List[str]:
    """Secuencia dependency-safe (transitiva). Priority solo desempata."""
    by_id = {a.asset_id: a for a in assets}
    priorities = {aid: sc.migration_priority.total for aid, sc in scores.items()}
    return graph.dependency_safe_sequence(
        target_id=asset.asset_id,
        assets_by_id=by_id,
        priority_scores=priorities,
        include_migrated=False,
    )


def decide(
    asset: CryptoAsset,
    contrast: ContrastResult,
    assets: List[CryptoAsset],
    scores: Dict[str, AssetScores],
    graph: DependencyGraph,
) -> DecisionOutcome:
    # Ciclo: no hay secuencia válida
    if any("DEPENDENCY CYCLE DETECTED" in r for r in contrast.reasons):
        return DecisionOutcome(
            endorsed=False,
            label="DEPENDENCY CYCLE DETECTED",
            recommended_sequence=[],
        )
    if contrast.severity == SEVERITY_CONFLICT:
        return DecisionOutcome(
            endorsed=False,
            label="RECOMMENDED ALTERNATIVE",
            recommended_sequence=_recommended_sequence(asset, assets, scores, graph),
        )
    return DecisionOutcome(
        endorsed=True,
        label="CONFIRMED DECISION",
        recommended_sequence=[asset.asset_id],
    )


def build_action(
    asset: CryptoAsset,
    contrast: ContrastResult,
    decision: DecisionOutcome,
    assets: List[CryptoAsset],
    scores: Dict[str, AssetScores],
    graph: DependencyGraph,
) -> ActionResult:
    by_id = {a.asset_id: a for a in assets}
    sequence = decision.recommended_sequence

    if any("DEPENDENCY CYCLE DETECTED" in r for r in contrast.reasons):
        return ActionResult(
            sequence=[],
            rationale=(
                "ACTION: No valid migration sequence exists until the dependency cycle "
                "is resolved. Break or redesign the circular dependency, then re-run "
                "the Stress Test."
            ),
        )

    if contrast.severity == SEVERITY_CONFLICT:
        rationale = (
            "ACTION: Resolve blocking dependencies first. "
            "Recommended dependency-safe sequence: "
            + (" → ".join(sequence) if sequence else "(none)")
            + "."
        )
        return ActionResult(sequence=sequence, rationale=rationale)

    # WARNING or NO_CONFLICT: actionable guidance without inventing data
    action_lines: List[str] = []
    for detail in contrast.dependency_details:
        if detail.label == "WARNING" and detail.asset_id in by_id:
            dep = by_id[detail.asset_id]
            if detail.status == MigrationStatus.PLANNED.value:
                action_lines.append(
                    f"Complete or coordinate {dep.name} migration before executing "
                    f"{asset.name} migration."
                )
            elif detail.status == MigrationStatus.IN_PROGRESS.value:
                action_lines.append(
                    f"Coordinate with the in-progress migration of {dep.name}; "
                    f"do not start a duplicate process for {dep.name} before continuing "
                    f"{asset.name}."
                )
    if asset.migration_status == MigrationStatus.IN_PROGRESS:
        action_lines.append(
            f"Do not start a duplicate migration process for {asset.name}; "
            "continue or coordinate the existing in_progress work."
        )

    if contrast.severity == SEVERITY_WARNING:
        rationale = "ACTION: " + (
            " ".join(action_lines)
            if action_lines
            else "Proceed with caution given the warnings listed in CONTRAST."
        )
        # sequence remains the single asset for endorsed decisions
        return ActionResult(sequence=sequence, rationale=rationale)

    rationale = (
        f"ACTION: Proceed with the migration of {asset.name} ({asset.asset_id}). "
        "No blocking conflicts detected."
    )
    return ActionResult(sequence=sequence, rationale=rationale)


def _builtin_contrast_explanation(contrast: ContrastResult) -> str:
    if contrast.severity == SEVERITY_NO_CONFLICT:
        return "🟢 NO CONFLICT: la decisión es consistente con el grafo y Migration Status."
    if contrast.severity == SEVERITY_WARNING:
        return "🟡 WARNING: " + " ".join(contrast.warnings or contrast.reasons)
    return "🔴 CONFLICT: " + " ".join(
        r for r in contrast.reasons if r.startswith("BLOCKING") or "CONFLICT" in r
    )


def _builtin_alternative_explanation(action: ActionResult) -> str:
    return (
        "Alternativa determinística dependency-safe: " + " → ".join(action.sequence)
        if action.sequence
        else "Sin secuencia alternativa."
    )


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------
class _LegacyDependency:
    def __init__(self, unresolved_prerequisites, has_conflict, message):
        self.unresolved_prerequisites = unresolved_prerequisites
        self.has_conflict = has_conflict
        self.message = message


class _LegacyRisk:
    def __init__(self, prerequisites_with_similar_or_higher_risk, message):
        self.prerequisites_with_similar_or_higher_risk = prerequisites_with_similar_or_higher_risk
        self.message = message


class _LegacyAgility:
    def __init__(self, is_low_agility, message):
        self.is_low_agility = is_low_agility
        self.message = message


def run_stress_test(
    decision_text: str,
    assets: List[CryptoAsset],
    scores: Dict[str, AssetScores],
    ai_client: Optional["AIClient"] = None,
) -> StressTestResult:
    evidence = evidence_check(decision_text, assets)

    if evidence.resolution == "AMBIGUOUS":
        audit_record = build_decision_audit(
            decision_text=decision_text,
            evidence_resolution="AMBIGUOUS",
            evidence_asset_id=None,
            evidence_candidates=evidence.candidates,
            evidence_message=evidence.message,
            analysis=None,
            policy_hits=[],
            contrast_severity=None,
            contrast_has_conflict=False,
            contrast_reasons=[],
            contrast_warnings=[],
            decision_endorsed=False,
            decision_label="AMBIGUOUS DECISION",
            decision_sequence=[],
            action_sequence=[],
            action_rationale="",
            ai_used=False,
            ai_provider="none",
        )
        return StressTestResult(
            decision_text=decision_text,
            evidence=evidence,
            decision=DecisionOutcome(
                endorsed=False,
                label="AMBIGUOUS DECISION",
                recommended_sequence=[],
            ),
            contrast_explanation=evidence.message,
            audit=audit_record,
            core_decision_snapshot={
                "severity": None,
                "has_conflict": False,
                "endorsed": False,
                "label": "AMBIGUOUS DECISION",
                "sequence": [],
                "policies_triggered": [],
            },
        )

    if not evidence.found or evidence.asset is None:
        audit_record = build_decision_audit(
            decision_text=decision_text,
            evidence_resolution="NOT_FOUND",
            evidence_asset_id=None,
            evidence_candidates=[],
            evidence_message=evidence.message,
            analysis=None,
            policy_hits=[],
            contrast_severity=None,
            contrast_has_conflict=False,
            contrast_reasons=[],
            contrast_warnings=[],
            decision_endorsed=False,
            decision_label="ASSET NOT FOUND",
            decision_sequence=[],
            action_sequence=[],
            action_rationale="",
            ai_used=False,
            ai_provider="none",
        )
        return StressTestResult(
            decision_text=decision_text,
            evidence=evidence,
            decision=DecisionOutcome(
                endorsed=False,
                label="ASSET NOT FOUND",
                recommended_sequence=[],
            ),
            contrast_explanation=evidence.message,
            audit=audit_record,
            core_decision_snapshot={
                "severity": None,
                "has_conflict": False,
                "endorsed": False,
                "label": "ASSET NOT FOUND",
                "sequence": [],
                "policies_triggered": [],
            },
        )

    asset = evidence.asset
    graph = build_graph(assets)
    analysis = analyze_asset(asset, assets, scores, graph)
    contrast = contrast_decision(asset, analysis, assets, scores, graph)
    decision = decide(asset, contrast, assets, scores, graph)
    action = build_action(asset, contrast, decision, assets, scores, graph)

    unresolved = _unresolved_for_sequence(asset, assets, graph)
    legacy_dep = _LegacyDependency(
        unresolved_prerequisites=[
            d.asset_id
            for d in contrast.dependency_details
            if d.label in ("BLOCKING", "MISSING")
        ],
        has_conflict=contrast.has_conflict,
        message=contrast.message,
    )
    higher_risk = [
        d
        for d in unresolved
        if d in scores and scores[d].risk.total >= analysis.risk_score
    ]
    legacy_risk = _LegacyRisk(
        prerequisites_with_similar_or_higher_risk=higher_risk,
        message=(
            f"{len(higher_risk)} prerequisito(s) con Risk >= al del activo."
            if higher_risk
            else "Ningún prerequisito pendiente con mayor riesgo."
        ),
    )
    legacy_agility = _LegacyAgility(
        is_low_agility=analysis.agility_estimate < STRESS_TEST_LOW_AGILITY_THRESHOLD,
        message=(
            f"Crypto Agility Estimate de {asset.asset_id} es {analysis.agility_estimate}/100."
        ),
    )

    # Snapshot del Core ANTES de cualquier IA (autoridad absoluta)
    core_snapshot = {
        "severity": contrast.severity,
        "has_conflict": contrast.has_conflict,
        "endorsed": decision.endorsed,
        "label": decision.label,
        "sequence": list(decision.recommended_sequence),
        "policies_triggered": list(contrast.policies_triggered),
    }

    contrast_explanation = _builtin_contrast_explanation(contrast)
    alternative_explanation = (
        _builtin_alternative_explanation(action) if not decision.endorsed else ""
    )

    ai_used = False
    ai_provider = "none"
    ai_explanation_conflict = False

    if ai_client is not None:
        ai_used = True
        ai_provider = type(ai_client).__name__
        context = {
            "asset_id": asset.asset_id,
            "has_conflict": contrast.has_conflict,
            "severity": contrast.severity,
            "reasons": contrast.reasons,
            # Explicit instruction: AI must not contradict Core
            "core_decision": core_snapshot["label"],
            "core_severity": core_snapshot["severity"],
        }
        try:
            ai_text = ai_client.explain_contrast(context)
            # Detect if AI text tries to contradict Core (heuristic, non-authoritative)
            if _ai_contradicts_core(ai_text, contrast.severity, decision.endorsed):
                ai_explanation_conflict = True
                contrast_explanation = (
                    f"[AI EXPLANATION CONFLICT — Core decision preserved]\n"
                    f"Core Decision: {contrast.severity} / {decision.label}\n"
                    f"AI Output (ignored for authority): {ai_text[:500]}"
                )
            else:
                contrast_explanation = ai_text
        except Exception:  # noqa: BLE001
            pass
        if not decision.endorsed:
            try:
                alternative_explanation = ai_client.explain_alternative(
                    {"sequence": action.sequence, "rationale": action.rationale}
                )
            except Exception:  # noqa: BLE001
                pass

    # Decision Audit (structured, exportable)
    audit_record = build_decision_audit(
        decision_text=decision_text,
        evidence_resolution=evidence.resolution,
        evidence_asset_id=asset.asset_id,
        evidence_candidates=evidence.candidates,
        evidence_message=evidence.message,
        analysis=analysis,
        policy_hits=contrast.policy_hits,
        contrast_severity=contrast.severity,
        contrast_has_conflict=contrast.has_conflict,
        contrast_reasons=contrast.reasons,
        contrast_warnings=contrast.warnings,
        decision_endorsed=decision.endorsed,
        decision_label=decision.label,
        decision_sequence=decision.recommended_sequence,
        action_sequence=action.sequence,
        action_rationale=action.rationale,
        ai_used=ai_used,
        ai_provider=ai_provider,
        ai_explanation_conflict=ai_explanation_conflict,
    )

    audit_event(
        "stress_test",
        f"decision={decision_text[:120]!r} asset={asset.asset_id} "
        f"severity={contrast.severity} conflict={contrast.has_conflict} "
        f"label={decision.label} policies={contrast.policies_triggered}",
    )
    return StressTestResult(
        decision_text=decision_text,
        evidence=evidence,
        analysis=analysis,
        contrast=contrast,
        decision=decision,
        action=action,
        dependency=legacy_dep,
        risk=legacy_risk,
        agility=legacy_agility,
        alternative_action=action if not decision.endorsed else None,
        contrast_explanation=contrast_explanation,
        alternative_explanation=alternative_explanation,
        audit=audit_record,
        ai_explanation_conflict=ai_explanation_conflict,
        core_decision_snapshot=core_snapshot,
    )


def _ai_contradicts_core(
    ai_text: str, severity: str, endorsed: bool
) -> bool:
    """Heuristic: detect if AI explanation claims the opposite of Core.

    This never changes the decision; it only flags the explanation.
    """
    if not ai_text:
        return False
    text = ai_text.lower()
    if severity == SEVERITY_CONFLICT:
        # AI claiming safety / approval despite CONFLICT
        safe_claims = [
            "no conflict",
            "safe to migrate",
            "approved",
            "sin conflicto",
            "es seguro",
            "puede migrar sin",
            "decision is safe",
            "no blocking",
        ]
        if any(c in text for c in safe_claims):
            return True
    if not endorsed:
        if "confirmed decision" in text or "decisión confirmada" in text:
            return True
    return False
