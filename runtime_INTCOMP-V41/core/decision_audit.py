"""INTCOMP Decision Audit — registro estructurado y exportable de cada Stress Test.

El audit captura evidencia, análisis, políticas activadas, contraste, decisión
y acción. La IA aparece solo como capa de explicación con autoridad cero.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from core.policy_engine import PolicyHit


@dataclass
class EvidenceAudit:
    resolution: str  # FOUND | AMBIGUOUS | NOT_FOUND
    asset_id: Optional[str]
    candidates: List[str] = field(default_factory=list)
    inventory_validated: bool = True
    dependencies_available: bool = True
    message: str = ""


@dataclass
class AnalysisAudit:
    classical_risk: int = 0
    quantum_exposure: int = 0
    risk_score: int = 0
    agility_estimate: int = 0
    dependency_impact: int = 0
    strategic_impact: int = 0
    migration_priority: int = 0
    migration_status: str = ""
    dependencies: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)


@dataclass
class ContrastAudit:
    severity: str  # NO_CONFLICT | WARNING | CONFLICT
    has_conflict: bool = False
    policies_triggered: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class DecisionAuditSection:
    endorsed: bool = False
    label: str = ""
    recommended_sequence: List[str] = field(default_factory=list)


@dataclass
class ActionAudit:
    sequence: List[str] = field(default_factory=list)
    rationale: str = ""


@dataclass
class AIAudit:
    used: bool = False
    authority: str = "NONE"  # always NONE
    role: str = "EXPLANATION_ONLY"
    provider: str = "none"
    explanation_conflict: bool = False
    note: str = "AI may explain; AI cannot make or modify the decision."


@dataclass
class DecisionAuditRecord:
    """Registro completo de una ejecución del Decision Stress Test."""

    decision_id: str
    timestamp_utc: str
    user_decision: str
    evidence: EvidenceAudit
    analysis: Optional[AnalysisAudit]
    policies: List[Dict[str, Any]]
    contrast: Optional[ContrastAudit]
    decision: Optional[DecisionAuditSection]
    action: Optional[ActionAudit]
    ai: AIAudit
    core_authority: str = "ABSOLUTE"
    methodology: str = "INTCOMP"
    version: str = "4.1.0"
    policy_set_id: str = "intcomp-cryptorisk-v1"
    policy_set_version: str = "1.0.0"
    policy_set_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary_lines(self) -> List[str]:
        lines = [
            "INTCOMP DECISION AUDIT",
            f"Decision ID: {self.decision_id}",
            f"Timestamp:   {self.timestamp_utc}",
            f"User Decision: {self.user_decision!r}",
            "",
            "Evidence:",
            f"  Resolution: {self.evidence.resolution}",
        ]
        if self.evidence.asset_id:
            lines.append(f"  Asset: {self.evidence.asset_id}")
        if self.evidence.candidates:
            lines.append(f"  Candidates: {', '.join(self.evidence.candidates)}")
        lines.append(f"  Inventory validated: {self.evidence.inventory_validated}")
        lines.append(f"  Dependencies available: {self.evidence.dependencies_available}")
        lines.append("")

        if self.analysis:
            lines.append("Analysis:")
            lines.append(f"  Risk Score: {self.analysis.risk_score}")
            lines.append(f"  Quantum Exposure: {self.analysis.quantum_exposure}")
            lines.append(f"  Crypto Agility Estimate: {self.analysis.agility_estimate}")
            lines.append(f"  Strategic Impact: {self.analysis.strategic_impact}")
            lines.append(f"  Dependency Impact: {self.analysis.dependency_impact}")
            lines.append(f"  Migration Priority: {self.analysis.migration_priority}")
            lines.append(f"  Migration Status: {self.analysis.migration_status}")
            lines.append("")

        triggered = [p for p in self.policies if p.get("status") == "TRIGGERED"]
        blocking = [p for p in triggered if p.get("decision_effect") == "CONFLICT"]
        lines.append(f"Policies Triggered: {len(triggered)}")
        if blocking:
            lines.append(f"Blocking Policies: {', '.join(p['policy_id'] for p in blocking)}")
        for p in triggered:
            marker = " [BLOCKING]" if p.get("decision_effect") == "CONFLICT" else ""
            ver = p.get("policy_version", "")
            ver_s = f" v{ver}" if ver else ""
            lines.append(
                f"  {p['policy_id']}{ver_s} — {p['name']} "
                f"[{p.get('severity', '')}] → {p.get('decision_effect', '')}{marker}"
            )
        lines.append("")

        if self.contrast:
            lines.append(f"Contrast: {self.contrast.severity}")
            lines.append(f"  has_conflict: {self.contrast.has_conflict}")
            lines.append("")

        if self.decision:
            lines.append(f"Decision: {self.decision.label}")
            lines.append(f"  endorsed: {self.decision.endorsed}")
            if self.decision.recommended_sequence:
                lines.append(
                    "  sequence: " + " → ".join(self.decision.recommended_sequence)
                )
            lines.append("")

        if self.action and self.action.sequence:
            lines.append("Action:")
            lines.append("  " + " → ".join(self.action.sequence))
            lines.append("")

        lines.append("AI:")
        lines.append(f"  USED: {self.ai.used}")
        lines.append(f"  AI AUTHORITY: {self.ai.authority}")
        lines.append(f"  AI ROLE: {self.ai.role}")
        lines.append(f"  Provider: {self.ai.provider}")
        if self.ai.explanation_conflict:
            lines.append("  AI EXPLANATION CONFLICT: detected (Core decision preserved)")
        lines.append("")
        lines.append(f"Core Authority: {self.core_authority}")
        lines.append(f"Methodology: {self.methodology} {self.version}")
        lines.append(f"Policy Set: {self.policy_set_id} @ {self.policy_set_version}")
        if self.policy_set_sha256:
            lines.append(f"Policy Set SHA-256: {self.policy_set_sha256}")
        return lines


def _make_decision_id(decision_text: str, asset_id: Optional[str]) -> str:
    raw = f"{decision_text}|{asset_id or ''}|{datetime.now(timezone.utc).isoformat()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10].upper()
    return f"INC-{digest}"


def build_decision_audit(
    *,
    decision_text: str,
    evidence_resolution: str,
    evidence_asset_id: Optional[str],
    evidence_candidates: Sequence[str],
    evidence_message: str,
    analysis: Optional[Any],
    policy_hits: Sequence[PolicyHit],
    contrast_severity: Optional[str],
    contrast_has_conflict: bool,
    contrast_reasons: Sequence[str],
    contrast_warnings: Sequence[str],
    decision_endorsed: Optional[bool],
    decision_label: Optional[str],
    decision_sequence: Sequence[str],
    action_sequence: Sequence[str],
    action_rationale: str,
    ai_used: bool,
    ai_provider: str = "none",
    ai_explanation_conflict: bool = False,
) -> DecisionAuditRecord:
    """Construye el registro de auditoría a partir de resultados del Core."""
    decision_id = _make_decision_id(decision_text, evidence_asset_id)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    evidence = EvidenceAudit(
        resolution=evidence_resolution,
        asset_id=evidence_asset_id,
        candidates=list(evidence_candidates),
        inventory_validated=True,
        dependencies_available=evidence_resolution == "FOUND",
        message=evidence_message,
    )

    analysis_audit: Optional[AnalysisAudit] = None
    if analysis is not None:
        analysis_audit = AnalysisAudit(
            classical_risk=getattr(analysis, "classical_risk", 0),
            quantum_exposure=getattr(analysis, "quantum_exposure", 0),
            risk_score=getattr(analysis, "risk_score", 0),
            agility_estimate=getattr(analysis, "agility_estimate", 0),
            dependency_impact=getattr(analysis, "dependency_impact", 0),
            strategic_impact=getattr(analysis, "strategic_impact", 0),
            migration_priority=getattr(analysis, "migration_priority", 0),
            migration_status=getattr(analysis, "migration_status", ""),
            dependencies=list(getattr(analysis, "dependencies", []) or []),
            dependents=list(getattr(analysis, "dependents", []) or []),
        )

    from core.policy_engine import POLICY_SET_ID, POLICY_SET_VERSION, get_policy

    policies = []
    for h in policy_hits:
        pol = get_policy(h.policy_id)
        policies.append(
            {
                "policy_id": h.policy_id,
                "policy_version": pol.version if pol else "1.0.0",
                "name": h.name,
                "status": h.status,
                "severity": h.severity,
                "category": h.category,
                "decision_effect": h.decision_effect,
                "evidence": h.evidence,
                "message": h.message,
                "human_explanation": h.human_explanation,
            }
        )

    contrast_audit: Optional[ContrastAudit] = None
    if contrast_severity is not None:
        triggered_ids = [h.policy_id for h in policy_hits if h.status == "TRIGGERED"]
        contrast_audit = ContrastAudit(
            severity=contrast_severity,
            has_conflict=contrast_has_conflict,
            policies_triggered=triggered_ids,
            reasons=list(contrast_reasons),
            warnings=list(contrast_warnings),
        )

    decision_section: Optional[DecisionAuditSection] = None
    if decision_label is not None:
        decision_section = DecisionAuditSection(
            endorsed=bool(decision_endorsed),
            label=decision_label,
            recommended_sequence=list(decision_sequence),
        )

    action_audit: Optional[ActionAudit] = None
    if action_sequence or action_rationale:
        action_audit = ActionAudit(
            sequence=list(action_sequence),
            rationale=action_rationale or "",
        )

    ai_audit = AIAudit(
        used=ai_used,
        authority="NONE",
        role="EXPLANATION_ONLY",
        provider=ai_provider,
        explanation_conflict=ai_explanation_conflict,
        note="AI may explain; AI cannot make or modify the decision.",
    )

    from core.policy_engine import POLICY_SET_ID, POLICY_SET_SHA256, POLICY_SET_VERSION

    return DecisionAuditRecord(
        decision_id=decision_id,
        timestamp_utc=ts,
        user_decision=decision_text,
        evidence=evidence,
        analysis=analysis_audit,
        policies=policies,
        contrast=contrast_audit,
        decision=decision_section,
        action=action_audit,
        ai=ai_audit,
        policy_set_id=POLICY_SET_ID,
        policy_set_version=POLICY_SET_VERSION,
        policy_set_sha256=POLICY_SET_SHA256,
    )
