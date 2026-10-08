"""INTCOMP Policy Engine — políticas explícitas, identificables y auditables.

Las reglas de Contrast se elevan a políticas declarativas cargadas desde
`config/policies.yaml` (con fallback embebido).

La lógica de evaluación permanece en Python y es 100% determinística.
Ninguna política es evaluada por IA.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.dependency_engine import DependencyGraph
from core.models import AssetScores, CryptoAsset, MigrationStatus


class PolicySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PolicyCategory(str, Enum):
    DEPENDENCY = "DEPENDENCY"
    MIGRATION_STATUS = "MIGRATION_STATUS"
    STRUCTURAL = "STRUCTURAL"
    RISK_SIGNAL = "RISK_SIGNAL"
    EVIDENCE = "EVIDENCE"


class DecisionEffect(str, Enum):
    CONFLICT = "CONFLICT"
    WARNING = "WARNING"
    BLOCK_SEQUENCE = "BLOCK_SEQUENCE"
    NONE = "NONE"


@dataclass(frozen=True)
class PolicyDefinition:
    policy_id: str
    name: str
    description: str
    category: PolicyCategory
    severity: PolicySeverity
    evidence_required: List[str]
    decision_effect: DecisionEffect
    human_explanation: str
    version: str = "1.0.0"


@dataclass
class PolicyHit:
    policy_id: str
    name: str
    status: str  # TRIGGERED | NOT_TRIGGERED
    severity: str
    category: str
    decision_effect: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    human_explanation: str = ""
    message: str = ""


_DEFAULT_THRESHOLDS: Dict[str, int] = {
    "quantum_exposure_high": 70,
    "risk_score_high": 70,
    "strategic_impact_high": 60,
    "agility_low": 40,
}

_EMBEDDED_POLICIES: List[Dict[str, Any]] = [
    {
        "policy_id": "P001",
        "name": "Dependency Cycle",
        "description": "Detecta ciclos de dependencia que involucran el activo o sus prerequisitos.",
        "category": "STRUCTURAL",
        "severity": "CRITICAL",
        "evidence_required": ["dependency_graph", "target_asset"],
        "decision_effect": "CONFLICT",
        "human_explanation": "Existe un ciclo de dependencia. No hay secuencia de migracion valida hasta que el ciclo se resuelva.",
        "enabled": True,
    },
    {
        "policy_id": "P002",
        "name": "Unresolved Dependency (not_started)",
        "description": "Una dependencia directa esta en estado not_started.",
        "category": "DEPENDENCY",
        "severity": "HIGH",
        "evidence_required": ["dependencies", "migration_status"],
        "decision_effect": "CONFLICT",
        "human_explanation": "Hay dependencias que aun no han iniciado migracion. Migrar el activo ahora violaria el orden de dependencias.",
        "enabled": True,
    },
    {
        "policy_id": "P003",
        "name": "Missing Dependency Evidence",
        "description": "Una dependencia referenciada no existe en el inventario.",
        "category": "EVIDENCE",
        "severity": "CRITICAL",
        "evidence_required": ["dependencies", "inventory"],
        "decision_effect": "CONFLICT",
        "human_explanation": "El inventario referencia una dependencia que no existe. La evidencia es incompleta.",
        "enabled": True,
    },
    {
        "policy_id": "P004",
        "name": "Target Already Migrated",
        "description": "El activo objetivo ya esta en estado migrated.",
        "category": "MIGRATION_STATUS",
        "severity": "HIGH",
        "evidence_required": ["migration_status"],
        "decision_effect": "CONFLICT",
        "human_explanation": "El activo ya fue migrado. Iniciar otra migracion produciria trabajo duplicado.",
        "enabled": True,
    },
    {
        "policy_id": "P005",
        "name": "Dependency Planned",
        "description": "Una dependencia directa esta en estado planned.",
        "category": "DEPENDENCY",
        "severity": "MEDIUM",
        "evidence_required": ["dependencies", "migration_status"],
        "decision_effect": "WARNING",
        "human_explanation": "Existe planificacion para la dependencia, pero aun no se ha ejecutado.",
        "enabled": True,
    },
    {
        "policy_id": "P006",
        "name": "Dependency In Progress",
        "description": "Una dependencia directa esta en estado in_progress.",
        "category": "DEPENDENCY",
        "severity": "MEDIUM",
        "evidence_required": ["dependencies", "migration_status"],
        "decision_effect": "WARNING",
        "human_explanation": "La dependencia ya tiene un proceso de migracion en curso.",
        "enabled": True,
    },
    {
        "policy_id": "P007",
        "name": "Target In Progress",
        "description": "El activo objetivo ya esta in_progress.",
        "category": "MIGRATION_STATUS",
        "severity": "MEDIUM",
        "evidence_required": ["migration_status"],
        "decision_effect": "WARNING",
        "human_explanation": "El activo ya tiene migracion en curso. No iniciar un proceso duplicado.",
        "enabled": True,
    },
    {
        "policy_id": "P008",
        "name": "Higher Priority Prerequisite Pending",
        "description": "Una dependencia tiene Migration Priority mayor y aun no esta migrada.",
        "category": "RISK_SIGNAL",
        "severity": "LOW",
        "evidence_required": ["dependencies", "migration_priority", "migration_status"],
        "decision_effect": "WARNING",
        "human_explanation": "Hay prerequisitos con mayor prioridad de migracion aun pendientes.",
        "enabled": True,
    },
    {
        "policy_id": "P009",
        "name": "High Quantum Exposure Signal",
        "description": "Quantum Exposure del activo es alto (heuristico).",
        "category": "RISK_SIGNAL",
        "severity": "LOW",
        "evidence_required": ["quantum_exposure"],
        "decision_effect": "WARNING",
        "human_explanation": "Indicador heuristico de exposicion cuantica alto. No es una probabilidad de ataque.",
        "enabled": True,
        "threshold_key": "quantum_exposure_high",
    },
    {
        "policy_id": "P010",
        "name": "High Risk Score Signal",
        "description": "Risk Score compuesto del activo es alto (heuristico).",
        "category": "RISK_SIGNAL",
        "severity": "LOW",
        "evidence_required": ["risk_score"],
        "decision_effect": "WARNING",
        "human_explanation": "Indicador heuristico de riesgo compuesto alto.",
        "enabled": True,
        "threshold_key": "risk_score_high",
    },
    {
        "policy_id": "P011",
        "name": "High Strategic Impact Signal",
        "description": "Strategic Impact del activo es alto (heuristico).",
        "category": "RISK_SIGNAL",
        "severity": "LOW",
        "evidence_required": ["strategic_impact"],
        "decision_effect": "WARNING",
        "human_explanation": "El activo tiene alto impacto estrategico.",
        "enabled": True,
        "threshold_key": "strategic_impact_high",
    },
    {
        "policy_id": "P012",
        "name": "Low Crypto Agility Signal",
        "description": "Crypto Agility Estimate bajo (heuristico).",
        "category": "RISK_SIGNAL",
        "severity": "LOW",
        "evidence_required": ["agility_estimate"],
        "decision_effect": "WARNING",
        "human_explanation": "Estimacion heuristica de agilidad criptografica baja.",
        "enabled": True,
        "threshold_key": "agility_low",
    },
]


def _policies_yaml_path() -> Path:
    """Prefer policies/v1/policies.yaml; fallback to config/policies.yaml."""
    here = Path(__file__).resolve().parent.parent
    for rel in (
        ("policies", "v1", "policies.yaml"),
        ("config", "policies.yaml"),
    ):
        candidate = here.joinpath(*rel)
        if candidate.is_file():
            return candidate
    return here / "policies" / "v1" / "policies.yaml"


def _parse_policy_row(row: Dict[str, Any]) -> Optional[PolicyDefinition]:
    try:
        if row.get("enabled", True) is False:
            return None
        return PolicyDefinition(
            policy_id=str(row["policy_id"]),
            name=str(row["name"]),
            description=str(row.get("description", "")).strip(),
            category=PolicyCategory(str(row["category"])),
            severity=PolicySeverity(str(row["severity"])),
            evidence_required=[str(x) for x in row.get("evidence_required", [])],
            decision_effect=DecisionEffect(str(row["decision_effect"])),
            human_explanation=str(row.get("human_explanation", "")).strip(),
            version=str(row.get("version", "1.0.0")),
        )
    except (KeyError, ValueError):
        return None


def _load_from_yaml():
    import yaml

    path = _policies_yaml_path()
    if not path.is_file():
        raise FileNotFoundError(str(path))
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "policies" not in data:
        raise ValueError("policies.yaml invalido: falta clave policies")
    catalog: Dict[str, PolicyDefinition] = {}
    for row in data["policies"]:
        if not isinstance(row, dict):
            continue
        parsed = _parse_policy_row(row)
        if parsed is not None:
            catalog[parsed.policy_id] = parsed
    if not catalog:
        raise ValueError("policies.yaml no contiene politicas validas")
    thresholds = dict(_DEFAULT_THRESHOLDS)
    raw_th = data.get("thresholds") or {}
    if isinstance(raw_th, dict):
        for k, v in raw_th.items():
            try:
                thresholds[str(k)] = int(v)
            except (TypeError, ValueError):
                pass
    # Integrity: SHA-256 of the policy file bytes (raw on-disk content)
    file_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    meta = {
        "policy_set_id": str(data.get("policy_set_id", "intcomp-cryptorisk-v1")),
        "policy_set_version": str(data.get("policy_set_version") or data.get("version") or "1.0.0"),
        "policy_set_sha256": file_sha256,
    }
    return catalog, thresholds, meta


def _load_embedded():
    catalog: Dict[str, PolicyDefinition] = {}
    for row in _EMBEDDED_POLICIES:
        parsed = _parse_policy_row(row)
        if parsed is not None:
            catalog[parsed.policy_id] = parsed
    # Deterministic hash of embedded policy ids/effects (not a file)
    import json
    emb_struct = [
        {
            "policy_id": r.get("policy_id"),
            "version": r.get("version", "1.0.0"),
            "decision_effect": r.get("decision_effect"),
            "enabled": r.get("enabled", True),
        }
        for r in _EMBEDDED_POLICIES
    ]
    emb_bytes = json.dumps(emb_struct, sort_keys=True, separators=(",", ":")).encode("utf-8")
    meta = {
        "policy_set_id": "intcomp-cryptorisk-v1-embedded",
        "policy_set_version": "1.0.0",
        "policy_set_sha256": hashlib.sha256(emb_bytes).hexdigest(),
    }
    return catalog, dict(_DEFAULT_THRESHOLDS), meta


POLICY_CATALOG: Dict[str, PolicyDefinition] = {}
POLICY_THRESHOLDS: Dict[str, int] = dict(_DEFAULT_THRESHOLDS)
_CATALOG_SOURCE: str = "uninitialized"
POLICY_SET_ID: str = "intcomp-cryptorisk-v1"
POLICY_SET_VERSION: str = "1.0.0"
POLICY_SET_SHA256: str = ""


def load_policy_catalog(force_reload: bool = False):
    global POLICY_CATALOG, POLICY_THRESHOLDS, _CATALOG_SOURCE
    global POLICY_SET_ID, POLICY_SET_VERSION, POLICY_SET_SHA256
    if POLICY_CATALOG and not force_reload:
        return POLICY_CATALOG, POLICY_THRESHOLDS
    try:
        catalog, thresholds, meta = _load_from_yaml()
        source = "yaml"
    except Exception:
        catalog, thresholds, meta = _load_embedded()
        source = "embedded"
    POLICY_CATALOG = catalog
    POLICY_THRESHOLDS = thresholds
    _CATALOG_SOURCE = source
    POLICY_SET_ID = meta.get("policy_set_id", "intcomp-cryptorisk-v1")
    POLICY_SET_VERSION = meta.get("policy_set_version", "1.0.0")
    POLICY_SET_SHA256 = str(meta.get("policy_set_sha256", "") or "")
    return POLICY_CATALOG, POLICY_THRESHOLDS


def catalog_source() -> str:
    return _CATALOG_SOURCE


def policy_set_info() -> Dict[str, str]:
    """Metadata del policy set activo (para Decision Audit)."""
    return {
        "policy_set_id": POLICY_SET_ID,
        "policy_set_version": POLICY_SET_VERSION,
        "policy_set_sha256": POLICY_SET_SHA256,
        "catalog_source": _CATALOG_SOURCE,
    }


load_policy_catalog()


def list_policies() -> List[PolicyDefinition]:
    if not POLICY_CATALOG:
        load_policy_catalog()
    return list(POLICY_CATALOG.values())


def get_policy(policy_id: str) -> Optional[PolicyDefinition]:
    if not POLICY_CATALOG:
        load_policy_catalog()
    return POLICY_CATALOG.get(policy_id)


def _cycles_affecting(asset_id: str, graph: DependencyGraph) -> List[List[str]]:
    scope = graph.fan_out_transitive(asset_id) | {asset_id}
    relevant: List[List[str]] = []
    for cycle in graph.detect_cycles():
        core = set(cycle[:-1]) if len(cycle) >= 2 and cycle[0] == cycle[-1] else set(cycle)
        if core & scope:
            relevant.append(cycle)
    return relevant


def _require_policy(policy_id: str) -> Optional[PolicyDefinition]:
    return POLICY_CATALOG.get(policy_id)


def _hit(
    p: PolicyDefinition,
    *,
    triggered: bool,
    evidence: Optional[Dict[str, Any]] = None,
    message: str = "",
) -> PolicyHit:
    return PolicyHit(
        policy_id=p.policy_id,
        name=p.name,
        status="TRIGGERED" if triggered else "NOT_TRIGGERED",
        severity=p.severity.value,
        category=p.category.value,
        decision_effect=p.decision_effect.value,
        evidence=evidence or {},
        human_explanation=p.human_explanation,
        message=message if triggered else "",
    )


def evaluate_policies(
    asset: CryptoAsset,
    assets: Sequence[CryptoAsset],
    scores: Dict[str, AssetScores],
    graph: DependencyGraph,
    *,
    low_agility_threshold: Optional[int] = None,
) -> List[PolicyHit]:
    if not POLICY_CATALOG:
        load_policy_catalog()

    by_id = {a.asset_id: a for a in assets}
    sc = scores.get(asset.asset_id)
    hits: List[PolicyHit] = []
    th = POLICY_THRESHOLDS

    p = _require_policy("P001")
    if p is not None:
        cycles = _cycles_affecting(asset.asset_id, graph)
        if cycles:
            shown = " ; ".join(" -> ".join(c) for c in cycles[:3])
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"cycles": cycles[:3], "target": asset.asset_id},
                    message=f"DEPENDENCY CYCLE DETECTED: {shown}",
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    p = _require_policy("P004")
    if p is not None:
        if asset.migration_status == MigrationStatus.MIGRATED:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"migration_status": asset.migration_status.value},
                    message=f"BLOCKING CONFLICT: {asset.asset_id} ya esta en estado 'migrated'.",
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    p = _require_policy("P007")
    if p is not None:
        if asset.migration_status == MigrationStatus.IN_PROGRESS:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"migration_status": asset.migration_status.value},
                    message=f"WARNING: {asset.asset_id} ya esta 'in_progress' — no iniciar un proceso duplicado.",
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    unresolved_not_started: List[str] = []
    missing_deps: List[str] = []
    planned_deps: List[str] = []
    in_progress_deps: List[str] = []
    higher_priority_pending: List[Dict[str, Any]] = []
    own_priority = sc.migration_priority.total if sc else 0

    for dep_id in asset.dependencies:
        if dep_id not in by_id:
            missing_deps.append(dep_id)
            continue
        dep = by_id[dep_id]
        st = dep.migration_status
        if st == MigrationStatus.NOT_STARTED:
            unresolved_not_started.append(dep_id)
        elif st == MigrationStatus.PLANNED:
            planned_deps.append(dep_id)
        elif st == MigrationStatus.IN_PROGRESS:
            in_progress_deps.append(dep_id)
        if st != MigrationStatus.MIGRATED and dep_id in scores:
            dep_pri = scores[dep_id].migration_priority.total
            if dep_pri > own_priority:
                higher_priority_pending.append(
                    {
                        "dependency": dep_id,
                        "dependency_priority": dep_pri,
                        "target_priority": own_priority,
                    }
                )

    p = _require_policy("P003")
    if p is not None:
        if missing_deps:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"missing_dependencies": missing_deps},
                    message=(
                        "BLOCKING CONFLICT: dependencia(s) MISSING / no existe(n) "
                        "en el inventario: " + ", ".join(missing_deps)
                    ),
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    p = _require_policy("P002")
    if p is not None:
        if unresolved_not_started:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"unresolved_dependencies": unresolved_not_started},
                    message=(
                        "BLOCKING CONFLICT: UNRESOLVED DEPENDENCY "
                        + ", ".join(unresolved_not_started)
                        + " esta(n) en 'not_started'."
                    ),
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    p = _require_policy("P005")
    if p is not None:
        if planned_deps:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"planned_dependencies": planned_deps},
                    message="WARNING: dependencia(s) planned: " + ", ".join(planned_deps),
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    p = _require_policy("P006")
    if p is not None:
        if in_progress_deps:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"in_progress_dependencies": in_progress_deps},
                    message="WARNING: dependencia(s) in_progress: " + ", ".join(in_progress_deps),
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    p = _require_policy("P008")
    if p is not None:
        if higher_priority_pending:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={"higher_priority_prerequisites": higher_priority_pending},
                    message="WARNING: prerequisito(s) con mayor Migration Priority aun pendientes.",
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    quantum = sc.quantum_exposure.total if sc else 0
    risk = sc.risk.total if sc else 0
    strategic = sc.strategic_impact.total if sc else 0
    agility = sc.agility_estimate.total if sc else 100

    q_th = int(th.get("quantum_exposure_high", 70))
    r_th = int(th.get("risk_score_high", 70))
    s_th = int(th.get("strategic_impact_high", 60))
    a_th = (
        int(low_agility_threshold)
        if low_agility_threshold is not None
        else int(th.get("agility_low", 40))
    )

    for pid, threshold_check, value, label in [
        ("P009", quantum >= q_th, quantum, "Quantum Exposure"),
        ("P010", risk >= r_th, risk, "Risk Score"),
        ("P011", strategic >= s_th, strategic, "Strategic Impact"),
        ("P012", agility < a_th, agility, "Crypto Agility Estimate"),
    ]:
        p = _require_policy(pid)
        if p is None:
            continue
        if threshold_check:
            hits.append(
                _hit(
                    p,
                    triggered=True,
                    evidence={label.lower().replace(" ", "_"): value},
                    message=f"WARNING: {label} heuristico ({value}/100).",
                )
            )
        else:
            hits.append(_hit(p, triggered=False))

    hits.sort(key=lambda h: h.policy_id)
    return hits


def triggered_policies(hits: Sequence[PolicyHit]) -> List[PolicyHit]:
    return [h for h in hits if h.status == "TRIGGERED"]


def severity_from_policies(hits: Sequence[PolicyHit]) -> str:
    triggered = triggered_policies(hits)
    if any(h.decision_effect == DecisionEffect.CONFLICT.value for h in triggered):
        return "CONFLICT"
    if any(h.decision_effect == DecisionEffect.WARNING.value for h in triggered):
        return "WARNING"
    return "NO_CONFLICT"
