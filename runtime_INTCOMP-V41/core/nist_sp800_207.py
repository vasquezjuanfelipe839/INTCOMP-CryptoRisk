"""Validación heurística alineada a NIST SP 800-207 (Zero Trust Architecture).

Referencia: Rose et al., NIST SP 800-207, Zero Trust Architecture (2020).
https://doi.org/10.6028/NIST.SP.800-207

IMPORTANTE:
- Esto NO es una certificación ni una auditoría formal de Zero Trust.
- Evalúa alineación *relativa* del inventario criptográfico con los 7
  principios básicos (tenets) de SP 800-207, usando solo datos del CSV
  y scores ya calculados.
- Determinístico: sin IA.

Los 7 tenets (SP 800-207 §2.1):
  1. All data sources and computing services are considered resources.
  2. All communication is secured regardless of network location.
  3. Access to individual enterprise resources is granted on a per-session basis.
  4. Access to resources is determined by dynamic policy.
  5. The enterprise monitors and measures the integrity and security posture
     of all owned and associated assets.
  6. All resource authentication and authorization are dynamic and strictly
     enforced before access is allowed.
  7. The enterprise collects as much information as possible about the current
     state of assets, network infrastructure and communications and uses it
     to improve its security posture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence

from core.models import AssetScores, CryptoAsset, MigrationStatus, ScoreBreakdown
from crypto.algorithm_catalog import get_algorithm_profile


class TenetStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"  # no hay datos suficientes en el inventario


@dataclass
class TenetResult:
    tenet_id: int
    title: str
    status: TenetStatus
    score: int  # 0-100 alignment contribution
    evidence: str
    recommendation: str


@dataclass
class AssetZTAResult:
    asset_id: str
    tenets: List[TenetResult]
    alignment_score: int  # 0-100 average
    gaps: List[str] = field(default_factory=list)


@dataclass
class InventoryZTAReport:
    """Resultado de validación SP 800-207 sobre todo el inventario."""

    assets: List[AssetZTAResult]
    inventory_alignment: int  # media
    tenet_summary: Dict[int, Dict[str, int]]  # tenet_id -> {pass,warn,fail,unknown}
    notes: List[str] = field(default_factory=list)


TENET_TITLES = {
    1: "All data sources and computing services are considered resources",
    2: "All communication is secured regardless of network location",
    3: "Access to individual enterprise resources is granted on a per-session basis",
    4: "Access to resources is determined by dynamic policy",
    5: "Enterprise monitors and measures integrity and security posture of assets",
    6: "Authentication and authorization are dynamic and strictly enforced before access",
    7: "Enterprise collects state information and uses it to improve security posture",
}


# Protocol modernity for tenet 2 (communication secured)
_STRONG_PROTOCOLS = {"TLS 1.3", "SSH-2"}
_ACCEPTABLE_PROTOCOLS = {"TLS 1.2", "IPSEC", "IPsec"}
_WEAK_PROTOCOLS = {"TLS 1.0", "TLS 1.1", "PROPRIETARY", "Proprietary"}


def _tenet1_resource_inventory(asset: CryptoAsset) -> TenetResult:
    """Tenet 1: being in a validated inventory satisfies 'considered a resource'."""
    return TenetResult(
        tenet_id=1,
        title=TENET_TITLES[1],
        status=TenetStatus.PASS,
        score=100,
        evidence=f"Asset '{asset.asset_id}' is present in the validated cryptographic inventory.",
        recommendation="Keep inventory complete; register new services before production use.",
    )


def _tenet2_secured_communication(
    asset: CryptoAsset, scores: Optional[AssetScores]
) -> TenetResult:
    """Tenet 2: communication secured regardless of location.

    Heuristic from protocol + classical/quantum crypto indicators + exposure.
    """
    proto = asset.protocol.strip()
    proto_u = proto.upper()
    profile = get_algorithm_profile(asset.algorithm)

    issues = []
    score = 100
    status = TenetStatus.PASS

    if proto_u in {p.upper() for p in _WEAK_PROTOCOLS} or "PROPRIETARY" in proto_u:
        issues.append(f"Weak/legacy protocol '{asset.protocol}'")
        score -= 40
        status = TenetStatus.FAIL
    elif proto_u in {p.upper() for p in _ACCEPTABLE_PROTOCOLS}:
        issues.append(f"Protocol '{asset.protocol}' acceptable but not strongest available")
        score -= 15
        if status == TenetStatus.PASS:
            status = TenetStatus.WARN
    elif proto_u not in {p.upper() for p in _STRONG_PROTOCOLS}:
        issues.append(f"Protocol '{asset.protocol}' not in known strong catalog")
        score -= 20
        status = TenetStatus.WARN

    if profile.family in ("symmetric-legacy", "hash-broken"):
        issues.append(f"Classical-weak algorithm {asset.algorithm}")
        score -= 25
        status = TenetStatus.FAIL if status != TenetStatus.FAIL else status
    if profile.quantum_vulnerable and asset.migration_status != MigrationStatus.MIGRATED:
        issues.append(f"Shor-vulnerable algorithm {asset.algorithm} not yet migrated")
        score -= 15
        if status == TenetStatus.PASS:
            status = TenetStatus.WARN

    # Same bar inside/outside: internet_exposed with weak crypto is especially bad
    if asset.internet_exposed and status == TenetStatus.FAIL:
        issues.append("Internet-exposed with weak crypto controls")
        score -= 10

    score = max(0, min(100, score))
    evidence = "; ".join(issues) if issues else (
        f"Protocol {asset.protocol}, algorithm {asset.algorithm}: consistent with secured communications baseline."
    )
    rec = (
        "Prefer TLS 1.3 (or equivalent), strong algorithms, and equal policy on- and off-premises "
        "(SP 800-207 tenet 2)."
    )
    return TenetResult(2, TENET_TITLES[2], status, score, evidence, rec)


def _tenet3_per_session(asset: CryptoAsset) -> TenetResult:
    """Tenet 3: per-session access — limited signal from crypto inventory alone."""
    # Identity-related assets are more relevant to session auth
    name_l = (asset.name + asset.asset_id).lower()
    is_identity = any(k in name_l for k in ("identity", "auth", "sso", "iam", "login"))
    if is_identity and asset.migration_status == MigrationStatus.MIGRATED:
        return TenetResult(
            3, TENET_TITLES[3], TenetStatus.PASS, 80,
            "Identity/auth asset marked migrated; supports per-session evaluation path.",
            "Ensure authz is re-evaluated per session/resource (least privilege).",
        )
    if is_identity:
        return TenetResult(
            3, TENET_TITLES[3], TenetStatus.WARN, 50,
            "Identity/auth asset present but not migrated; session-bound access may rely on legacy crypto.",
            "Prioritize strong auth crypto and session-bound tokens for this asset.",
        )
    return TenetResult(
        3, TENET_TITLES[3], TenetStatus.UNKNOWN, 50,
        "Inventory lacks explicit session/policy fields; cannot fully assess per-session access.",
        "Extend inventory with session/authz metadata for stronger ZTA assessment.",
    )


def _tenet4_dynamic_policy(asset: CryptoAsset, scores: Optional[AssetScores]) -> TenetResult:
    """Tenet 4: dynamic policy — proxy via crypto agility + migration posture."""
    agility = scores.agility_estimate.total if scores else 50
    if agility >= 60 and asset.migration_status in (
        MigrationStatus.MIGRATED,
        MigrationStatus.IN_PROGRESS,
        MigrationStatus.PLANNED,
    ):
        return TenetResult(
            4, TENET_TITLES[4], TenetStatus.PASS, min(100, agility),
            f"Crypto Agility Estimate {agility}/100 and status={asset.migration_status.value} "
            "suggest capacity to adapt controls/policy.",
            "Bind access policy to observable posture signals (identity, device, environment).",
        )
    if agility < 40:
        return TenetResult(
            4, TENET_TITLES[4], TenetStatus.WARN, agility,
            f"Low Crypto Agility Estimate ({agility}/100) may hinder dynamic policy changes.",
            "Reduce coupling and modernize protocols to enable policy-driven crypto changes.",
        )
    return TenetResult(
        4, TENET_TITLES[4], TenetStatus.WARN, max(40, agility),
        f"Agility={agility}/100, status={asset.migration_status.value}: partial readiness for dynamic policy.",
        "Document policy attributes beyond static network location (SP 800-207 tenet 4).",
    )


def _tenet5_monitor_posture(asset: CryptoAsset, scores: Optional[AssetScores]) -> TenetResult:
    """Tenet 5: monitor integrity and security posture of assets."""
    # Having scores + status is a form of posture measurement for crypto
    if scores is None:
        return TenetResult(
            5, TENET_TITLES[5], TenetStatus.FAIL, 20,
            "No computed scores available for posture measurement.",
            "Run scoring pipeline and track migration_status continuously.",
        )
    factors = [
        f"classical={scores.classical_risk.total}",
        f"quantum={scores.quantum_exposure.total}",
        f"status={asset.migration_status.value}",
    ]
    score = 70
    status = TenetStatus.PASS
    if asset.migration_status == MigrationStatus.NOT_STARTED and scores.quantum_exposure.total >= 70:
        score = 45
        status = TenetStatus.WARN
        factors.append("high quantum exposure without migration progress")
    return TenetResult(
        5, TENET_TITLES[5], status, score,
        "Crypto posture measured: " + ", ".join(factors) + ".",
        "Feed continuous diagnostics into policy engines (SP 800-207 tenet 5).",
    )


def _tenet6_authn_authz(asset: CryptoAsset, scores: Optional[AssetScores]) -> TenetResult:
    """Tenet 6: authn/authz dynamic and enforced before access.

    Heuristic: identity path assets + strong crypto; weak auth algorithms fail.
    """
    name_l = (asset.name + asset.asset_id).lower()
    is_auth = any(k in name_l for k in ("identity", "auth", "vpn", "gateway", "cert", "sso"))
    profile = get_algorithm_profile(asset.algorithm)
    if profile.family in ("symmetric-legacy", "hash-broken"):
        return TenetResult(
            6, TENET_TITLES[6], TenetStatus.FAIL, 25,
            f"Auth-relevant crypto uses weak algorithm {asset.algorithm}.",
            "Replace broken/legacy algorithms before relying on them for access control.",
        )
    if is_auth and profile.quantum_vulnerable and asset.migration_status != MigrationStatus.MIGRATED:
        return TenetResult(
            6, TENET_TITLES[6], TenetStatus.WARN, 55,
            f"Access-path asset uses Shor-vulnerable {asset.algorithm}; not migrated.",
            "Plan PQC/hybrid for identity and gateway authentication paths.",
        )
    if is_auth:
        return TenetResult(
            6, TENET_TITLES[6], TenetStatus.PASS, 75,
            "Access-path asset inventoried with non-legacy algorithm baseline.",
            "Enforce authn/authz before every session; avoid implicit trust by location.",
        )
    return TenetResult(
        6, TENET_TITLES[6], TenetStatus.UNKNOWN, 50,
        "Limited authn/authz metadata in inventory for this asset.",
        "Tag assets on the authentication path for stronger tenet-6 evaluation.",
    )


def _tenet7_collect_improve(asset: CryptoAsset) -> TenetResult:
    """Tenet 7: collect state and improve posture — inventory + status lifecycle."""
    if asset.migration_status == MigrationStatus.MIGRATED:
        return TenetResult(
            7, TENET_TITLES[7], TenetStatus.PASS, 90,
            "Asset has completed a migration cycle; state used to improve posture.",
            "Continue collecting runtime telemetry and re-assess periodically.",
        )
    if asset.migration_status in (MigrationStatus.PLANNED, MigrationStatus.IN_PROGRESS):
        return TenetResult(
            7, TENET_TITLES[7], TenetStatus.PASS, 70,
            f"Status={asset.migration_status.value}: improvement action is tracked.",
            "Close the loop: update status when controls change.",
        )
    return TenetResult(
        7, TENET_TITLES[7], TenetStatus.WARN, 40,
        "Status=not_started: inventory exists but improvement cycle not started.",
        "Use Migration Priority and Stress Test outcomes to drive remediation.",
    )


def evaluate_asset_zta(
    asset: CryptoAsset, scores: Optional[AssetScores] = None
) -> AssetZTAResult:
    tenets = [
        _tenet1_resource_inventory(asset),
        _tenet2_secured_communication(asset, scores),
        _tenet3_per_session(asset),
        _tenet4_dynamic_policy(asset, scores),
        _tenet5_monitor_posture(asset, scores),
        _tenet6_authn_authz(asset, scores),
        _tenet7_collect_improve(asset),
    ]
    alignment = round(sum(t.score for t in tenets) / len(tenets))
    gaps = [
        f"T{t.tenet_id} {t.status.value}: {t.evidence}"
        for t in tenets
        if t.status in (TenetStatus.FAIL, TenetStatus.WARN)
    ]
    return AssetZTAResult(
        asset_id=asset.asset_id,
        tenets=tenets,
        alignment_score=alignment,
        gaps=gaps,
    )


def evaluate_inventory_zta(
    assets: Sequence[CryptoAsset],
    scores: Optional[Dict[str, AssetScores]] = None,
) -> InventoryZTAReport:
    results = [
        evaluate_asset_zta(a, scores.get(a.asset_id) if scores else None) for a in assets
    ]
    summary: Dict[int, Dict[str, int]] = {
        i: {"pass": 0, "warn": 0, "fail": 0, "unknown": 0} for i in range(1, 8)
    }
    for r in results:
        for t in r.tenets:
            summary[t.tenet_id][t.status.value] += 1
    inv_align = round(sum(r.alignment_score for r in results) / len(results)) if results else 0
    notes = [
        "Heuristic alignment with NIST SP 800-207 tenets — not a formal ZTA certification.",
        "Source: NIST SP 800-207 Zero Trust Architecture (2020), doi:10.6028/NIST.SP.800-207.",
        "Several tenets require policy/session telemetry beyond a crypto inventory; those return UNKNOWN/WARN.",
    ]
    return InventoryZTAReport(
        assets=results,
        inventory_alignment=inv_align,
        tenet_summary=summary,
        notes=notes,
    )


def zta_report_markdown(report: InventoryZTAReport, lang: str = "es") -> str:
    if lang == "en":
        lines = [
            "# NIST SP 800-207 Zero Trust — heuristic alignment report",
            "",
            f"**Inventory alignment score:** {report.inventory_alignment}/100",
            "",
            "> Not a certification. Deterministic mapping from crypto inventory to SP 800-207 tenets.",
            "",
            "## Tenet summary (asset counts)",
            "",
            "| Tenet | Pass | Warn | Fail | Unknown |",
            "|---:|---:|---:|---:|---:|",
        ]
    else:
        lines = [
            "# NIST SP 800-207 Zero Trust — informe de alineación heurística",
            "",
            f"**Alineación del inventario:** {report.inventory_alignment}/100",
            "",
            "> No es una certificación. Mapeo determinístico del inventario criptográfico a los tenets de SP 800-207.",
            "",
            "## Resumen por tenet (conteo de activos)",
            "",
            "| Tenet | Pass | Warn | Fail | Unknown |",
            "|---:|---:|---:|---:|---:|",
        ]
    for i in range(1, 8):
        s = report.tenet_summary[i]
        lines.append(
            f"| T{i} | {s['pass']} | {s['warn']} | {s['fail']} | {s['unknown']} |"
        )
    lines += ["", "## Per asset", ""]
    for r in sorted(report.assets, key=lambda x: x.alignment_score):
        lines.append(f"### `{r.asset_id}` — alignment {r.alignment_score}/100")
        for t in r.tenets:
            lines.append(
                f"- **T{t.tenet_id} [{t.status.value}]** ({t.score}/100): {t.evidence}"
            )
        lines.append("")
    for n in report.notes:
        lines.append(f"- {n}")
    lines.append("")
    return "\n".join(lines)
