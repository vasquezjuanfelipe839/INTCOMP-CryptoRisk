"""Export de plan de migración a tareas (CSV / Markdown).

Determinístico. No modifica scores. Pensado para pegar en Jira, Linear,
Azure Boards, GitHub Projects, etc.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from core.community_detection import CommunityPartition, detect_communities
from core.models import AssetScores, CryptoAsset
from core.scoring import score_inventory


@dataclass
class MigrationTask:
    task_id: str
    title: str
    asset_id: str
    asset_name: str
    migration_status: str
    migration_priority: int
    classical_risk: int
    quantum_exposure: int
    strategic_impact: int
    community_id: str
    community_members: str
    dependencies: str
    blocked_by: str
    labels: str
    wave: int
    notes: str


def _blocked_by(asset: CryptoAsset, by_id: Dict[str, CryptoAsset]) -> List[str]:
    blocked = []
    for dep in asset.dependencies:
        if dep not in by_id:
            blocked.append(f"{dep}(MISSING)")
            continue
        st = by_id[dep].migration_status.value
        if st != "migrated":
            blocked.append(f"{dep}({st})")
    return blocked


def _labels(asset: CryptoAsset, scores: AssetScores) -> List[str]:
    tags = [f"status:{asset.migration_status.value}", f"crit:{asset.criticality.value}"]
    if scores.quantum_exposure.total >= 70:
        tags.append("quantum-high")
    elif scores.quantum_exposure.total >= 40:
        tags.append("quantum-med")
    if scores.classical_risk.total >= 60:
        tags.append("classical-high")
    if asset.internet_exposed:
        tags.append("internet-exposed")
    if not asset.dependencies:
        tags.append("no-deps")
    return tags


def build_migration_tasks(
    assets: Sequence[CryptoAsset],
    scores: Optional[Dict[str, AssetScores]] = None,
    partition: Optional[CommunityPartition] = None,
) -> List[MigrationTask]:
    """Construye una tarea por activo, ordenada por ola (comunidad) y priority."""
    if scores is None:
        scores = score_inventory(list(assets))
    if partition is None:
        partition = detect_communities(list(assets), algorithm="greedy_modularity")

    by_id = {a.asset_id: a for a in assets}

    # wave index = order of communities (already size-desc in partition)
    community_wave = {
        c.community_id: i + 1 for i, c in enumerate(partition.communities)
    }

    tasks: List[MigrationTask] = []
    for asset in assets:
        s = scores[asset.asset_id]
        cid = partition.community_of(asset.asset_id) or "unassigned"
        members = []
        for c in partition.communities:
            if c.community_id == cid:
                members = c.members
                break
        blocked = _blocked_by(asset, by_id)
        wave = community_wave.get(cid, 99)
        notes = ""
        if blocked:
            notes = "Blocked until prerequisites are migrated: " + ", ".join(blocked)
        elif asset.migration_status.value == "migrated":
            notes = "Already migrated — verify and close."
        tasks.append(
            MigrationTask(
                task_id=f"MIG-{asset.asset_id}",
                title=f"Migrate {asset.name} ({asset.asset_id})",
                asset_id=asset.asset_id,
                asset_name=asset.name,
                migration_status=asset.migration_status.value,
                migration_priority=s.migration_priority.total,
                classical_risk=s.classical_risk.total,
                quantum_exposure=s.quantum_exposure.total,
                strategic_impact=s.strategic_impact.total,
                community_id=cid,
                community_members=";".join(members),
                dependencies=";".join(asset.dependencies),
                blocked_by=";".join(blocked),
                labels=",".join(_labels(asset, s)),
                wave=wave,
                notes=notes,
            )
        )

    # sort: wave asc, then priority desc, then asset_id
    tasks.sort(key=lambda t: (t.wave, -t.migration_priority, t.asset_id))
    return tasks


def tasks_to_csv(tasks: Sequence[MigrationTask]) -> str:
    buf = io.StringIO()
    fields = [
        "task_id",
        "title",
        "asset_id",
        "asset_name",
        "migration_status",
        "migration_priority",
        "classical_risk",
        "quantum_exposure",
        "strategic_impact",
        "community_id",
        "wave",
        "dependencies",
        "blocked_by",
        "labels",
        "notes",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for t in tasks:
        writer.writerow({f: getattr(t, f) for f in fields})
    return buf.getvalue()


def tasks_to_markdown(tasks: Sequence[MigrationTask], lang: str = "es") -> str:
    if lang == "en":
        title = "# Migration task plan (INTCOMP CryptoRisk)"
        intro = (
            "Generated deterministically from inventory scores and graph communities. "
            "Import into Jira / Linear / Azure Boards / GitHub Projects."
        )
        wave_h = "## Wave"
        cols = (
            "| Task | Asset | Status | Priority | Quantum | Classical | Blocked by | Labels |\n"
            "|---|---|---|---:|---:|---:|---|---|"
        )
    else:
        title = "# Plan de tareas de migración (INTCOMP CryptoRisk)"
        intro = (
            "Generado de forma determinística a partir de scores e inventario y comunidades del grafo. "
            "Importable en Jira / Linear / Azure Boards / GitHub Projects."
        )
        wave_h = "## Ola"
        cols = (
            "| Tarea | Activo | Estado | Priority | Quantum | Classical | Bloqueado por | Labels |\n"
            "|---|---|---|---:|---:|---:|---|---|"
        )

    lines = [title, "", intro, ""]
    current_wave = None
    for t in tasks:
        if t.wave != current_wave:
            current_wave = t.wave
            lines.append(f"{wave_h} {t.wave} (`{t.community_id}`)")
            lines.append("")
            lines.append(cols)
        blocked = t.blocked_by or "—"
        lines.append(
            f"| `{t.task_id}` | {t.asset_name} (`{t.asset_id}`) | {t.migration_status} | "
            f"{t.migration_priority} | {t.quantum_exposure} | {t.classical_risk} | {blocked} | {t.labels} |"
        )
    lines.append("")
    return "\n".join(lines)


def stress_action_markdown(
    sequence: Sequence[str],
    assets: Sequence[CryptoAsset],
    scores: Dict[str, AssetScores],
    rationale: str = "",
    lang: str = "es",
) -> str:
    """Checklist Markdown a partir de la secuencia del Stress Test."""
    by_id = {a.asset_id: a for a in assets}
    if lang == "en":
        lines = ["# Stress Test — recommended action checklist", ""]
        if rationale:
            lines += [rationale, ""]
        lines.append("| Step | Asset | Status | Priority | Quantum |")
        lines.append("|---:|---|---|---:|---:|")
    else:
        lines = ["# Stress Test — checklist de acción recomendada", ""]
        if rationale:
            lines += [rationale, ""]
        lines.append("| Paso | Activo | Estado | Priority | Quantum |")
        lines.append("|---:|---|---|---:|---:|")

    for i, aid in enumerate(sequence, 1):
        a = by_id.get(aid)
        if a and aid in scores:
            s = scores[aid]
            lines.append(
                f"| {i} | {a.name} (`{aid}`) | {a.migration_status.value} | "
                f"{s.migration_priority.total} | {s.quantum_exposure.total} |"
            )
        else:
            lines.append(f"| {i} | `{aid}` | ? | — | — |")
    lines.append("")
    return "\n".join(lines)
