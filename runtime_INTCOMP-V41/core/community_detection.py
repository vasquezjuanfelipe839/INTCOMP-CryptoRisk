"""Detección de comunidades sobre el grafo de dependencias.

100% determinístico (semillas fijas, orden de nodos estable). No usa IA.
No modifica scores de riesgo ni Migration Priority: aporta una capa de
agrupación para olas de migración y análisis.

Algoritmos:
- weak_components: componentes débilmente conexas
- label_propagation: propagación de etiquetas (Raghavan et al.), seed fija
- greedy_modularity: agregación greedy tipo Louvain (un nivel)
- dependency_roots: partición por raíz de prerequisitos (heurística de dominio)

La proyección no dirigida trata cada dependencia A→B como arista {A,B}.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from core.dependency_engine import DependencyGraph, build_graph
from core.models import CryptoAsset


@dataclass
class Community:
    """Una comunidad detectada."""

    community_id: str
    members: List[str]
    algorithm: str
    notes: Dict[str, str] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.members)


@dataclass
class CommunityPartition:
    """Resultado completo de un algoritmo de detección."""

    algorithm: str
    communities: List[Community]
    node_to_community: Dict[str, str]
    modularity: Optional[float] = None
    notes: Dict[str, str] = field(default_factory=dict)

    def community_of(self, asset_id: str) -> Optional[str]:
        return self.node_to_community.get(asset_id)


def _undirected_adj(graph: DependencyGraph, node_ids: Sequence[str]) -> Dict[str, Set[str]]:
    und: Dict[str, Set[str]] = {n: set() for n in node_ids}
    for src, deps in graph.depends_on.items():
        if src not in und:
            und[src] = set()
        for dst in deps:
            if dst not in und:
                und[dst] = set()
            und[src].add(dst)
            und[dst].add(src)
    # ensure all declared nodes exist even if isolated
    for n in node_ids:
        und.setdefault(n, set())
    return und


def _stable_nodes(graph: DependencyGraph, assets: Optional[Sequence[CryptoAsset]] = None) -> List[str]:
    if assets is not None:
        return [a.asset_id for a in assets]
    return sorted(graph.depends_on.keys())


def _groups_to_partition(
    algorithm: str,
    groups: List[List[str]],
    modularity: Optional[float] = None,
    notes: Optional[Dict[str, str]] = None,
) -> CommunityPartition:
    communities: List[Community] = []
    node_to: Dict[str, str] = {}
    # ordenar grupos por tamaño desc, luego por primer miembro
    ordered = sorted(groups, key=lambda g: (-len(g), g[0] if g else ""))
    for i, members in enumerate(ordered):
        members_sorted = sorted(members)
        cid = f"{algorithm}-{i+1:02d}"
        communities.append(
            Community(community_id=cid, members=members_sorted, algorithm=algorithm)
        )
        for m in members_sorted:
            node_to[m] = cid
    return CommunityPartition(
        algorithm=algorithm,
        communities=communities,
        node_to_community=node_to,
        modularity=modularity,
        notes=notes or {},
    )


# ---------------------------------------------------------------------------
# 1. Weakly connected components
# ---------------------------------------------------------------------------
def weak_components(
    graph: DependencyGraph, assets: Optional[Sequence[CryptoAsset]] = None
) -> CommunityPartition:
    nodes = _stable_nodes(graph, assets)
    und = _undirected_adj(graph, nodes)
    seen: Set[str] = set()
    groups: List[List[str]] = []
    for n in nodes:
        if n in seen:
            continue
        comp: List[str] = []
        q: deque[str] = deque([n])
        seen.add(n)
        while q:
            u = q.popleft()
            comp.append(u)
            for v in sorted(und[u]):  # orden estable
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        groups.append(comp)
    return _groups_to_partition(
        "weak_components",
        groups,
        notes={"description": "Componentes débilmente conexas del grafo de dependencias."},
    )


# ---------------------------------------------------------------------------
# 2. Label Propagation (determinista con seed y orden fijo)
# ---------------------------------------------------------------------------
def label_propagation(
    graph: DependencyGraph,
    assets: Optional[Sequence[CryptoAsset]] = None,
    max_iter: int = 50,
    seed: int = 42,
) -> CommunityPartition:
    """Propagación de etiquetas. Empates se resuelven por orden lexicográfico
    de la etiqueta (determinista; no usa random).
    """
    nodes = _stable_nodes(graph, assets)
    und = _undirected_adj(graph, nodes)
    label: Dict[str, str] = {n: n for n in nodes}

    for _ in range(max_iter):
        changed = False
        # orden de visita fijo (lexicográfico) para determinismo
        for n in nodes:
            if not und[n]:
                continue
            counts: Dict[str, int] = defaultdict(int)
            for nb in und[n]:
                counts[label[nb]] += 1
            max_c = max(counts.values())
            # empate: etiqueta lexicográficamente menor
            candidates = sorted(lb for lb, c in counts.items() if c == max_c)
            new = candidates[0]
            if new != label[n]:
                label[n] = new
                changed = True
        if not changed:
            break

    groups_map: Dict[str, List[str]] = defaultdict(list)
    for n, lb in label.items():
        groups_map[lb].append(n)
    groups = list(groups_map.values())
    return _groups_to_partition(
        "label_propagation",
        groups,
        notes={
            "description": "Label propagation determinista (empates por orden lex).",
            "max_iter": str(max_iter),
            "seed_note": "Sin RNG: orden de nodos y empates fijos.",
        },
    )


# ---------------------------------------------------------------------------
# 3. Greedy modularity (Louvain-like, un nivel)
# ---------------------------------------------------------------------------
def _modularity(partition: Dict[str, str], und: Dict[str, Set[str]], m: int) -> float:
    if m <= 0:
        return 0.0
    nodes = list(und.keys())
    deg = {n: len(und[n]) for n in nodes}
    q = 0.0
    for i in nodes:
        for j in nodes:
            if partition[i] != partition[j]:
                continue
            aij = 1.0 if j in und[i] else 0.0
            q += aij - (deg[i] * deg[j]) / (2.0 * m)
    return q / (2.0 * m)


def greedy_modularity(
    graph: DependencyGraph, assets: Optional[Sequence[CryptoAsset]] = None
) -> CommunityPartition:
    """Agregación greedy de modularidad (estilo Louvain, una pasada repetida
    hasta convergencia local). Orden de nodos fijo → resultado determinista.
    """
    nodes = _stable_nodes(graph, assets)
    und = _undirected_adj(graph, nodes)
    m = sum(len(und[n]) for n in nodes) // 2
    partition: Dict[str, str] = {n: n for n in nodes}

    improved = True
    rounds = 0
    max_rounds = max(2 * len(nodes), 10)
    while improved and rounds < max_rounds:
        improved = False
        rounds += 1
        for n in nodes:
            if not und[n]:
                continue
            current = partition[n]
            candidates = sorted({partition[nb] for nb in und[n]} | {current})
            base_q = _modularity(partition, und, m)
            best = current
            best_q = base_q
            for cand in candidates:
                if cand == current:
                    continue
                trial = dict(partition)
                trial[n] = cand
                q = _modularity(trial, und, m)
                if q > best_q + 1e-12:
                    best_q = q
                    best = cand
            if best != current:
                partition[n] = best
                improved = True

    groups_map: Dict[str, List[str]] = defaultdict(list)
    for n, c in partition.items():
        groups_map[c].append(n)
    q_final = _modularity(partition, und, m)
    return _groups_to_partition(
        "greedy_modularity",
        list(groups_map.values()),
        modularity=round(q_final, 6),
        notes={
            "description": "Greedy modularity (Louvain-like, un nivel, determinista).",
            "undirected_edges": str(m),
        },
    )


# ---------------------------------------------------------------------------
# 4. Dependency-root partition (domain heuristic)
# ---------------------------------------------------------------------------
def dependency_roots(
    graph: DependencyGraph, assets: Optional[Sequence[CryptoAsset]] = None
) -> CommunityPartition:
    """Cada activo se asigna a una raíz de su cadena de prerequisitos.

    Si tiene varias raíces, se elige la de mayor fan-in transitivo; empate lex.
    Aislados son su propia comunidad.
    """
    nodes = _stable_nodes(graph, assets)
    node_set = set(nodes)

    def ultimate_roots(n: str, visiting: Optional[Set[str]] = None) -> Set[str]:
        if visiting is None:
            visiting = set()
        if n in visiting:
            return set()
        visiting.add(n)
        deps = [d for d in graph.fan_out(n) if d in node_set]
        if not deps:
            return {n}
        roots: Set[str] = set()
        for d in deps:
            roots |= ultimate_roots(d, visiting)
        return roots

    fan_in_cache = {n: len(graph.fan_in_transitive(n)) for n in nodes}

    def pick_root(roots: Set[str]) -> str:
        return sorted(roots, key=lambda r: (-fan_in_cache.get(r, 0), r))[0]

    groups_map: Dict[str, List[str]] = defaultdict(list)
    for n in nodes:
        roots = ultimate_roots(n)
        key = pick_root(roots) if roots else n
        groups_map[key].append(n)

    return _groups_to_partition(
        "dependency_roots",
        list(groups_map.values()),
        notes={
            "description": (
                "Partición por raíz de prerequisitos (heurística de dominio). "
                "No optimiza modularidad."
            ),
        },
    )


# ---------------------------------------------------------------------------
# API de conveniencia
# ---------------------------------------------------------------------------
ALGORITHMS = {
    "weak_components": weak_components,
    "label_propagation": label_propagation,
    "greedy_modularity": greedy_modularity,
    "dependency_roots": dependency_roots,
}


def detect_communities(
    assets: Sequence[CryptoAsset],
    algorithm: str = "greedy_modularity",
) -> CommunityPartition:
    """Detecta comunidades sobre el inventario.

    algorithm: weak_components | label_propagation | greedy_modularity | dependency_roots
    """
    if algorithm not in ALGORITHMS:
        raise ValueError(
            f"Algoritmo desconocido '{algorithm}'. Opciones: {sorted(ALGORITHMS)}"
        )
    graph = build_graph(list(assets))
    return ALGORITHMS[algorithm](graph, assets)


def detect_all(assets: Sequence[CryptoAsset]) -> Dict[str, CommunityPartition]:
    """Ejecuta todos los algoritmos y devuelve un dict nombre → partición."""
    graph = build_graph(list(assets))
    return {name: fn(graph, assets) for name, fn in ALGORITHMS.items()}
