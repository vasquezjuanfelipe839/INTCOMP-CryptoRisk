"""Grafo de dependencias entre activos.

`dependencies` de cada CryptoAsset se interpreta como "este activo depende
de estos otros" (A → depende_de → [B, C]). Todo acá es determinístico:
son algoritmos clásicos de grafos, sin IA de por medio.

Dependency-safe migration sequence (V3.1):
Si A depende de B y B depende de C, la migración de A respeta C → B → A.
Migration Priority solo desempata entre nodos ya disponibles; nunca rompe
una arista del grafo.

Memoria (V3.1+):
- Índice invertido lazy para fan-in O(1) amortizado tras O(n+m) de construcción.
- fan_out devuelve la lista interna (solo lectura; no mutar).
- SCC Tarjan/Kosaraju en O(n+m) sin matrices densas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.config import DEPENDENCY_IMPACT_BUCKETS, DEPENDENCY_IMPACT_DEFAULT, bucket_lookup
from core.models import CryptoAsset, MigrationStatus, ScoreBreakdown

_EMPTY: Tuple[str, ...] = ()


@dataclass
class DependencyGraph:
    depends_on: Dict[str, List[str]] = field(default_factory=dict)  # fan-out directo
    # Índice invertido lazy: depended_by[v] = nodos u con arista u→v (u depende de v)
    _depended_by: Optional[Dict[str, List[str]]] = field(
        default=None, repr=False, compare=False
    )

    def _ensure_reverse_index(self) -> Dict[str, List[str]]:
        """Construye el índice invertido una sola vez: O(n+m) tiempo y memoria."""
        if self._depended_by is None:
            rev: Dict[str, List[str]] = {k: [] for k in self.depends_on}
            for u, deps in self.depends_on.items():
                for v in deps:
                    if v in rev:
                        rev[v].append(u)
            self._depended_by = rev
        return self._depended_by

    def invalidate_reverse_index(self) -> None:
        """Llamar si se muta `depends_on` tras el build (uso avanzado)."""
        self._depended_by = None

    def fan_out(self, asset_id: str) -> List[str]:
        """Prerequisitos directos. Vista de la lista interna — no mutar."""
        return self.depends_on.get(asset_id, [])

    def fan_in_direct(self, asset_id: str) -> List[str]:
        """Dependientes directos vía índice invertido (O(deg⁻) tras build)."""
        rev = self._ensure_reverse_index()
        return rev.get(asset_id, [])

    def fan_in_transitive(self, asset_id: str) -> Set[str]:
        """Todos los activos que dependen de `asset_id` (directa o indirectamente)."""
        rev = self._ensure_reverse_index()
        visited: Set[str] = set()
        stack = list(rev.get(asset_id, ()))
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            stack.extend(rev.get(current, ()))
        return visited

    def fan_out_transitive(self, asset_id: str) -> Set[str]:
        """Todos los prerequisitos de `asset_id`, directos e indirectos."""
        visited: Set[str] = set()
        stack = list(self.depends_on.get(asset_id, ()))
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            stack.extend(self.depends_on.get(current, ()))
        return visited

    def fan_in_transitive_sizes(self) -> Dict[str, int]:
        """Tamaños de fan-in transitivo para todos los nodos.

        Una BFS por nodo; reutiliza el índice invertido (sin reconstruirlo).
        Memoria pico: O(n) por BFS, no O(n²) de sets simultáneos.
        """
        rev = self._ensure_reverse_index()
        sizes: Dict[str, int] = {}
        for asset_id in self.depends_on:
            visited: Set[str] = set()
            stack = list(rev.get(asset_id, ()))
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                stack.extend(rev.get(current, ()))
            sizes[asset_id] = len(visited)
        return sizes

    def detect_cycles(self) -> List[List[str]]:
        """Detección de ciclos por DFS de tres colores (Cormen et al.).

        Colores:
          WHITE (0) — no visitado
          GRAY  (1) — en la pila de recursión (camino activo)
          BLACK (2) — expandido por completo

        Una arista hacia un nodo GRAY es una back-edge ⇒ ciclo dirigido.
        Cada ciclo se reporta como lista de ids que empieza y termina en el
        mismo nodo, p. ej. [A, B, A]. Complejidad O(n + m).

        Dependencias a ids ausentes del grafo se ignoran (las gestiona el
        loader / Stress Test como MISSING).
        """
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {aid: WHITE for aid in self.depends_on}
        cycles: List[List[str]] = []
        seen_cycle_keys: Set[tuple] = set()

        def _record_cycle(path: List[str], back_to: str) -> None:
            start = path.index(back_to)
            cycle = path[start:] + [back_to]
            key = tuple(cycle)
            if key not in seen_cycle_keys:
                seen_cycle_keys.add(key)
                cycles.append(cycle)

        def visit(node: str, path: List[str]) -> None:
            color[node] = GRAY
            path.append(node)
            for neighbor in self.depends_on.get(node, ()):
                if neighbor not in color:
                    continue
                if color[neighbor] == GRAY:
                    _record_cycle(path, neighbor)
                elif color[neighbor] == WHITE:
                    visit(neighbor, path)
            path.pop()
            color[node] = BLACK

        for node in list(self.depends_on):
            if color[node] == WHITE:
                visit(node, [])
        return cycles

    def has_cycle(self) -> bool:
        """True si existe al menos un ciclo dirigido. O(n + m)."""
        return bool(self.detect_cycles())

    def strongly_connected_components(self) -> List[List[str]]:
        """Componentes fuertemente conexas (SCC) vía algoritmo de Tarjan (1972).

        Complejidad O(n + m). Sin matriz n×n.
        """
        index_counter = [0]
        stack: List[str] = []
        on_stack: Set[str] = set()
        index: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        components: List[List[str]] = []

        def strongconnect(v: str) -> None:
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(v)

            for w in self.depends_on.get(v, ()):
                if w not in self.depends_on:
                    continue
                if w not in index:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index[w])

            if lowlink[v] == index[v]:
                comp: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                components.append(comp)

        for v in list(self.depends_on):
            if v not in index:
                strongconnect(v)
        return components

    def cyclic_components(self) -> List[List[str]]:
        """SCC con tamaño ≥ 2 o auto-bucle (bloques con dependencia circular)."""
        result: List[List[str]] = []
        for comp in self.strongly_connected_components():
            if len(comp) >= 2:
                result.append(sorted(comp))
            elif len(comp) == 1:
                v = comp[0]
                if v in self.depends_on.get(v, ()):
                    result.append([v])
        return result

    def kosaraju_strongly_connected_components(self) -> List[List[str]]:
        """SCC vía Kosaraju: DFS + traspuesto + DFS. O(n + m).

        Reutiliza el índice invertido como Gᵀ cuando ya está construido
        (misma estructura: depended_by[v] = predecesores en G = vecinos en Gᵀ
        solo si la arista era u→v con u depende de v… 

        Convención del proyecto: arista u→v significa "u depende de v".
        Traspuesto: v→u. El índice invertido depends_by[v] lista los u
        tales que u→v, es decir exactamente los vecinos de v en Gᵀ.
        """
        visited: Set[str] = set()
        finish_order: List[str] = []

        def dfs_forward(v: str) -> None:
            visited.add(v)
            for w in self.depends_on.get(v, ()):
                if w in self.depends_on and w not in visited:
                    dfs_forward(w)
            finish_order.append(v)

        for v in list(self.depends_on):
            if v not in visited:
                dfs_forward(v)

        # Gᵀ = índice invertido (sin copiar listas: solo lectura en DFS)
        transpose = self._ensure_reverse_index()

        visited.clear()
        components: List[List[str]] = []

        def dfs_transpose(v: str, comp: List[str]) -> None:
            visited.add(v)
            comp.append(v)
            for w in transpose.get(v, ()):
                if w not in visited:
                    dfs_transpose(w, comp)

        for v in reversed(finish_order):
            if v not in visited:
                comp: List[str] = []
                dfs_transpose(v, comp)
                components.append(comp)

        return components

    def dependency_safe_sequence(
        self,
        target_id: str,
        assets_by_id: Dict[str, CryptoAsset],
        priority_scores: Optional[Dict[str, int]] = None,
        include_migrated: bool = False,
    ) -> List[str]:
        """Secuencia de migración dependency-safe hacia `target_id`.

        Migration Priority solo ordena entre nodos *ready*; nunca antepone
        un nodo a su prerequisito.
        """
        priority_scores = priority_scores or {}
        prereqs = self.fan_out_transitive(target_id)
        nodes: Set[str] = set(prereqs)
        nodes.add(target_id)

        active: Set[str] = set()
        for n in nodes:
            if n == target_id:
                active.add(n)
                continue
            asset = assets_by_id.get(n)
            if asset is None:
                active.add(n)
                continue
            if include_migrated or asset.migration_status != MigrationStatus.MIGRATED:
                active.add(n)

        indegree: Dict[str, int] = {n: 0 for n in active}
        children: Dict[str, List[str]] = {n: [] for n in active}
        for n in active:
            for dep in self.depends_on.get(n, ()):
                if dep in active:
                    children[dep].append(n)
                    indegree[n] += 1

        def sort_key(aid: str) -> tuple:
            return (-int(priority_scores.get(aid, 0)), aid)

        ready = sorted([n for n in active if indegree[n] == 0], key=sort_key)
        order: List[str] = []
        while ready:
            node = ready.pop(0)
            order.append(node)
            for ch in children.get(node, ()):
                indegree[ch] -= 1
                if indegree[ch] == 0:
                    ready.append(ch)
                    ready.sort(key=sort_key)

        remaining = [n for n in active if n not in order]
        if remaining:
            order.extend(sorted(remaining, key=sort_key))

        if target_id in order:
            order = [x for x in order if x != target_id] + [target_id]
        else:
            order.append(target_id)
        return order

    def topological_order(self) -> List[str]:
        """Orden global: cada activo después de sus prerequisitos."""
        visited: Set[str] = set()
        order: List[str] = []

        def visit(node: str, guard: Set[str]) -> None:
            if node in visited or node in guard:
                return
            guard.add(node)
            for dep in self.depends_on.get(node, ()):
                if dep in self.depends_on:
                    visit(dep, guard)
            guard.discard(node)
            if node not in visited:
                visited.add(node)
                order.append(node)

        for node in self.depends_on:
            visit(node, set())
        return order


def build_graph(assets: List[CryptoAsset]) -> DependencyGraph:
    return DependencyGraph(
        depends_on={a.asset_id: list(a.dependencies) for a in assets}
    )


def compute_dependency_impact(asset_id: str, graph: DependencyGraph) -> ScoreBreakdown:
    """Dependency Impact: dato crudo del grafo, sin ponderar por criticidad."""
    affected = len(graph.fan_in_transitive(asset_id))
    points = bucket_lookup(affected, DEPENDENCY_IMPACT_BUCKETS, DEPENDENCY_IMPACT_DEFAULT)
    return ScoreBreakdown(
        total=points,
        factors={"affected_assets_count": float(affected)},
        notes={
            "affected_assets_count": (
                f"{affected} activo(s) dependen de este, directa o "
                "indirectamente (fan-in transitivo)."
            )
        },
    )
