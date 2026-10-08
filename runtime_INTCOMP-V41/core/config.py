"""Pesos y umbrales de todas las fórmulas determinísticas.

Todo lo que un motor necesita ajustar vive acá, documentado, en vez de estar
hardcodeado dentro de la lógica. Cambiar un peso es cambiar un número acá,
no reescribir una función. Ver docs/methodology.md para la explicación de
cada fórmula.
"""

# ---------------------------------------------------------------------------
# Risk Engine (0-100)
# ---------------------------------------------------------------------------
RISK_MAX_ALGORITHM = 30
RISK_MAX_EXPOSURE = 20
RISK_MAX_CRITICALITY = 20
RISK_MAX_DATA_LIFETIME = 15
RISK_MAX_DEPENDENCIES = 15

RISK_CRITICALITY_POINTS = {
    "low": 5,
    "medium": 10,
    "high": 15,
    "critical": 20,
}

# años de vida útil de los datos a partir de los cuales se asigna el máximo
RISK_DATA_LIFETIME_CAP_YEARS = 30

# ---------------------------------------------------------------------------
# Crypto Agility Estimate (0-100) — heurística, no medición objetiva
# ---------------------------------------------------------------------------
AGILITY_MAX_COUPLING = 35
AGILITY_MAX_PREREQUISITES = 20
AGILITY_MAX_CRITICALITY = 25
AGILITY_MAX_PROTOCOL = 20

# más dependientes (fan-in) => más difícil => MENOS puntos de agility
AGILITY_COUPLING_BUCKETS = [
    (0, 35),
    (2, 25),
    (5, 15),
    (9, 8),
]
AGILITY_COUPLING_DEFAULT = 0  # 10+ dependientes

# más prerequisitos (fan-out) => más difícil => MENOS puntos
AGILITY_PREREQUISITE_BUCKETS = [
    (0, 20),
    (2, 14),
    (5, 8),
]
AGILITY_PREREQUISITE_DEFAULT = 2  # 6+ prerequisitos

AGILITY_CRITICALITY_POINTS = {
    "critical": 5,
    "high": 12,
    "medium": 19,
    "low": 25,
}

# catálogo de "modernidad" de protocolo: más alto = más fácil cambiar
# el algoritmo por configuración, sin tocar código
AGILITY_PROTOCOL_POINTS = {
    "TLS 1.3": 20,
    "TLS 1.2": 14,
    "SSH-2": 14,
    "IPSEC": 10,
    "TLS 1.1": 6,
    "TLS 1.0": 4,
    "PROPRIETARY": 2,
}
AGILITY_PROTOCOL_DEFAULT = 10  # protocolo no catalogado

# ---------------------------------------------------------------------------
# Dependency Impact (0-100) — dato crudo del grafo
# ---------------------------------------------------------------------------
DEPENDENCY_IMPACT_BUCKETS = [
    (0, 0),
    (2, 30),
    (5, 60),
    (9, 85),
]
DEPENDENCY_IMPACT_DEFAULT = 100  # 10+ dependientes transitivos

# ---------------------------------------------------------------------------
# Strategic Impact (0-100)
# ---------------------------------------------------------------------------
STRATEGIC_MAX_SERVICES_AFFECTED = 35
STRATEGIC_MAX_CRITICALITY = 25
STRATEGIC_MAX_GRAPH_POSITION = 25
STRATEGIC_MAX_OWN_DEPENDENCIES = 15

STRATEGIC_SERVICES_AFFECTED_BUCKETS = [
    (0, 0),
    (2, 10),
    (5, 20),
    (9, 30),
]
STRATEGIC_SERVICES_AFFECTED_DEFAULT = 35  # 10+ afectados

STRATEGIC_CRITICALITY_POINTS = {
    "low": 5,
    "medium": 12,
    "high": 19,
    "critical": 25,
}

STRATEGIC_OWN_DEPENDENCIES_BUCKETS = [
    (0, 0),
    (2, 5),
    (5, 9),
    (9, 12),
]
STRATEGIC_OWN_DEPENDENCIES_DEFAULT = 15  # 10+ dependencias propias

# ---------------------------------------------------------------------------
# Migration Priority Score (0-100) — combina las 4 dimensiones anteriores
# ---------------------------------------------------------------------------
MIGRATION_PRIORITY_WEIGHTS = {
    "risk": 0.35,
    "strategic_impact": 0.30,
    "dependency_impact": 0.20,
    "agility_inverted": 0.15,
}

# ---------------------------------------------------------------------------
# Decision Stress Test
# ---------------------------------------------------------------------------
# umbral de Crypto Agility Estimate por debajo del cual se marca como
# "requiere más tiempo de preparación" en el Agility Check
STRESS_TEST_LOW_AGILITY_THRESHOLD = 40


def bucket_lookup(count: int, buckets, default: int) -> int:
    """Busca `count` en una lista [(umbral, puntos), ...] ordenada ascendente.

    Devuelve los puntos del primer umbral que `count` no supera; si supera
    todos, devuelve `default`.
    """
    for threshold, points in buckets:
        if count <= threshold:
            return points
    return default

# ---------------------------------------------------------------------------
# Security controls (STRIDE mitigations)
# ---------------------------------------------------------------------------
# DoS / Tampering: límites de inventario CSV
SECURITY_MAX_CSV_BYTES = 2 * 1024 * 1024  # 2 MiB
SECURITY_MAX_CSV_ROWS = 5000
SECURITY_MAX_DEPENDENCIES_PER_ASSET = 50
SECURITY_MAX_ASSET_ID_LEN = 128
SECURITY_MAX_NAME_LEN = 256

# Audit trail local (Repudiation mitigation — best effort)
SECURITY_AUDIT_ENABLED = True
SECURITY_AUDIT_PATH = __import__("os").environ.get("INTCOMP_AUDIT_PATH", "data/audit.log")
SECURITY_AUDIT_MAX_BYTES = 1 * 1024 * 1024  # rotate-ish truncate when larger
