"""Catálogo estático de algoritmos criptográficos.

Esto NO es una opinión de la IA ni un estándar inventado: es una tabla de
referencia basada en clasificaciones públicas y ampliamente documentadas
(principalmente las publicaciones del NIST sobre criptografía post-cuántica
y criptoanálisis clásico). Cada familia tiene una nota que explica el motivo
de su clasificación.

Fuentes de referencia (clasificación pública, no fechas de "Q-day"):
- NIST IR 8105 / NIST SP 800-208 y series PQC (vulnerabilidad de RSA/ECC/DH
  al algoritmo de Shor en un computador cuántico suficientemente potente).
- NIST SP 800-57 / SP 800-131A (recomendaciones de key size y deprecación
  de algoritmos clásicos débiles: DES, 3DES, SHA-1, MD5, RC4).
- Análisis públicos de colisiones (SHA-1 broken, MD5 broken).

NO se afirman fechas de llegada de computadoras cuánticas capaces de romper
algoritmos concretos. Quantum Exposure es un indicador heurístico de
exposición relativa, no una probabilidad de ataque.
"""

from __future__ import annotations

from typing import NamedTuple, Optional, Tuple

# ---------------------------------------------------------------------------
# Classical Cryptographic Risk — debilidad frente a ataques clásicos
# ---------------------------------------------------------------------------
# Puntos 0-40 centrados en debilidades ya documentadas (colisiones, claves
# cortas, algoritmos deprecados). No incluye vulnerabilidad cuántica.
CLASSICAL_FAMILY_POINTS = {
    "hash-broken": 40,  # MD5, SHA-1: colisiones conocidas
    "symmetric-legacy": 36,  # DES, 3DES, RC4: deprecados / claves cortas
    "asymmetric-classical": 8,  # RSA/ECC/DH: clásicamente fuertes si key size ok
    "symmetric": 4,  # AES, ChaCha20: sin debilidades clásicas relevantes
    "hash-strong": 2,  # SHA-2/3 familia
    "post-quantum": 2,  # FIPS 203/204/205 y aliases: diseñados frente a amenaza cuántica conocida
    "unknown": 20,  # conservador
}

# ---------------------------------------------------------------------------
# Quantum Exposure — exposición heurística a amenazas cuánticas conocidas
# ---------------------------------------------------------------------------
# Puntos base por familia (0-40). Shor afecta clave pública; Grover reduce
# seguridad efectiva de simétricos a la mitad (por eso no es 0).
QUANTUM_FAMILY_POINTS = {
    "asymmetric-classical": 36,  # Shor: factorización / log discreto
    "symmetric-legacy": 12,  # ya débil clásicamente; Grover agrava poco más
    "hash-broken": 10,
    "symmetric": 10,  # Grover: seguridad efectiva ~ mitad
    "hash-strong": 8,
    "post-quantum": 2,  # ML-KEM/ML-DSA/SLH-DSA etc.: exposición relativa baja a Shor
    "unknown": 20,
}

FAMILY_NOTES = {
    "asymmetric-classical": (
        "Vulnerable al algoritmo de Shor en una computadora cuántica "
        "suficientemente potente (NIST PQC guidance)."
    ),
    "symmetric-legacy": "Considerado débil frente a ataques clásicos conocidos (NIST SP 800-131A).",
    "hash-broken": "Tiene colisiones conocidas y documentadas públicamente.",
    "symmetric": (
        "Considerado resistente hoy a ataques clásicos; el algoritmo de Grover "
        "reduce a la mitad la seguridad efectiva de la criptografía simétrica."
    ),
    "hash-strong": "Sin debilidades conocidas relevantes hoy.",
    "post-quantum": (
        "Algoritmo post-cuántico alineado con estándares o candidatos NIST PQC "
        "(p. ej. FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA). "
        "Exposición relativa baja a Shor; no implica inmunidad absoluta ni "
        "certificación de la implementación."
    ),
    "unknown": "Algoritmo no catalogado: se aplica un puntaje conservador por defecto.",
}


class AlgorithmProfile(NamedTuple):
    family: str
    quantum_vulnerable: bool
    min_recommended_key_size: Optional[int]


ALGORITHM_CATALOG = {
    "RSA": AlgorithmProfile("asymmetric-classical", True, 2048),
    "DH": AlgorithmProfile("asymmetric-classical", True, 2048),
    "DSA": AlgorithmProfile("asymmetric-classical", True, 2048),
    "ECC": AlgorithmProfile("asymmetric-classical", True, 256),
    "ECDSA": AlgorithmProfile("asymmetric-classical", True, 256),
    "ECDH": AlgorithmProfile("asymmetric-classical", True, 256),
    "ED25519": AlgorithmProfile("asymmetric-classical", True, 256),
    "AES": AlgorithmProfile("symmetric", False, 256),
    "CHACHA20": AlgorithmProfile("symmetric", False, 256),
    "3DES": AlgorithmProfile("symmetric-legacy", False, 168),
    "DES": AlgorithmProfile("symmetric-legacy", False, 56),
    "RC4": AlgorithmProfile("symmetric-legacy", False, None),
    "SHA-1": AlgorithmProfile("hash-broken", False, None),
    "MD5": AlgorithmProfile("hash-broken", False, None),
    "SHA-256": AlgorithmProfile("hash-strong", False, None),
    "SHA-384": AlgorithmProfile("hash-strong", False, None),
    "SHA-512": AlgorithmProfile("hash-strong", False, None),
    # NIST PQC FIPS 203/204/205 + competition-name aliases
    "ML-KEM": AlgorithmProfile("post-quantum", False, None),
    "MLKEM": AlgorithmProfile("post-quantum", False, None),
    "KYBER": AlgorithmProfile("post-quantum", False, None),
    "CRYSTALS-KYBER": AlgorithmProfile("post-quantum", False, None),
    "ML-DSA": AlgorithmProfile("post-quantum", False, None),
    "MLDSA": AlgorithmProfile("post-quantum", False, None),
    "DILITHIUM": AlgorithmProfile("post-quantum", False, None),
    "CRYSTALS-DILITHIUM": AlgorithmProfile("post-quantum", False, None),
    "SLH-DSA": AlgorithmProfile("post-quantum", False, None),
    "SLHDSA": AlgorithmProfile("post-quantum", False, None),
    "SPHINCS+": AlgorithmProfile("post-quantum", False, None),
    "SPHINCS": AlgorithmProfile("post-quantum", False, None),
    "FN-DSA": AlgorithmProfile("post-quantum", False, None),
    "FNDSA": AlgorithmProfile("post-quantum", False, None),
    "FALCON": AlgorithmProfile("post-quantum", False, None),
    "HQC": AlgorithmProfile("post-quantum", False, None),
}


def _normalize(algorithm: str) -> str:
    text = algorithm.strip().upper().replace(" ", "")
    # unificar separadores frecuentes en inventarios
    text = text.replace("_", "-")
    # SPHINCS+ y variantes
    if text in {"SPHINCS+", "SPHINCSPLUS", "SPHINCS-PLUS"}:
        return "SPHINCS+"
    return text


def get_algorithm_profile(algorithm: str) -> AlgorithmProfile:
    return ALGORITHM_CATALOG.get(
        _normalize(algorithm), AlgorithmProfile("unknown", False, None)
    )


def _key_size_adjustment(profile: AlgorithmProfile, key_size: int) -> Tuple[int, str]:
    """Ajuste por key_size bajo o muy alto respecto al mínimo recomendado."""
    if profile.min_recommended_key_size is None:
        return 0, ""
    if key_size < profile.min_recommended_key_size:
        return 6, " Además, key_size está por debajo del mínimo recomendado (NIST SP 800-57)."
    if key_size >= profile.min_recommended_key_size * 2:
        return -2, " El key_size usado supera holgadamente el mínimo recomendado."
    return 0, ""


def score_classical_algorithm(algorithm: str, key_size: int) -> Tuple[int, str]:
    """Puntos 0-40 de debilidad clásica del algoritmo + nota."""
    profile = get_algorithm_profile(algorithm)
    base = CLASSICAL_FAMILY_POINTS[profile.family]
    adj, adj_note = _key_size_adjustment(profile, key_size)
    # Para asimétricos, key size bajo es debilidad clásica relevante
    if profile.family != "asymmetric-classical":
        # key size bajo en simétricos legacy ya está reflejado en la familia
        if adj > 0 and profile.family in ("symmetric", "hash-strong"):
            pass
        elif profile.family in ("symmetric-legacy", "hash-broken"):
            adj = max(adj, 0)  # no bajar más
    points = max(0, min(40, base + adj))
    note = FAMILY_NOTES[profile.family] + adj_note
    return points, note


def score_quantum_algorithm(algorithm: str, key_size: int) -> Tuple[int, str]:
    """Puntos 0-40 de exposición cuántica del algoritmo + nota.

    No afirma cuándo llegará un computador cuántico capaz de romper el
    algoritmo; solo clasifica exposición relativa conocida (Shor / Grover).
    """
    profile = get_algorithm_profile(algorithm)
    base = QUANTUM_FAMILY_POINTS[profile.family]
    # Claves más cortas en asimétricos aumentan ligeramente la exposición
    # relativa (menos bits que Shor debe atacar), sin inventar timelines.
    adj = 0
    extra = ""
    if profile.quantum_vulnerable and profile.min_recommended_key_size is not None:
        if key_size < profile.min_recommended_key_size:
            adj = 4
            extra = " Key size por debajo del mínimo recomendado aumenta la exposición relativa."
        elif key_size >= profile.min_recommended_key_size * 2:
            adj = -2
            extra = " Key size holgado reduce ligeramente la exposición relativa al tamaño de instancia."
    points = max(0, min(40, base + adj))
    note = FAMILY_NOTES[profile.family] + extra
    return points, note


def score_algorithm(algorithm: str, key_size: int) -> Tuple[int, str]:
    """Compatibilidad V2: puntos 0-30 combinando debilidad clásica y cuántica.

    Se usa como factor "algorithm" del Risk Score compuesto. No es una
    probabilidad de ataque.
    """
    classical, classical_note = score_classical_algorithm(algorithm, key_size)
    quantum, quantum_note = score_quantum_algorithm(algorithm, key_size)
    # Escala el máximo de ambos a 0-30 para no romper el tope del Risk Engine
    combined = max(classical, quantum)
    points = round(combined * 30 / 40)
    points = max(0, min(30, points))
    profile = get_algorithm_profile(algorithm)
    note = FAMILY_NOTES[profile.family]
    if classical >= quantum:
        note = classical_note
    else:
        note = quantum_note
    return points, note
