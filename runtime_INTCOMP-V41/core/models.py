"""Modelos de datos del sistema.

CryptoAsset es la entrada validada (lo que viene del CSV). Los distintos
*Breakdown son la salida de cada motor determinístico: siempre guardan el
total y el detalle por factor, para que la UI pueda explicar cada número.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MigrationStatus(str, Enum):
    """Estado real de migración del activo. Independiente de Migration Priority."""

    NOT_STARTED = "not_started"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    MIGRATED = "migrated"


class CryptoAsset(BaseModel):
    """Un activo criptográfico del inventario, ya validado."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    asset_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    algorithm: str = Field(min_length=1, max_length=64)
    key_size: int = Field(ge=0, le=65536)
    protocol: str = Field(min_length=1, max_length=64)
    criticality: Criticality
    internet_exposed: bool
    data_lifetime_years: int = Field(ge=0, le=100)
    dependencies: List[str] = Field(default_factory=list, max_length=50)
    migration_status: MigrationStatus = MigrationStatus.NOT_STARTED
    aliases: List[str] = Field(default_factory=list, max_length=20)

    @field_validator("asset_id", "name", "algorithm", "protocol")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("no puede estar vacío")
        return value

    @field_validator("asset_id")
    @classmethod
    def asset_id_charset(cls, value: str) -> str:
        """Solo identificadores seguros (sin path traversal)."""
        if ".." in value or "/" in value or "\\" in value:
            raise ValueError("asset_id contiene patrón de path no permitido")
        if any(ord(c) < 32 for c in value):
            raise ValueError("asset_id contiene caracteres de control")
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@-")
        if not set(value) <= allowed:
            raise ValueError("asset_id contiene caracteres no permitidos")
        return value

    @field_validator("criticality", mode="before")
    @classmethod
    def parse_criticality(cls, value):
        if isinstance(value, Criticality):
            return value
        text = str(value).strip().lower()
        # aliases comunes
        aliases = {
            "critica": "critical",
            "crítica": "critical",
            "medio": "medium",
            "media": "medium",
            "bajo": "low",
            "baja": "low",
            "alto": "high",
            "alta": "high",
        }
        text = aliases.get(text, text)
        return Criticality(text)

    @field_validator("dependencies", mode="before")
    @classmethod
    def parse_dependencies(cls, value):
        """Acepta lista, string vacío, o string separado por ';' o ','."""
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        text = str(value).strip()
        if not text:
            return []
        # Normalizar separadores mixtos ; y ,
        text = text.replace(";", ",")
        if "," in text:
            return [p.strip() for p in text.split(",") if p.strip()]
        return [text]

    @field_validator("dependencies")
    @classmethod
    def dependencies_safe(cls, value: List[str]) -> List[str]:
        cleaned: List[str] = []
        for dep in value:
            dep = dep.strip()
            if not dep:
                continue
            if ".." in dep or "/" in dep or "\\" in dep:
                raise ValueError(f"dependency insegura: {dep!r}")
            if len(dep) > 128:
                raise ValueError("dependency excede longitud máxima")
            cleaned.append(dep)
        if len(cleaned) > 50:
            raise ValueError("demasiadas dependencias (máx. 50)")
        return cleaned


    @field_validator("aliases", mode="before")
    @classmethod
    def parse_aliases(cls, value):
        """Acepta lista o string separado por ';' o ','."""
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()][:20]
        text = str(value).strip()
        if not text:
            return []
        parts = text.replace(";", ",").split(",")
        return [p.strip() for p in parts if p.strip()][:20]

    @field_validator("migration_status", mode="before")
    @classmethod
    def parse_migration_status(cls, value):
        if value is None or (isinstance(value, str) and not value.strip()):
            return MigrationStatus.NOT_STARTED
        if isinstance(value, MigrationStatus):
            return value
        text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        return MigrationStatus(text)

    @model_validator(mode="after")
    def no_self_dependency(self) -> "CryptoAsset":
        if self.asset_id in self.dependencies:
            raise ValueError("un activo no puede depender de sí mismo")
        return self


class ScoreBreakdown(BaseModel):
    """Resultado de un motor determinístico: total + factores explicados."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0, le=100)
    factors: Dict[str, float] = Field(default_factory=dict)
    notes: Dict[str, str] = Field(default_factory=dict)

    @field_validator("total", mode="before")
    @classmethod
    def clamp_total(cls, value):
        """Acepta int/float y acota a 0-100 por robustez de motores."""
        try:
            v = int(round(float(value)))
        except (TypeError, ValueError) as exc:
            raise ValueError("total debe ser numérico") from exc
        return max(0, min(100, v))


class AssetScores(BaseModel):
    """Todos los scores calculados para un activo, listos para la UI."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=128)
    classical_risk: ScoreBreakdown
    quantum_exposure: ScoreBreakdown
    risk: ScoreBreakdown
    agility_estimate: ScoreBreakdown
    dependency_impact: ScoreBreakdown
    strategic_impact: ScoreBreakdown
    migration_priority: ScoreBreakdown


class InventoryLoadResult(BaseModel):
    """Resultado de cargar un CSV: activos válidos + problemas encontrados."""

    model_config = ConfigDict(extra="forbid")

    assets: List[CryptoAsset]
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    @property
    def is_usable(self) -> bool:
        return len(self.assets) > 0
