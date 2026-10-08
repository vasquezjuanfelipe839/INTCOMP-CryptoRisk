"""Carga y valida el CSV de inventario criptográfico.

No confía ciegamente en el archivo: valida cada fila con Pydantic, detecta
asset_id duplicados y dependencias que apuntan a activos que no existen.
Nunca lanza una excepción por una fila individual mala — la reporta como
error y sigue con el resto, para que un solo dato sucio no tumbe todo el
inventario.

migration_status es opcional: si falta la columna o el valor, se asume
not_started (compatibilidad con inventarios V2).
"""

from __future__ import annotations

import io
from typing import Union

import pandas as pd
from pydantic import ValidationError

from core.models import CryptoAsset, InventoryLoadResult, MigrationStatus
from core.security_controls import (
    is_safe_asset_id,
    measure_source_size,
    redact_secrets,
    validate_csv_rows,
    validate_csv_size,
)
from core import config as app_config

REQUIRED_COLUMNS = {
    "asset_id",
    "name",
    "algorithm",
    "key_size",
    "protocol",
    "criticality",
    "internet_exposed",
    "data_lifetime_years",
    "dependencies",
}


def _parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text in {"true", "1", "yes", "si", "sí"}


def load_inventory(source: Union[str, io.BytesIO, io.StringIO]) -> InventoryLoadResult:
    """Carga un CSV (path o buffer) y devuelve activos válidos + errores."""
    size = measure_source_size(source)
    size_err = validate_csv_size(size)
    if size_err:
        return InventoryLoadResult(assets=[], errors=[size_err])

    try:
        df = pd.read_csv(source, dtype=str, keep_default_na=False)
    except Exception as exc:  # noqa: BLE001 - queremos capturar cualquier fallo de parseo
        return InventoryLoadResult(
            assets=[], errors=[redact_secrets(f"No se pudo leer el CSV: {exc}")]
        )

    row_err = validate_csv_rows(len(df))
    if row_err:
        return InventoryLoadResult(assets=[], errors=[row_err])

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        return InventoryLoadResult(
            assets=[], errors=[f"Faltan columnas obligatorias: {sorted(missing)}"]
        )

    has_status = "migration_status" in df.columns
    has_aliases = "aliases" in df.columns
    assets = []
    errors = []
    warnings = []
    seen_ids = set()

    for idx, row in df.iterrows():
        row_num = idx + 2  # +1 por header, +1 porque idx arranca en 0
        try:
            status_raw = row["migration_status"] if has_status else MigrationStatus.NOT_STARTED
            aliases_raw = row["aliases"] if has_aliases else []
            asset = CryptoAsset(
                asset_id=row["asset_id"],
                name=row["name"],
                algorithm=row["algorithm"],
                key_size=int(row["key_size"]) if row["key_size"] else 0,
                protocol=row["protocol"],
                criticality=row["criticality"].strip().lower(),
                internet_exposed=_parse_bool(row["internet_exposed"]),
                data_lifetime_years=int(row["data_lifetime_years"])
                if row["data_lifetime_years"]
                else 0,
                dependencies=row["dependencies"],
                migration_status=status_raw,
                aliases=aliases_raw,
            )
        except (ValidationError, ValueError) as exc:
            errors.append(f"Fila {row_num}: {redact_secrets(str(exc))}")
            continue

        if not is_safe_asset_id(asset.asset_id):
            errors.append(
                f"Fila {row_num}: asset_id contiene caracteres no permitidos "
                f"o patrón inseguro"
            )
            continue
        if len(asset.asset_id) > app_config.SECURITY_MAX_ASSET_ID_LEN:
            errors.append(
                f"Fila {row_num}: asset_id exceeds max length "
                f"({app_config.SECURITY_MAX_ASSET_ID_LEN})"
            )
            continue
        if len(asset.name) > app_config.SECURITY_MAX_NAME_LEN:
            errors.append(
                f"Fila {row_num}: name exceeds max length "
                f"({app_config.SECURITY_MAX_NAME_LEN})"
            )
            continue
        if len(asset.dependencies) > app_config.SECURITY_MAX_DEPENDENCIES_PER_ASSET:
            errors.append(
                f"Fila {row_num}: too many dependencies "
                f"(>{app_config.SECURITY_MAX_DEPENDENCIES_PER_ASSET})"
            )
            continue

        if asset.asset_id in seen_ids:
            errors.append(f"Fila {row_num}: asset_id '{asset.asset_id}' duplicado")
            continue

        seen_ids.add(asset.asset_id)
        assets.append(asset)

    all_ids = {a.asset_id for a in assets}
    for asset in assets:
        for dep in asset.dependencies:
            if dep not in all_ids:
                warnings.append(
                    f"'{asset.asset_id}' depende de '{dep}', que no existe en el inventario"
                )

    return InventoryLoadResult(assets=assets, errors=errors, warnings=warnings)
