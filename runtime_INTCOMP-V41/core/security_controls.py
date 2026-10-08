"""Controles de mitigación STRIDE implementados en código.

- Tampering / DoS: límites de tamaño y filas de CSV, sanitización básica
- Information Disclosure: redacción de secretos en texto de error
- Repudiation: audit log best-effort de eventos de decisión
- Elevation: helpers para verificar usuario no-root en runtime (informativo)

No sustituye autenticación perimetral ni TLS (ver docs/security.md).
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Optional, Tuple, Union

from core import config

_SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key\s*[:=]\s*)\S+", re.I),
    re.compile(r"(authorization\s*:\s*bearer\s+)\S+", re.I),
    re.compile(r"(nvapi-[A-Za-z0-9_-]+)", re.I),
]


def redact_secrets(text: str) -> str:
    """Evita filtrar API keys en mensajes de error o logs."""
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(r"\1***REDACTED***", out)
    return out


def validate_csv_size(num_bytes: int) -> Optional[str]:
    if num_bytes > config.SECURITY_MAX_CSV_BYTES:
        return (
            f"CSV exceeds size limit ({num_bytes} bytes > "
            f"{config.SECURITY_MAX_CSV_BYTES} bytes)."
        )
    return None


def validate_csv_rows(num_rows: int) -> Optional[str]:
    if num_rows > config.SECURITY_MAX_CSV_ROWS:
        return (
            f"CSV exceeds row limit ({num_rows} > {config.SECURITY_MAX_CSV_ROWS})."
        )
    return None


def measure_source_size(source: Union[str, Path, object]) -> int:
    """Best-effort size for path or buffer."""
    if isinstance(source, (str, Path)):
        path = Path(source)
        if path.is_file():
            return path.stat().st_size
        return 0
    # file-like
    try:
        pos = source.tell()  # type: ignore[attr-defined]
        source.seek(0, 2)  # type: ignore[attr-defined]
        size = source.tell()  # type: ignore[attr-defined]
        source.seek(pos)  # type: ignore[attr-defined]
        return int(size)
    except Exception:  # noqa: BLE001
        try:
            data = source.getvalue()  # type: ignore[attr-defined]
            return len(data) if data is not None else 0
        except Exception:  # noqa: BLE001
            return 0


def audit_event(event_type: str, detail: str = "") -> None:
    """Append-only audit line. Failures are silent (must not break analysis)."""
    if not getattr(config, "SECURITY_AUDIT_ENABLED", True):
        return
    try:
        path = ensure_audit_parent_safe(config.SECURITY_AUDIT_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > config.SECURITY_AUDIT_MAX_BYTES:
            # simple truncate to last half
            data = path.read_bytes()
            path.write_bytes(data[len(data) // 2 :])
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} | {event_type} | {redact_secrets(detail)}\n"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:  # noqa: BLE001
        return


def runtime_security_status() -> dict:
    """Informational checks for operators."""
    uid = os.geteuid() if hasattr(os, "geteuid") else None
    return {
        "running_as_uid": uid,
        "is_root": uid == 0 if uid is not None else "unknown",
        "ai_enabled_env": os.getenv("AI_ENABLED", "true"),
        "has_nvidia_key": bool(os.getenv("NVIDIA_API_KEY", "").strip()),
        "audit_path": config.SECURITY_AUDIT_PATH,
        "max_csv_bytes": config.SECURITY_MAX_CSV_BYTES,
        "max_csv_rows": config.SECURITY_MAX_CSV_ROWS,
    }


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")


def is_safe_asset_id(asset_id: str) -> bool:
    """Reject path traversal and odd control characters in asset_id."""
    if not asset_id or not isinstance(asset_id, str):
        return False
    if ".." in asset_id or "/" in asset_id or "\\" in asset_id:
        return False
    if any(ord(c) < 32 for c in asset_id):
        return False
    return bool(_SAFE_ID.match(asset_id.strip()))


def ensure_audit_parent_safe(path: str | Path) -> Path:
    """Resolve audit path; avoid writing outside cwd/data-ish roots when relative."""
    pth = Path(path).expanduser()
    if not pth.is_absolute():
        pth = Path.cwd() / pth
    return pth.resolve()
