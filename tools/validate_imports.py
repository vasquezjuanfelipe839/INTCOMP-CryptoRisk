"""Preflight import check — must pass before Uvicorn starts."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime_INTCOMP-V41"
os.environ.setdefault("INTCOMP_ROOT", str(RUNTIME))
sys.path.insert(0, str(RUNTIME))
sys.path.insert(0, str(ROOT / "backend"))

checks = [
    ("requests", lambda: __import__("requests")),
    ("yaml", lambda: __import__("yaml")),
    ("pandas", lambda: __import__("pandas")),
    ("fastapi", lambda: __import__("fastapi")),
    ("ai.nvidia_client", lambda: __import__("ai.nvidia_client", fromlist=["NVIDIAClient"])),
    ("ai.fallback_client", lambda: __import__("ai.fallback_client", fromlist=["FallbackClient"])),
    ("crypto.inventory_loader", lambda: __import__("crypto.inventory_loader", fromlist=["load_inventory"])),
    ("core.stress_test_engine", lambda: __import__("core.stress_test_engine", fromlist=["run_stress_test"])),
    ("backend.main", lambda: __import__("main")),
]

failed = []
for name, fn in checks:
    try:
        fn()
        print(f"  {name:28} OK")
    except Exception as e:
        print(f"  {name:28} FAIL  {type(e).__name__}: {e}")
        failed.append((name, str(e)))

if failed:
    sys.exit(1)
print("CORE_IMPORTS_OK")
sys.exit(0)
