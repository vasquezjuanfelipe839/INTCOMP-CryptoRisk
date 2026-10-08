#!/usr/bin/env python3
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
results = []

def ok(name, cond, detail=""):
    results.append((name, cond, detail))
    print(f"{name:22} {'OK' if cond else 'FAIL'} {detail}")

print("=" * 40)
print("INTCOMP CHECK")
print("=" * 40)
ok("Python", sys.version_info >= (3, 9), sys.version.split()[0])
core = ROOT / "runtime_INTCOMP-V41" / "core" / "stress_test_engine.py"
ok("Core", core.exists(), str(core.name))
demo = ROOT / "demo" / "demo_inventory.csv"
ok("Demo CSV", demo.exists())
try:
    import fastapi, uvicorn, pandas, requests, yaml  # noqa
    ok("Dependencies", True)
except Exception as e:
    ok("Dependencies", False, str(e))
try:
    import os
    os.environ["INTCOMP_ROOT"] = str(ROOT / "runtime_INTCOMP-V41")
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    h = c.get("/api/health").json()
    ok("API", h.get("ok") is True)
    c.post("/api/inventory/load-demo")
    r = c.post("/api/stress-test/compare", json={"asset_id": "demo-payment"}).json()
    ok("AI Boundary", r.get("parity") is True)
    inj = c.post(
        "/api/stress-test",
        json={"asset_id": "demo-payment", "severity": "NO_CONFLICT", "sequence": ["X"]},
    ).json()
    ok("Injection guard", inj["core"]["severity"] == "CONFLICT")
except Exception as e:
    ok("API", False, str(e)[:80])
print("=" * 40)
status = "READY" if all(x[1] for x in results) else "NOT READY"
print(f"FINAL STATUS: {status}")
sys.exit(0 if status == "READY" else 1)
