#!/usr/bin/env python3
"""INTCOMP Easy Launcher — starts FastAPI over real Core. No decision logic here."""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
REQ = ROOT / "requirements.txt"
HOST = "127.0.0.1"
PORT = 8000
URL = f"http://{HOST}:{PORT}"


def log(step: str, msg: str = "OK") -> None:
    print(f"[{step}] {msg}")


def find_python() -> str:
    candidates = []
    if sys.platform == "win32":
        candidates = ["py -3", "python", "python3"]
    else:
        candidates = ["python3", "python"]
    for c in candidates:
        try:
            parts = c.split()
            r = subprocess.run(
                parts + ["-c", "import sys; assert sys.version_info >= (3, 9); print(sys.executable)"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            continue
    return ""


def venv_python() -> Path:
    if sys.platform == "win32":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def ensure_venv(base_py: str) -> Path:
    """Prefer local .venv; fall back to system interpreter if venv cannot be created."""
    vp = venv_python()
    if vp.exists():
        log("2/5", "Virtual environment found")
        return vp
    log("2/5", "Creating virtual environment (.venv)...")
    r = subprocess.run([base_py, "-m", "venv", str(VENV)], capture_output=True, text=True)
    if r.returncode == 0 and vp.exists():
        log("2/5", "Virtual environment created")
        return vp
    # Restricted environments (or missing venv): fall back
    log("2/5", "Local venv unavailable — using system Python")
    return Path(base_py)


REQUIRED_IMPORT_CHECKS = [
    ("fastapi", "import fastapi"),
    ("uvicorn", "import uvicorn"),
    ("python-multipart", "import multipart"),
    ("pandas", "import pandas"),
    ("pydantic", "import pydantic"),
    ("requests", "import requests"),
    ("PyYAML", "import yaml"),
]


def missing_deps(py: Path) -> list:
    missing = []
    for name, code in REQUIRED_IMPORT_CHECKS:
        r = subprocess.run([str(py), "-c", code], capture_output=True, text=True)
        if r.returncode != 0:
            missing.append(name)
    return missing


def deps_ok(py: Path) -> bool:
    return not missing_deps(py)


def ensure_deps(py: Path) -> None:
    miss = missing_deps(py)
    if not miss:
        log("3/6", "Dependencies already installed")
        return
    print("      Missing dependency: " + ", ".join(miss))
    log("3/6", "Installing dependencies (first run may take a minute)...")
    subprocess.run([str(py), "-m", "pip", "install", "--upgrade", "pip"], capture_output=True)
    r = subprocess.run([str(py), "-m", "pip", "install", "-r", str(REQ)])
    if r.returncode != 0:
        print("ERROR")
        print("Could not install required dependencies.")
        print("Please check your internet connection and run START_INTCOMP.bat again.")
        sys.exit(1)
    miss2 = missing_deps(py)
    if miss2:
        print("ERROR")
        print("Still missing after install: " + ", ".join(miss2))
        print("Try again with internet access.")
        sys.exit(1)
    log("3/6", "Dependencies installed")


def validate_core_imports(py: Path) -> None:
    log("4/6", "Checking Core / AI imports...")
    script = ROOT / "tools" / "validate_imports.py"
    r = subprocess.run([str(py), str(script)], cwd=str(ROOT))
    if r.returncode != 0:
        print("ERROR")
        print("Core/AI import check failed.")
        print("A required package may still be missing (e.g. requests).")
        print("Attempting one more install of requirements.txt...")
        subprocess.run([str(py), "-m", "pip", "install", "-r", str(REQ)])
        r2 = subprocess.run([str(py), str(script)], cwd=str(ROOT))
        if r2.returncode != 0:
            print("ERROR: Could not import INTCOMP Core modules.")
            print("See messages above. Fix dependencies and retry.")
            sys.exit(1)
    log("4/6", "Core imports OK")



def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((HOST, port)) != 0


def wait_ready(timeout: float = 45.0) -> bool:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(URL + "/api/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def banner() -> None:
    print("=" * 48)
    print("     INTCOMP CryptoRisk V4.1")
    print("     Easy Launcher (Web Prototype)")
    print("=" * 48)
    print()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="Open UI (user loads demo in browser)")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    global PORT, URL
    PORT = args.port
    URL = f"http://{HOST}:{PORT}"

    banner()
    os.environ["INTCOMP_ROOT"] = str(ROOT / "runtime_INTCOMP-V41")
    os.chdir(ROOT)

    log("1/5", "Checking Python...")
    base = find_python()
    if not base:
        print("ERROR")
        print("Python was not found.")
        print("Possible cause: Python is not installed.")
        print("Solution: Install Python 3.10+ from https://www.python.org/downloads/")
        print("          On Windows, check 'Add python.exe to PATH'.")
        return 1
    log("1/5", f"OK ({base})")

    core = ROOT / "runtime_INTCOMP-V41" / "core" / "stress_test_engine.py"
    if not core.exists():
        print("ERROR")
        print("INTCOMP Core runtime is missing.")
        print(f"Expected: {core}")
        return 1

    py = ensure_venv(base)
    ensure_deps(py)
    validate_core_imports(py)

    if not port_free(PORT):
        print(f"WARNING: Port {PORT} appears busy.")
        print("If INTCOMP is already running, open:")
        print(f"  {URL}")
        print("Or close the other process and try again.")
        # still try health
        if wait_ready(3):
            log("5/6", "Server already responding")
            if not args.no_browser:
                webbrowser.open(URL)
            print()
            print(f"INTCOMP is running at:\n  {URL}")
            print("Do not close this window while using INTCOMP.")
            print("Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                print("\nStopped.")
            return 0

    log("5/6", "Starting INTCOMP server...")
    env = os.environ.copy()
    env["INTCOMP_ROOT"] = str(ROOT / "runtime_INTCOMP-V41")
    proc = subprocess.Popen(
        [
            str(py),
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            HOST,
            "--port",
            str(PORT),
        ],
        cwd=str(ROOT),
        env=env,
    )

    if not wait_ready():
        print("ERROR")
        print("Server did not become ready in time.")
        print("Possible cause: missing dependency or Core import error.")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        return 1

    log("6/6", "Opening browser...")
    if not args.no_browser:
        try:
            webbrowser.open(URL)
        except Exception:
            print(f"Open your browser and visit:\n  {URL}")

    print()
    print("=" * 48)
    print(f"INTCOMP is running at:\n  {URL}")
    print()
    print("Tips:")
    print("  1. Click 'Load demo inventory'")
    print("  2. Open Stress Test → demo-payment")
    print("  3. Try AI Boundary comparison")
    print()
    print("Do not close this window while using INTCOMP.")
    print("Press Ctrl+C to stop.")
    print("=" * 48)

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\nStopping...")
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
        print("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
