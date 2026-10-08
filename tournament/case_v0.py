"""Frozen Case V0 — public vs private. Built from real demo inventory outcomes."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

CASE_ID = "case-v0-payment-migration"
CASE_VERSION = "0.1.0"
EVALUATOR_VERSION = "score-v1"
CORE_VERSION = "INTCOMP-4.1.0"
POLICY_SET_ID = "intcomp-cryptorisk-v1"
POLICY_SET_VERSION = "1.0.0"

# Public inventory snapshot (participant-visible fields only)
PUBLIC_INVENTORY = [
    {"asset_id": "demo-pki", "name": "Demo Root CA", "algorithm": "RSA", "criticality": "critical", "internet_exposed": False, "migration_status": "not_started", "dependencies": [], "heuristic_risk": 61},
    {"asset_id": "demo-pki-int", "name": "Demo Issuing CA", "algorithm": "RSA", "criticality": "critical", "internet_exposed": False, "migration_status": "not_started", "dependencies": ["demo-pki"], "heuristic_risk": 70},
    {"asset_id": "demo-hsm", "name": "Demo HSM", "algorithm": "AES", "criticality": "critical", "internet_exposed": False, "migration_status": "migrated", "dependencies": [], "heuristic_risk": 41},
    {"asset_id": "demo-identity", "name": "Identity Service", "algorithm": "ECDSA", "criticality": "critical", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-pki-int"], "heuristic_risk": 78},
    {"asset_id": "demo-sso", "name": "Enterprise SSO", "algorithm": "RSA", "criticality": "critical", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-identity", "demo-pki-int"], "heuristic_risk": 82},
    {"asset_id": "demo-payment", "name": "Payment Gateway", "algorithm": "RSA", "criticality": "critical", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-sso", "demo-pki-int"], "heuristic_risk": 77},
    {"asset_id": "demo-api", "name": "Public API Edge", "algorithm": "RSA", "criticality": "high", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-sso", "demo-pki-int"], "heuristic_risk": 65},
    {"asset_id": "demo-crm", "name": "Customer CRM", "algorithm": "RSA", "criticality": "high", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-sso"], "heuristic_risk": 71},
    {"asset_id": "demo-legacy-ftp", "name": "Legacy Partner FTP", "algorithm": "RSA", "criticality": "high", "internet_exposed": True, "migration_status": "not_started", "dependencies": [], "heuristic_risk": 70},
    {"asset_id": "demo-low-wiki", "name": "Internal Wiki", "algorithm": "RSA", "criticality": "low", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-pki-int"], "heuristic_risk": 53},
    {"asset_id": "demo-cycle-a", "name": "Region Sync A", "algorithm": "AES", "criticality": "medium", "internet_exposed": False, "migration_status": "not_started", "dependencies": ["demo-cycle-b"], "heuristic_risk": 25},
    {"asset_id": "demo-cycle-b", "name": "Region Sync B", "algorithm": "AES", "criticality": "medium", "internet_exposed": False, "migration_status": "not_started", "dependencies": ["demo-cycle-a"], "heuristic_risk": 25},
    {"asset_id": "demo-ghost", "name": "EDI Bridge", "algorithm": "3DES", "criticality": "high", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-payment", "demo-GHOST-MAINFRAME"], "heuristic_risk": 68},
    {"asset_id": "demo-migrated", "name": "Offsite Backup", "algorithm": "AES", "criticality": "critical", "internet_exposed": False, "migration_status": "migrated", "dependencies": ["demo-hsm"], "heuristic_risk": 38},
    {"asset_id": "demo-pqc", "name": "PQC Pilot Endpoint", "algorithm": "ML-KEM", "criticality": "medium", "internet_exposed": False, "migration_status": "migrated", "dependencies": ["demo-hsm"], "heuristic_risk": 14},
    {"asset_id": "demo-unknown", "name": "Mystery Box", "algorithm": "UNKNOWN_ALGO", "criticality": "medium", "internet_exposed": False, "migration_status": "not_started", "dependencies": [], "heuristic_risk": 27},
    {"asset_id": "demo-msg", "name": "Event Bus", "algorithm": "AES", "criticality": "high", "internet_exposed": False, "migration_status": "not_started", "dependencies": ["demo-pki-int"], "heuristic_risk": 25},
    {"asset_id": "demo-portal", "name": "Customer Portal", "algorithm": "RSA", "criticality": "high", "internet_exposed": True, "migration_status": "not_started", "dependencies": ["demo-sso", "demo-crm"], "heuristic_risk": 64},
]

PUBLIC_CASE: Dict[str, Any] = {
    "case_id": CASE_ID,
    "case_version": CASE_VERSION,
    "title": "CASE V0 — Crypto Payment Migration",
    "objective": (
        "Prepare a dependency-safe path to migrate the Payment Gateway (demo-payment). "
        "Highest heuristic risk is not necessarily the first migration step. "
        "Distinguish CONFLICT (blocked) from WARNING (not blocked)."
    ),
    "constraints": [
        "Respect declared dependencies (prerequisite before dependent).",
        "Do not plan new migration work for already migrated assets.",
        "Dependency cycles have no valid full migration sequence until resolved.",
        "Missing inventory dependencies are not executable steps.",
        "demo-payment may appear only after its prerequisites on the trust path.",
    ],
    "task": {
        "priority_assets_k": 5,
        "target_assessments_required": ["demo-payment", "demo-legacy-ftp"],
        "labels": ["CONFLICT", "WARNING", "NO_CONFLICT"],
        "migration_sequence": "Ordered asset_ids toward safe payment migration.",
    },
    "inventory": PUBLIC_INVENTORY,
    "disclaimer": "Heuristic risk is prioritization only — not probability of attack.",
}

# Dependency edges from inventory (dep -> dependent)
def _edges():
    e = []
    for a in PUBLIC_INVENTORY:
        for d in a["dependencies"]:
            e.append([d, a["asset_id"]])
    return e

PRIVATE_CASE: Dict[str, Any] = {
    "case_id": CASE_ID,
    "case_version": CASE_VERSION,
    "evaluator_version": EVALUATOR_VERSION,
    "core_version": CORE_VERSION,
    "policy_set_id": POLICY_SET_ID,
    "policy_set_version": POLICY_SET_VERSION,
    "must_attention": ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
    "allowed_priority": [
        "demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment", "demo-legacy-ftp"
    ],
    "expected_severity": {
        "demo-payment": "CONFLICT",
        "demo-legacy-ftp": "WARNING",
    },
    "expected_sequence_canonical": [
        "demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"
    ],
    "goal_target": "demo-payment",
    "goal_ancestors": ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso"],
    "edges": _edges(),
    "known_assets": [a["asset_id"] for a in PUBLIC_INVENTORY],
    "missing_nodes": ["demo-GHOST-MAINFRAME"],
    "no_work_assets": ["demo-hsm", "demo-migrated", "demo-pqc"],
}


def _hash_obj(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def public_hash() -> str:
    return _hash_obj(PUBLIC_CASE)


def private_hash() -> str:
    return _hash_obj(PRIVATE_CASE)


def freeze_meta() -> Dict[str, Any]:
    return {
        "case_id": CASE_ID,
        "case_version": CASE_VERSION,
        "core_version": CORE_VERSION,
        "policy_set_id": POLICY_SET_ID,
        "policy_set_version": POLICY_SET_VERSION,
        "inventory_hash": _hash_obj(PUBLIC_INVENTORY),
        "graph_hash": _hash_obj(_edges()),
        "expected_outcome_hash": private_hash(),
        "public_hash": public_hash(),
        "evaluator_version": EVALUATOR_VERSION,
    }
