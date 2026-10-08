"""Tournament MVP tests — auth, benchmarks, security, isolation."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("INTCOMP_ROOT", str(ROOT / "runtime_INTCOMP-V41"))

from tournament.case_v0 import PRIVATE_CASE  # noqa: E402
from tournament.evaluator import evaluate  # noqa: E402


def _sub(priority, assessments, sequence):
    return {
        "priority_assets": priority,
        "target_assessments": assessments,
        "migration_sequence": sequence,
        "justification_tags": [],
    }


PERFECT = _sub(
    ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
    [
        {"asset_id": "demo-payment", "label": "CONFLICT"},
        {"asset_id": "demo-legacy-ftp", "label": "WARNING"},
    ],
    ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
)
RISK_ONLY = _sub(
    ["demo-sso", "demo-identity", "demo-payment", "demo-crm", "demo-pki-int"],
    [
        {"asset_id": "demo-payment", "label": "CONFLICT"},
        {"asset_id": "demo-legacy-ftp", "label": "CONFLICT"},
    ],
    ["demo-sso", "demo-identity", "demo-payment", "demo-crm", "demo-pki-int"],
)
REVERSE = _sub(
    ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
    [
        {"asset_id": "demo-payment", "label": "CONFLICT"},
        {"asset_id": "demo-legacy-ftp", "label": "WARNING"},
    ],
    ["demo-payment", "demo-sso", "demo-identity", "demo-pki-int", "demo-pki"],
)
SWAP = _sub(
    ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
    [
        {"asset_id": "demo-payment", "label": "WARNING"},
        {"asset_id": "demo-legacy-ftp", "label": "CONFLICT"},
    ],
    ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
)
EMPTY = _sub([], [], [])


def test_perfect_near_100():
    e = evaluate(PRIVATE_CASE, PERFECT)
    assert e["score"] >= 95


def test_empty_zero():
    assert evaluate(PRIVATE_CASE, EMPTY)["score"] == 0


def test_ranking_order():
    scores = {
        "A": evaluate(PRIVATE_CASE, PERFECT)["score"],
        "B": evaluate(PRIVATE_CASE, RISK_ONLY)["score"],
        "C": evaluate(PRIVATE_CASE, REVERSE)["score"],
        "D": evaluate(PRIVATE_CASE, SWAP)["score"],
        "E": evaluate(PRIVATE_CASE, EMPTY)["score"],
    }
    assert scores == {"A": 100.0, "B": 48.5, "C": 65.0, "D": 75.0, "E": 0.0}
    assert scores["A"] > scores["D"] > scores["C"] > scores["B"] > scores["E"]


def test_payment_first_zeros_sequence_components():
    e = evaluate(PRIVATE_CASE, REVERSE)
    assert e["breakdown"]["C4"] == 0 and e["breakdown"]["C5"] == 0


def test_unknown_asset_no_full_precision():
    bad = _sub(
        ["demo-pki", "not-real-asset", "demo-payment", "demo-sso", "demo-identity"],
        [{"asset_id": "demo-payment", "label": "CONFLICT"}, {"asset_id": "demo-legacy-ftp", "label": "WARNING"}],
        ["demo-pki", "demo-pki-int", "demo-identity", "demo-sso", "demo-payment"],
    )
    e = evaluate(PRIVATE_CASE, bad)
    assert e["breakdown"]["C2"] < 1.0 and e["breakdown"]["C6"] < 1.0


def test_ghost_in_sequence_invalid():
    ghost = dict(PERFECT)
    ghost["migration_sequence"] = PERFECT["migration_sequence"] + ["demo-GHOST-MAINFRAME"]
    assert evaluate(PRIVATE_CASE, ghost)["breakdown"]["C4"] == 0


def test_reproducible():
    assert evaluate(PRIVATE_CASE, PERFECT) == evaluate(PRIVATE_CASE, PERFECT)


def test_client_score_ignored_by_evaluator():
    s = dict(PERFECT)
    s["score"] = 100
    assert evaluate(PRIVATE_CASE, s)["score"] >= 95


@pytest.fixture()
def client(tmp_path):
    from fastapi.testclient import TestClient
    import main as m
    from tournament.router import init_store

    init_store(tmp_path / "t.sqlite3")
    return TestClient(m.app)


def _register(client, name):
    r = client.post("/api/t/participants", json={"display_name": name})
    assert r.status_code == 200
    p = r.json()["participant"]
    assert "access_token" in p and p["access_token"]
    assert "participant_id" in p
    return p


def _auth(token, **extra):
    h = {"Authorization": f"Bearer {token}"}
    h.update(extra)
    return h


def test_server_generated_participant_id(client):
    p = _register(client, "Alice")
    assert p["participant_id"].startswith("p-")
    assert len(p["participant_id"]) > 20
    # client id ignored
    p2 = client.post(
        "/api/t/participants",
        json={"display_name": "Forced", "participant_id": "p-admin"},
    ).json()["participant"]
    assert p2["participant_id"] != "p-admin"


def test_token_uniqueness(client):
    a = _register(client, "A")
    b = _register(client, "B")
    assert a["access_token"] != b["access_token"]
    assert a["participant_id"] != b["participant_id"]


def test_submit_requires_token(client):
    body = {"case_id": "case-v0-payment-migration", **PERFECT}
    assert client.post("/api/t/submissions", json=body).status_code == 401
    assert client.post("/api/t/submissions", json=body, headers=_auth("fake")).status_code == 401


def test_api_public_case_hides_private(client):
    r = client.get("/api/t/cases/case-v0-payment-migration")
    assert r.status_code == 200
    assert "must_attention" not in r.json()
    assert "expected_severity" not in r.json()
    assert "P002" not in r.text
    assert "access_token" not in r.text


def test_submission_flow_token_and_one_shot(client):
    p = _register(client, "Alice")
    body = {"case_id": "case-v0-payment-migration", **PERFECT, "score": 0}
    r = client.post("/api/t/submissions", json=body, headers=_auth(p["access_token"]))
    assert r.status_code == 200
    assert r.json()["score"] >= 95
    r2 = client.post("/api/t/submissions", json=body, headers=_auth(p["access_token"]))
    assert r2.status_code == 409


def test_cross_participant_isolation(client):
    a = _register(client, "A")
    b = _register(client, "B")
    body = {"case_id": "case-v0-payment-migration", **PERFECT}
    sub = client.post("/api/t/submissions", json=body, headers=_auth(a["access_token"])).json()
    sid = sub["submission_id"]
    assert client.get(f"/api/t/submissions/{sid}", headers=_auth(a["access_token"])).status_code == 200
    assert client.get(f"/api/t/submissions/{sid}", headers=_auth(b["access_token"])).status_code == 404
    assert client.get(f"/api/t/audit/{sid}", headers=_auth(b["access_token"])).status_code == 404
    assert client.get(f"/api/t/audit/{sid}", headers=_auth(a["access_token"])).status_code == 200


def test_x_participant_id_cannot_override_bearer(client):
    a = _register(client, "A")
    b = _register(client, "B")
    body = {"case_id": "case-v0-payment-migration", **PERFECT}
    # Submit as A while claiming X-Participant-Id: B
    r = client.post(
        "/api/t/submissions",
        json=body,
        headers=_auth(a["access_token"], **{"X-Participant-Id": b["participant_id"]}),
    )
    assert r.status_code == 200
    sid = r.json()["submission_id"]
    # Owned by A: B cannot read; A can
    assert client.get(f"/api/t/submissions/{sid}", headers=_auth(b["access_token"])).status_code == 404
    assert client.get(f"/api/t/submissions/{sid}", headers=_auth(a["access_token"])).status_code == 200
    # X-Participant-Id alone is not enough
    assert client.get(
        f"/api/t/submissions/{sid}",
        headers={"X-Participant-Id": a["participant_id"]},
    ).status_code == 401


def test_fake_token_rejected(client):
    assert client.get("/api/t/submissions/x", headers=_auth("not-a-real-token")).status_code == 401
    assert client.get("/api/t/audit/x", headers=_auth("")).status_code == 401


def test_score_injection_api(client):
    p = _register(client, "Dodger")
    body = {
        "case_id": "case-v0-payment-migration",
        "priority_assets": [],
        "target_assessments": [],
        "migration_sequence": [],
        "score": 100,
        "evaluation": {"C1": 1},
    }
    r = client.post("/api/t/submissions", json=body, headers=_auth(p["access_token"]))
    assert r.status_code == 200
    assert r.json()["score"] == 0.0


def test_leaderboard(client):
    for name, sub in [("P1", PERFECT), ("P2", RISK_ONLY), ("P3", EMPTY)]:
        p = _register(client, name)
        client.post(
            "/api/t/submissions",
            json={"case_id": "case-v0-payment-migration", **sub},
            headers=_auth(p["access_token"]),
        )
    board = client.get("/api/t/leaderboards/round-mvp-1").json()["leaderboard"]
    assert board[0]["display_name"] == "P1"
    assert board[0]["score"] >= board[-1]["score"]


def test_public_endpoints_no_tokens(client):
    for path in [
        "/api/t/tournaments",
        "/api/t/tournaments/tour-mvp-1",
        "/api/t/rounds/round-mvp-1/cases",
        "/api/t/cases/case-v0-payment-migration",
        "/api/t/leaderboards/round-mvp-1",
    ]:
        r = client.get(path)
        assert r.status_code == 200
        assert "access_token" not in r.text
        assert "token_hash" not in r.text


def test_v35_health_still_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["authority"]["core"] == "ABSOLUTE"
    assert r.json()["authority"]["ai"] == "NONE"
