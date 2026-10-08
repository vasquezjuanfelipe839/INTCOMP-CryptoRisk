"""Tournament API under /api/t/* — isolated from V3.5 analysis routes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from tournament.case_v0 import PRIVATE_CASE, PUBLIC_CASE, freeze_meta
from tournament.evaluator import evaluate
from tournament.store import TournamentStore

router = APIRouter(prefix="/api/t", tags=["tournament"])

_STORE: Optional[TournamentStore] = None


def init_store(db_path: Path) -> TournamentStore:
    global _STORE
    _STORE = TournamentStore(db_path)
    _STORE.seed_mvp(PUBLIC_CASE, PRIVATE_CASE, freeze_meta())
    return _STORE


def store() -> TournamentStore:
    if _STORE is None:
        raise HTTPException(503, "Tournament store not initialized")
    return _STORE


def _bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def require_participant(
    authorization: Optional[str] = Header(None),
    x_participant_id: Optional[str] = Header(None, alias="X-Participant-Id"),
) -> dict:
    """
    Identity from Bearer token only.
    X-Participant-Id is ignored for authorization (compat header, not authority).
    """
    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(401, "Missing or invalid Authorization: Bearer <access_token>")
    part = store().resolve_token(token)
    if not part:
        raise HTTPException(401, "Invalid access token")
    # Intentionally ignore x_participant_id even if it disagrees
    return part


class RegisterBody(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=80)
    tournament_id: str = "tour-mvp-1"
    # Client-supplied id is accepted in schema for compatibility but IGNORED
    participant_id: Optional[str] = None


class Assessment(BaseModel):
    asset_id: str
    label: str


class SubmissionBody(BaseModel):
    case_id: str
    priority_assets: List[str] = []
    target_assessments: List[Assessment] = []
    migration_sequence: List[str] = []
    justification_tags: List[str] = []
    score: Optional[Any] = None
    evaluation: Optional[Any] = None
    expected_sequence: Optional[Any] = None
    expected_severity: Optional[Any] = None


@router.get("/tournaments")
def list_tournaments():
    return {"tournaments": store().list_tournaments()}


@router.get("/tournaments/{tid}")
def get_tournament(tid: str):
    t = store().get_tournament(tid)
    if not t:
        raise HTTPException(404, "Tournament not found")
    return t


@router.get("/rounds/{round_id}/cases")
def round_cases(round_id: str):
    if round_id != "round-mvp-1":
        raise HTTPException(404, "Round not found")
    pub = store().get_public_case(PUBLIC_CASE["case_id"])
    if not pub:
        raise HTTPException(404, "Case not found")
    return {"round_id": round_id, "cases": [pub]}


@router.get("/cases/{case_id}")
def get_case_public(case_id: str):
    pub = store().get_public_case(case_id)
    if not pub:
        raise HTTPException(404, "Case not found")
    return pub


@router.post("/participants")
def register_participant(body: RegisterBody):
    # Ignore body.participant_id completely
    p = store().register_participant(body.tournament_id, body.display_name.strip())
    return {"participant": p}


@router.post("/submissions")
def create_submission(
    body: SubmissionBody,
    authorization: Optional[str] = Header(None),
    x_participant_id: Optional[str] = Header(None, alias="X-Participant-Id"),
):
    part = require_participant(authorization, x_participant_id)
    pid = part["id"]
    st = store()
    priv = st.get_private_case(body.case_id)
    if not priv:
        raise HTTPException(404, "Case not found")
    if st.existing_submission(pid, body.case_id):
        raise HTTPException(409, "ONE_SUBMISSION_ONLY — submission already locked for this case")

    payload = {
        "case_id": body.case_id,
        "priority_assets": body.priority_assets,
        "target_assessments": [a.model_dump() for a in body.target_assessments],
        "migration_sequence": body.migration_sequence,
        "justification_tags": body.justification_tags,
    }
    payload_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    freeze = priv.get("_freeze") or freeze_meta()
    evaluation = evaluate(priv, payload)
    try:
        result = st.save_submission_eval(
            pid,
            body.case_id,
            priv.get("case_version") or PUBLIC_CASE["case_version"],
            payload,
            payload_hash,
            evaluation,
            freeze,
        )
    except ValueError as e:
        if str(e) == "ONE_SUBMISSION_ONLY":
            raise HTTPException(409, "ONE_SUBMISSION_ONLY")
        raise
    return {
        "ok": True,
        "submission_id": result["submission_id"],
        "score": result["score"],
        "breakdown": result["breakdown"],
        "evaluator_version": evaluation["evaluator_version"],
        "note": "Score computed server-side. Client score fields ignored.",
    }


@router.get("/submissions/{submission_id}")
def get_submission(
    submission_id: str,
    authorization: Optional[str] = Header(None),
    x_participant_id: Optional[str] = Header(None, alias="X-Participant-Id"),
):
    part = require_participant(authorization, x_participant_id)
    sub = store().get_submission(submission_id, requester_pid=part["id"])
    if not sub:
        raise HTTPException(404, "Submission not found or not owned by participant")
    return sub


@router.get("/leaderboards/{round_id}")
def leaderboard(round_id: str):
    return {"round_id": round_id, "leaderboard": store().leaderboard(round_id)}


@router.get("/audit/{submission_id}")
def audit(
    submission_id: str,
    authorization: Optional[str] = Header(None),
    x_participant_id: Optional[str] = Header(None, alias="X-Participant-Id"),
):
    part = require_participant(authorization, x_participant_id)
    a = store().get_audit_for_submission(submission_id, requester_pid=part["id"])
    if not a:
        raise HTTPException(404, "Audit not found or not owned by participant")
    return a
