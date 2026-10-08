"""SQLite persistence for Tournament MVP."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
import secrets
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_lock = threading.Lock()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TournamentStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with _lock, self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS tournaments (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  status TEXT NOT NULL,
                  core_version TEXT,
                  policy_set_id TEXT,
                  policy_set_version TEXT,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rounds (
                  id TEXT PRIMARY KEY,
                  tournament_id TEXT NOT NULL,
                  name TEXT NOT NULL,
                  status TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                  id TEXT PRIMARY KEY,
                  case_version TEXT NOT NULL,
                  public_json TEXT NOT NULL,
                  private_json TEXT NOT NULL,
                  freeze_json TEXT NOT NULL,
                  UNIQUE(id, case_version)
                );
                CREATE TABLE IF NOT EXISTS round_cases (
                  round_id TEXT NOT NULL,
                  case_id TEXT NOT NULL,
                  case_version TEXT NOT NULL,
                  PRIMARY KEY (round_id, case_id)
                );
                CREATE TABLE IF NOT EXISTS participants (
                  id TEXT PRIMARY KEY,
                  tournament_id TEXT NOT NULL,
                  display_name TEXT NOT NULL,
                  token_hash TEXT,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS submissions (
                  id TEXT PRIMARY KEY,
                  participant_id TEXT NOT NULL,
                  case_id TEXT NOT NULL,
                  case_version TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  payload_hash TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  UNIQUE(participant_id, case_id)
                );
                CREATE TABLE IF NOT EXISTS evaluations (
                  id TEXT PRIMARY KEY,
                  submission_id TEXT NOT NULL UNIQUE,
                  score REAL NOT NULL,
                  breakdown_json TEXT NOT NULL,
                  evaluator_version TEXT NOT NULL,
                  freeze_json TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                  id TEXT PRIMARY KEY,
                  type TEXT NOT NULL,
                  refs_json TEXT NOT NULL,
                  body_json TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                """
            )
            cols = [r[1] for r in c.execute("PRAGMA table_info(participants)").fetchall()]
            if "token_hash" not in cols:
                c.execute("ALTER TABLE participants ADD COLUMN token_hash TEXT")

    def seed_mvp(self, public: dict, private: dict, freeze: dict) -> Dict[str, str]:
        """Idempotent seed: one tournament, one round, case v0."""
        with _lock, self._conn() as c:
            row = c.execute("SELECT id FROM tournaments WHERE id=?", ("tour-mvp-1",)).fetchone()
            if not row:
                c.execute(
                    "INSERT INTO tournaments VALUES (?,?,?,?,?,?,?)",
                    (
                        "tour-mvp-1",
                        "CryptoRisk Decision Quality MVP",
                        "open",
                        freeze.get("core_version"),
                        freeze.get("policy_set_id"),
                        freeze.get("policy_set_version"),
                        _utc(),
                    ),
                )
                c.execute(
                    "INSERT INTO rounds VALUES (?,?,?,?,?)",
                    ("round-mvp-1", "tour-mvp-1", "Qualifier — Case V0", "open", _utc()),
                )
            c.execute(
                "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?)",
                (
                    public["case_id"],
                    public["case_version"],
                    json.dumps(public),
                    json.dumps(private),
                    json.dumps(freeze),
                ),
            )
            c.execute(
                "INSERT OR REPLACE INTO round_cases VALUES (?,?,?)",
                ("round-mvp-1", public["case_id"], public["case_version"]),
            )
        return {"tournament_id": "tour-mvp-1", "round_id": "round-mvp-1", "case_id": public["case_id"]}

    def list_tournaments(self) -> List[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM tournaments").fetchall()
            return [dict(r) for r in rows]

    def get_tournament(self, tid: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT * FROM tournaments WHERE id=?", (tid,)).fetchone()
            return dict(r) if r else None

    def get_public_case(self, case_id: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT public_json, freeze_json, case_version FROM cases WHERE id=?", (case_id,)).fetchone()
            if not r:
                return None
            pub = json.loads(r["public_json"])
            pub["freeze_meta"] = {
                k: json.loads(r["freeze_json"]).get(k)
                for k in (
                    "case_id",
                    "case_version",
                    "core_version",
                    "policy_set_id",
                    "policy_set_version",
                    "public_hash",
                    "evaluator_version",
                )
            }
            # never attach private
            return pub

    def get_private_case(self, case_id: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute("SELECT private_json, freeze_json FROM cases WHERE id=?", (case_id,)).fetchone()
            if not r:
                return None
            priv = json.loads(r["private_json"])
            priv["_freeze"] = json.loads(r["freeze_json"])
            return priv

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def register_participant(self, tournament_id: str, display_name: str) -> dict:
        """Server-side ID + one-time access_token (store only hash). Client participant_id ignored."""
        pid = "p-" + secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        th = self._hash_token(token)
        with _lock, self._conn() as c:
            c.execute(
                "INSERT INTO participants (id, tournament_id, display_name, token_hash, created_at) VALUES (?,?,?,?,?)",
                (pid, tournament_id, display_name, th, _utc()),
            )
        return {
            "participant_id": pid,
            "display_name": display_name,
            "tournament_id": tournament_id,
            "access_token": token,  # returned once only
        }

    def resolve_token(self, token: str) -> Optional[dict]:
        if not token or not str(token).strip():
            return None
        th = self._hash_token(str(token).strip())
        with self._conn() as c:
            r = c.execute(
                "SELECT id, tournament_id, display_name, created_at FROM participants WHERE token_hash=?",
                (th,),
            ).fetchone()
            return dict(r) if r else None

    def get_participant(self, pid: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute(
                "SELECT id, tournament_id, display_name, created_at FROM participants WHERE id=?",
                (pid,),
            ).fetchone()
            return dict(r) if r else None

    def existing_submission(self, participant_id: str, case_id: str) -> Optional[dict]:
        with self._conn() as c:
            r = c.execute(
                "SELECT * FROM submissions WHERE participant_id=? AND case_id=?",
                (participant_id, case_id),
            ).fetchone()
            return dict(r) if r else None

    def save_submission_eval(
        self,
        participant_id: str,
        case_id: str,
        case_version: str,
        payload: dict,
        payload_hash: str,
        evaluation: dict,
        freeze: dict,
    ) -> dict:
        sid = f"sub-{uuid.uuid4().hex[:12]}"
        eid = f"ev-{uuid.uuid4().hex[:12]}"
        now = _utc()
        with _lock, self._conn() as c:
            try:
                c.execute(
                    "INSERT INTO submissions VALUES (?,?,?,?,?,?,?)",
                    (sid, participant_id, case_id, case_version, json.dumps(payload), payload_hash, now),
                )
            except sqlite3.IntegrityError:
                raise ValueError("ONE_SUBMISSION_ONLY")
            c.execute(
                "INSERT INTO evaluations VALUES (?,?,?,?,?,?,?)",
                (
                    eid,
                    sid,
                    float(evaluation["score"]),
                    json.dumps(evaluation["breakdown"]),
                    evaluation["evaluator_version"],
                    json.dumps(freeze),
                    now,
                ),
            )
            audit = {
                "participant_id": participant_id,
                "case_id": case_id,
                "case_version": case_version,
                "payload_hash": payload_hash,
                "score": evaluation["score"],
                "breakdown": evaluation["breakdown"],
                "core_version": freeze.get("core_version"),
                "policy_set_id": freeze.get("policy_set_id"),
                "policy_set_version": freeze.get("policy_set_version"),
                "evaluator_version": evaluation["evaluator_version"],
                "public_hash": freeze.get("public_hash"),
            }
            c.execute(
                "INSERT INTO audit_events VALUES (?,?,?,?,?)",
                (f"aud-{uuid.uuid4().hex[:12]}", "SUBMISSION_EVALUATED", json.dumps({"submission_id": sid}), json.dumps(audit), now),
            )
        return {"submission_id": sid, "evaluation_id": eid, "score": evaluation["score"], "breakdown": evaluation["breakdown"], "audit": audit}

    def get_submission(self, submission_id: str, requester_pid: Optional[str] = None) -> Optional[dict]:
        with self._conn() as c:
            s = c.execute("SELECT * FROM submissions WHERE id=?", (submission_id,)).fetchone()
            if not s:
                return None
            if requester_pid and s["participant_id"] != requester_pid:
                return None  # isolation
            e = c.execute("SELECT * FROM evaluations WHERE submission_id=?", (submission_id,)).fetchone()
            out = dict(s)
            out["payload"] = json.loads(s["payload_json"])
            if e:
                out["evaluation"] = {
                    "score": e["score"],
                    "breakdown": json.loads(e["breakdown_json"]),
                    "evaluator_version": e["evaluator_version"],
                }
            return out

    def leaderboard(self, round_id: str) -> List[dict]:
        with self._conn() as c:
            # MVP: single case per round; join participants via submissions
            rows = c.execute(
                """
                SELECT p.display_name AS display_name, p.id AS participant_id,
                       e.score AS score, s.id AS submission_id, s.created_at AS created_at
                FROM submissions s
                JOIN evaluations e ON e.submission_id = s.id
                JOIN participants p ON p.id = s.participant_id
                JOIN round_cases rc ON rc.case_id = s.case_id
                WHERE rc.round_id = ?
                ORDER BY e.score DESC, s.created_at ASC
                """,
                (round_id,),
            ).fetchall()
            board = []
            for i, r in enumerate(rows, 1):
                board.append(
                    {
                        "rank": i,
                        "participant_id": r["participant_id"],
                        "display_name": r["display_name"],
                        "score": r["score"],
                        "submission_id": r["submission_id"],
                    }
                )
            return board

    def get_audit_for_submission(self, submission_id: str, requester_pid: Optional[str] = None) -> Optional[dict]:
        sub = self.get_submission(submission_id, requester_pid)
        if not sub:
            return None
        with self._conn() as c:
            r = c.execute(
                "SELECT * FROM audit_events WHERE type=? AND refs_json LIKE ? ORDER BY created_at DESC LIMIT 1",
                ("SUBMISSION_EVALUATED", f"%{submission_id}%"),
            ).fetchone()
            if not r:
                return {"submission_id": submission_id, "evaluation": sub.get("evaluation")}
            body = json.loads(r["body_json"])
            return body
