"""Deterministic Tournament evaluator (score-v1). No FastAPI, no AI, no I/O."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

WEIGHTS = {
    "C1": 0.20,
    "C2": 0.10,
    "C3": 0.25,
    "C4": 0.25,
    "C5": 0.10,
    "C6": 0.10,
}
EVALUATOR_VERSION = "score-v1"


def _norm_ids(xs: Optional[Sequence[str]]) -> List[str]:
    if not xs:
        return []
    out: List[str] = []
    for x in xs:
        if x is None:
            continue
        s = str(x).strip()
        if s:
            out.append(s)
    return out


def priority_recall(priority: Sequence[str], must_set: Set[str]) -> float:
    if not must_set:
        return 0.0
    p = set(_norm_ids(priority))
    return len(p & must_set) / float(len(must_set))


def priority_precision(priority: Sequence[str], allowed: Set[str]) -> float:
    p = _norm_ids(priority)
    if not p:
        return 0.0
    return len(set(p) & allowed) / float(len(p))


def severity_classification(
    assessments: Sequence[Dict[str, Any]],
    expected: Dict[str, str],
) -> float:
    """Mean exact match over required expected keys."""
    if not expected:
        return 0.0
    got = {}
    for a in assessments or []:
        aid = str(a.get("asset_id") or a.get("id") or "").strip()
        lab = str(a.get("label") or a.get("expected_severity") or a.get("severity") or "").strip().upper()
        if aid and lab:
            got[aid] = lab
    hits = 0
    for aid, exp in expected.items():
        if got.get(aid) == str(exp).upper():
            hits += 1
    return hits / float(len(expected))


def sequence_validity(
    sequence: Sequence[str],
    edges: Set[Tuple[str, str]],
    known: Set[str],
    missing_forbidden: Set[str],
) -> float:
    """
    1.0 topo-valid on known graph, no unknown/missing as executable.
    0.5 partial: some valid ordering but issues.
    0.0 payment-first style / hard breaks handled by caller too.
    """
    seq = _norm_ids(sequence)
    if not seq:
        return 0.0
    if any(x in missing_forbidden for x in seq):
        return 0.0
    if any(x not in known for x in seq):
        # unknown ids: no full credit
        known_only = [x for x in seq if x in known]
        if not known_only:
            return 0.0
        seq = known_only
        partial = True
    else:
        partial = False

    pos = {a: i for i, a in enumerate(seq)}
    violations = 0
    checked = 0
    for a, b in edges:
        # edge: a must precede b if both in sequence
        if a in pos and b in pos:
            checked += 1
            if pos[a] > pos[b]:
                violations += 1
    if violations:
        return 0.0
    if partial:
        return 0.5
    return 1.0


def sequence_goal(
    sequence: Sequence[str],
    target: str,
    ancestors: List[str],
) -> float:
    seq = _norm_ids(sequence)
    if not seq:
        return 0.0
    if seq[0] == target:
        return 0.0
    if target not in seq:
        # prefix of ancestors only
        if all(a in seq for a in ancestors) and seq == [x for x in ancestors if x in seq]:
            return 0.4
        return 0.0
    # target present: all ancestors before target
    ti = seq.index(target)
    before = seq[:ti]
    if all(a in before for a in ancestors):
        # order among ancestors
        idxs = [before.index(a) for a in ancestors]
        if idxs == sorted(idxs):
            return 1.0
        return 0.6
    return 0.2


def constraint_compliance(
    priority: Sequence[str],
    sequence: Sequence[str],
    known: Set[str],
    no_work: Set[str],
    missing_forbidden: Set[str],
) -> float:
    p = _norm_ids(priority)
    s = _norm_ids(sequence)
    # Empty submission is non-compliant with the mission
    if not p and not s:
        return 0.0
    score = 1.0
    # unknown in priority or sequence
    for x in p + s:
        if x not in known and x not in missing_forbidden:
            score -= 0.15
        if x in missing_forbidden:
            score -= 0.25
        if x in no_work and x in p:
            score -= 0.15
    # duplicates in sequence
    if len(s) != len(set(s)):
        score -= 0.15
    if len(p) != len(set(p)):
        score -= 0.1
    return max(0.0, min(1.0, score))


def evaluate(case_private: Dict[str, Any], submission: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pure evaluation.
    case_private keys used:
      must_attention, allowed_priority, expected_severity,
      edges (list of [from,to]), known_assets, missing_nodes,
      no_work_assets, goal_target, goal_ancestors
    """
    priority = submission.get("priority_assets") or []
    assessments = submission.get("target_assessments") or []
    sequence = submission.get("migration_sequence") or []

    must = set(case_private["must_attention"])
    allowed = set(case_private["allowed_priority"])
    expected_sev = dict(case_private["expected_severity"])
    edges = {tuple(e) for e in case_private["edges"]}
    known = set(case_private["known_assets"])
    missing = set(case_private.get("missing_nodes") or [])
    no_work = set(case_private.get("no_work_assets") or [])
    target = case_private["goal_target"]
    ancestors = list(case_private["goal_ancestors"])

    c1 = priority_recall(priority, must)
    c2 = priority_precision(priority, allowed)
    c3 = severity_classification(assessments, expected_sev)
    c4 = sequence_validity(sequence, edges, known, missing)
    c5 = sequence_goal(sequence, target, ancestors)
    c6 = constraint_compliance(priority, sequence, known, no_work, missing)

    # hard: payment first
    seq = _norm_ids(sequence)
    if seq and seq[0] == target:
        c4 = 0.0
        c5 = 0.0

    breakdown = {
        "C1": round(c1, 4),
        "C2": round(c2, 4),
        "C3": round(c3, 4),
        "C4": round(c4, 4),
        "C5": round(c5, 4),
        "C6": round(c6, 4),
    }
    total = 100.0 * sum(WEIGHTS[k] * breakdown[k] for k in WEIGHTS)
    total = round(min(100.0, max(0.0, total)), 2)
    return {
        "evaluator_version": EVALUATOR_VERSION,
        "score": total,
        "breakdown": breakdown,
        "weights": dict(WEIGHTS),
    }
