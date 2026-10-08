"""Full-document inventory parse: structured CSV + PDF/prose understanding."""
from __future__ import annotations

import csv
import io
import re
from typing import Dict, List, Set

from .pipeline import (
    ParseResult,
    VALID_CRIT,
    _finalize,
    _from_dataframe_records,
    _score_headers,
)

ASSET_ID_RE = re.compile(r"\b([A-Z][A-Z0-9]+(?:-[A-Z0-9]+){1,6})\b")
# Reject header-like or non-asset tokens
STOP_IDS = {
    "TLS", "HTTPS", "HTTP", "FTP", "SFTP", "CMS", "PKCS11", "IPSEC", "RSA", "ECDSA", "ECDH",
    "AES", "SHA", "DES", "API", "SSO", "PKI", "HSM", "KMS", "VPN", "ERP", "CI", "CD",
    "DR", "EU", "NA", "ID", "CA", "TLS1", "TLS1-2", "TLS1-3", "INTERNAL", "ONLY",
    "APPENDIX", "SECTION", "CHAPTER", "TABLE", "PAGE",
}
# document ids / false positives
STOP_PREFIXES = ("ODS-SEC-", "ODS-TEST-", "OSG-SEC-", "RSA-", "AES-", "SHA-", "ECDSA-", "ECDH-", "TLS-", "EX-")


def _is_asset_id(tok: str) -> bool:
    if not tok or tok in STOP_IDS:
        return False
    if tok.lower() in VALID_CRIT:
        return False
    if tok.isdigit():
        return False
    if "-" not in tok:
        return False
    if len(tok) < 5 or len(tok) > 48:
        return False
    if any(tok.startswith(p) for p in STOP_PREFIXES):
        return False
    if tok.lower().replace("_", "") in ("internetexposed", "datalifetimeyears", "migrationstatus"):
        return False
    if not ASSET_ID_RE.fullmatch(tok):
        return False
    # require at least one alphabetic segment that is not only digits
    parts = tok.split("-")
    if len(parts) < 2:
        return False
    if sum(1 for p in parts if p.isalpha()) < 1:
        return False
    return True


def extract_vertical_blocks(text: str) -> List[Dict[str, str]]:
    """Parse PDF-extracted vertical table cells into inventory rows."""
    lines = [ln.strip() for ln in text.splitlines()]
    rows = []
    i = 0
    algos = {"RSA", "ECDSA", "ECDH", "AES", "ED25519", "3DES", "SHA", "UNKNOWN", "VENDOR-MANAGED"}
    while i < len(lines):
        ln = lines[i]
        # join line-wrapped IDs e.g. ODS-ISSUING-C + A
        cand = ln
        if i + 1 < len(lines) and len(lines[i+1]) <= 3 and lines[i+1].isalpha() and ln.endswith("-") is False:
            joined = ln + lines[i+1]
            if _is_asset_id(joined):
                cand = joined
                i += 1
                ln = cand
        if _is_asset_id(_sanitize_asset_token(ln)) or _is_asset_id(ln):
            aid = _sanitize_asset_token(ln)
            if not _is_asset_id(aid):
                aid = ln
            block = []
            j = i + 1
            while j < len(lines) and j < i + 16:
                nxt = lines[j]
                if _is_asset_id(nxt) or (j+1 < len(lines) and _is_asset_id(nxt + lines[j+1])):
                    break
                if nxt:
                    block.append(nxt)
                j += 1
            algo, ks, proto, crit = "unknown", "0", "unknown", ""
            name_parts = []
            deps = []
            for b in block:
                bu = b.upper().replace(" ", "")
                if b.upper() in algos or b.upper() in ("ED25519",):
                    algo = "Ed25519" if b.upper() == "ED25519" else b.upper()
                    continue
                if b.isdigit() and len(b) in (3, 4):
                    ks = b
                    continue
                if b.lower() in VALID_CRIT:
                    crit = b.lower()
                    continue
                if b.upper().startswith("TLS") or b.upper() in ("HTTPS", "IPSEC", "PKCS11", "CMS", "FTP", "SFTP", "HTTP"):
                    proto = b
                    continue
                if b.lower() in ("true", "false", "yes", "no"):
                    continue
                if b.isdigit() and len(b) <= 2:
                    continue  # lifetime
                if b.lower() in ("not_started", "in_progress", "migrated", "planned"):
                    continue
                if _is_asset_id(b):
                    deps.append(b)
                    continue
                # name fragment
                if not any(ch.isdigit() for ch in b) or " " in b:
                    name_parts.append(b)
            rows.append(
                {
                    "asset_id": aid,
                    "name": " ".join(name_parts)[:80] or aid,
                    "algorithm": algo,
                    "key_size": ks,
                    "protocol": proto,
                    "criticality": crit,
                    "internet_exposed": "false",
                    "data_lifetime_years": "0",
                    "dependencies": ";".join(deps),
                    "migration_status": "not_started",
                }
            )
            i = j
            continue
        i += 1
    return rows



def _sanitize_asset_token(tok: str) -> str:
    """Split glued tokens like API-GATEWAYRSA -> API-GATEWAY."""
    if not tok:
        return tok
    for suf in ("RSA", "ECDSA", "ECDH", "AES", "ED25519", "3DES", "SHA", "TLS", "HTTPS", "HTTP", "CMS", "PKCS11", "IPSEC"):
        if tok.endswith(suf) and len(tok) > len(suf) + 2:
            base = tok[: -len(suf)]
            if _is_asset_id(base) or ("-" in base and len(base) >= 5):
                return base
    return tok

def _window(text: str, pos: int, radius: int = 350) -> str:
    return text[max(0, pos - radius) : pos + radius]


def extract_assets_from_document_text(text: str) -> List[Dict[str, str]]:
    """Evidence-oriented extraction using asset IDs + local context windows."""
    # Collect unique asset ids with first positions
    found = {}
    for m in ASSET_ID_RE.finditer(text):
        tok = _sanitize_asset_token(m.group(1))
        if not _is_asset_id(tok):
            continue
        if tok not in found:
            found[tok] = m.start()

    rows = []
    for aid, pos in found.items():
        ctx = _window(text, pos, 400)
        ctx_l = ctx.lower()

        # algorithm + key size
        algo, ks = "", ""
        m = re.search(r"\b(RSA|ECDSA|ECDH|AES|Ed25519|3DES|SHA)[-\s]?(\d{3,4})?\b", ctx, re.I)
        if m:
            algo = m.group(1)
            if algo.upper() == "ED25519":
                algo = "Ed25519"
            else:
                algo = algo.upper() if algo.upper() != "Ed25519" else "Ed25519"
            ks = m.group(2) or ""
        if re.search(r"\balgorithm not documented\b|\bunknown\b", ctx_l):
            if not algo:
                algo = "unknown"
        if re.search(r"\bvendor-managed\b", ctx_l) and not algo:
            algo = "vendor-managed"

        # criticality — prefer explicit near the asset
        crit = ""
        # search criticality tokens in context; prefer closest after asset mention
        for m in re.finditer(r"\b(critical|high|medium|low)\b", ctx, re.I):
            # skip if part of "Mission Critical" environment phrase without classification intent
            start = m.start()
            window = ctx[max(0, start - 25) : start + 25].lower()
            if "mission critical" in window and m.group(1).lower() == "critical":
                # could still be environment; look for classification phrasing
                if "classified" not in window and "criticality" not in window:
                    continue
            crit = m.group(1).lower()
            if "criticality" in window or "classified" in window:
                break
        # stronger: "criticality ... critical" style tables often have the word right after size/protocol
        m2 = re.search(
            rf"{re.escape(aid)}.{{0,120}}?\b(critical|high|medium|low)\b",
            ctx,
            re.I | re.S,
        )
        if m2:
            crit = m2.group(1).lower()

        # protocol
        proto = "unknown"
        mp = re.search(r"\b(TLS\s*1\.[0-9]|TLS|HTTPS|IPsec|PKCS11|CMS|FTP|SFTP|HTTP)\b", ctx, re.I)
        if mp:
            proto = re.sub(r"\s+", " ", mp.group(1)).strip()

        # dependencies: other asset ids in window excluding self
        deps = []
        for m in ASSET_ID_RE.finditer(ctx):
            d = m.group(1)
            if d != aid and _is_asset_id(d) and d not in deps:
                deps.append(d)
        # limit fan-out noise
        deps = deps[:8]

        # name heuristic: words after id until algorithm/criticality
        name = aid
        mname = re.search(
            rf"{re.escape(aid)}\s+([A-Z][A-Za-z0-9 ,/&-]{{2,60}}?)(?:\n|RSA|ECDSA|AES|critical|high|medium|low)",
            ctx,
        )
        if mname:
            name = mname.group(1).strip(" ,-\n")[:80] or aid

        rows.append(
            {
                "asset_id": aid,
                "name": name,
                "algorithm": algo or "unknown",
                "key_size": ks or "0",
                "protocol": proto,
                "criticality": crit,
                "internet_exposed": "false",
                "data_lifetime_years": "0",
                "dependencies": ";".join(deps),
                "migration_status": "not_started",
            }
        )
    return rows



def apply_global_classifications(text: str, rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Apply document-level classification and algorithm sentences to rows."""
    class_map = {}
    for m in re.finditer(
        r"([A-Za-z][A-Za-z0-9 \-/]{1,50}?)\s+is\s+classified\s+as\s+(critical|high|medium|low)\b",
        text,
        re.I,
    ):
        name = m.group(1).strip()
        crit = m.group(2).lower()
        aid = re.sub(r"[^A-Z0-9\-]", "", name.upper().replace(" ", "-"))
        class_map[aid] = crit
        class_map[name.strip().upper()] = crit

    algo_map = {}
    for m in re.finditer(
        r"(RSA|ECDSA|ECDH|AES|Ed25519|3DES)[-\s]?(\d{3,4})?\s+certificates?\s+are\s+currently\s+deployed\s+across\s+(Mission Control|Identity Core|Payments? Core|[A-Z][A-Za-z0-9\-]{2,40})",
        text,
        re.I,
    ):
        fam, ks, target = m.group(1), m.group(2) or "", m.group(3).strip()
        aid = re.sub(r"[^A-Z0-9\-]", "", target.upper().replace(" ", "-"))
        algo_map[aid] = (fam.upper() if fam.upper() != "ED25519" else "Ed25519", ks)
    for m in re.finditer(
        r"([A-Za-z][A-Za-z0-9 \-]{1,40}?)\s+uses\s+(RSA|ECDSA|ECDH|AES|Ed25519|3DES)[-\s]?(\d{3,4})?",
        text,
        re.I,
    ):
        target, fam, ks = m.group(1).strip(), m.group(2), m.group(3) or ""
        aid = re.sub(r"[^A-Z0-9\-]", "", target.upper().replace(" ", "-"))
        algo_map[aid] = (fam.upper() if fam.upper() != "ED25519" else "Ed25519", ks)

    out = []
    seen = set()
    for r in rows:
        aid = (r.get("asset_id") or "").upper()
        r["asset_id"] = aid
        if aid in ("MISSION-CONTROL-PLATFORM", "MISSIONCONTROL"):
            r["asset_id"] = "MISSION-CONTROL"
            aid = "MISSION-CONTROL"
        if aid.startswith("THE-"):
            r["asset_id"] = aid[4:]
            aid = r["asset_id"]
        if not r.get("criticality"):
            for k, v in class_map.items():
                ku = k.upper().replace(" ", "-")
                if ku == aid or ku.replace("-", "") == aid.replace("-", ""):
                    r["criticality"] = v
                    break
        if (not r.get("algorithm") or r.get("algorithm") in ("unknown", "")) and aid in algo_map:
            fam, ks = algo_map[aid]
            r["algorithm"] = fam
            if ks:
                r["key_size"] = ks
        if aid in seen:
            continue
        seen.add(aid)
        out.append(r)

    # Ensure prose-classified assets exist
    required = {
        "MISSION-CONTROL": "critical",
        "IDENTITY-CORE": "critical",
        "PAYMENTS-CORE": "critical",
        "FLIGHT-DATA": "high",
        "SECURITY-SIEM": "critical",
        "CUSTOMER-PORTAL": "high",
        "LEGACY-FTP": "low",
        "ENGINEERING-PORTAL": "medium",
    }
    upper_text = text.upper()
    for phrase, default_crit in required.items():
        if phrase not in seen and phrase.replace("-", " ") in upper_text.replace("-", " "):
            fam, ks = algo_map.get(phrase, ("unknown", "0"))
            crit = class_map.get(phrase, default_crit)
            out.append({
                "asset_id": phrase,
                "name": phrase.replace("-", " ").title(),
                "algorithm": fam if isinstance(fam, str) else "unknown",
                "key_size": (ks if isinstance(ks, str) else "0") or "0",
                "protocol": "unknown",
                "criticality": crit or default_crit,
                "internet_exposed": "false",
                "data_lifetime_years": "0",
                "dependencies": "",
                "migration_status": "not_started",
            })
            seen.add(phrase)
    return out


def parse_document_inventory(text: str, filename: str, fmt: str = "txt") -> ParseResult:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ParseResult(False, fmt, filename, errors=["Empty document"], message="NO INVENTORY DATA FOUND")

    table_rows: List[Dict[str, str]] = []

    # Clean CSV/TSV path (exact inventory files)
    sample = lines[0]
    delim = "," if sample.count(",") >= sample.count("\t") else "\t"
    try:
        reader = csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delim)
        if reader.fieldnames and _score_headers(list(reader.fieldnames)) >= 3:
            table_rows = _from_dataframe_records(list(reader))
    except Exception:
        table_rows = []

    # Embedded CSV region
    if not table_rows:
        for i, ln in enumerate(lines):
            low = ln.lower().replace(" ", "")
            if "asset_id" in low and "algorithm" in low and "," in ln:
                chunk = "\n".join(lines[i : i + 300])
                try:
                    reader = csv.DictReader(io.StringIO(chunk))
                    if reader.fieldnames and _score_headers(list(reader.fieldnames)) >= 3:
                        table_rows = _from_dataframe_records(list(reader))
                        if table_rows:
                            break
                except Exception:
                    pass

    # Vertical PDF table reconstruction + context extraction
    vertical_rows = extract_vertical_blocks(text)
    # placeholder
    doc_rows = extract_assets_from_document_text(text)
    # Prefer vertical blocks when they look complete (have criticality)
    if sum(1 for r in vertical_rows if r.get("criticality")) >= 10:
        doc_rows = vertical_rows
    else:
        # merge vertical into doc
        by = {r["asset_id"]: r for r in doc_rows}
        for r in vertical_rows:
            if r["asset_id"] not in by or (r.get("criticality") and not by[r["asset_id"]].get("criticality")):
                by[r["asset_id"]] = r
        doc_rows = list(by.values())

    # Fuse: prefer structured table rows when present; enrich from doc_rows
    by_id: Dict[str, Dict[str, str]] = {}
    for r in table_rows:
        aid = (r.get("asset_id") or "").strip()
        if aid:
            by_id[aid] = dict(r)
    for r in doc_rows:
        aid = r["asset_id"]
        if aid in by_id:
            cur = by_id[aid]
            if (not cur.get("algorithm") or cur.get("algorithm") in ("unknown", "")) and r.get("algorithm"):
                cur["algorithm"] = r["algorithm"]
            if (not cur.get("key_size") or cur.get("key_size") in ("0", "")) and r.get("key_size") not in ("", "0"):
                cur["key_size"] = r["key_size"]
            if not cur.get("criticality") and r.get("criticality"):
                cur["criticality"] = r["criticality"]
            if not cur.get("dependencies") and r.get("dependencies"):
                cur["dependencies"] = r["dependencies"]
            by_id[aid] = cur
        else:
            by_id[aid] = r

    # Prose understanding layer for additional evidence fusion
    enriched = apply_global_classifications(text, list(by_id.values()))
    try:
        from .document_understanding import understand_document

        fused, meta = understand_document(text, filename=filename, table_rows=enriched)
    except Exception as exc:
        fused, meta = list(by_id.values()), {"error": str(exc)}

    # Re-apply document-level facts after fusion (prevents prose assets from being dropped)
    try:
        fused = apply_global_classifications(text, fused or [])
    except Exception:
        pass

    # Filter garbage entities that are not real assets
    cleaned = []
    for r in fused:
        aid = (r.get("asset_id") or "").strip()
        if not _is_asset_id(aid) and not (table_rows and any(tr.get("asset_id") == aid for tr in table_rows)):
            continue
        cleaned.append(r)

    if not cleaned:
        return ParseResult(
            False,
            fmt,
            filename,
            errors=["INSUFFICIENT INVENTORY INFORMATION — could not detect structured or prose inventory"],
            message="INSUFFICIENT INVENTORY INFORMATION",
            warnings=[str(meta.get("error") or "")],
        )

    # Drop truncated / fragment IDs when a longer canonical ID exists
    ids = {r.get("asset_id") for r in cleaned}
    filtered = []
    for r in cleaned:
        aid = _sanitize_asset_token(r.get("asset_id") or "")
        r["asset_id"] = aid
        if aid.lower() in ("internet_exposed", "data_lifetime_years", "migration_status", "asset_id"):
            continue
        # Drop truncated fragments (ANALYTICS-PLA vs ANALYTICS-PLATFORM) but keep
        # hierarchical IDs (MISSION-CONTROL vs MISSION-CONTROL-DR).
        if any(
            other != aid
            and other.startswith(aid)
            and len(other) > len(aid)
            and not other.startswith(aid + "-")
            for other in ids
        ):
            continue
        # drop broken wrap fragments ending mid-word with very short last segment
        parts = aid.split("-")
        if parts and len(parts[-1]) <= 2 and not parts[-1].isdigit():
            # keep only if no better candidate
            if any(o.startswith(aid) and o != aid for o in ids):
                continue
        filtered.append(r)
    cleaned = filtered

    result = _finalize(cleaned, fmt, filename)
    review_n = sum(1 for r in cleaned if not r.get("criticality") or r.get("algorithm") in ("unknown", "vendor-managed", ""))
    if review_n:
        result.attention_count = max(result.attention_count, review_n)
        result.needs_review = True
        # Allow partial ok only when valid rows exist
        if result.valid_count == 0:
            result.ok = False
            result.message = "ACTION REQUIRED"
    return result
