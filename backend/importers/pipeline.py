from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

REQUIRED = [
    "asset_id",
    "name",
    "algorithm",
    "key_size",
    "protocol",
    "criticality",
    "internet_exposed",
    "data_lifetime_years",
    "dependencies",
]
OPTIONAL = ["migration_status", "aliases"]
VALID_CRIT = {"low", "medium", "high", "critical"}

HEADER_ALIASES = {
    "asset_id": {"asset_id", "asset", "id", "assetid", "system_id", "service_id"},
    "name": {"name", "asset_name", "system", "service", "system_name", "service_name", "title"},
    "algorithm": {"algorithm", "algo", "cryptography", "crypto", "cipher", "encryption"},
    "key_size": {"key_size", "keysize", "bits", "key_bits", "key length", "key_length"},
    "protocol": {"protocol", "proto", "transport"},
    "criticality": {"criticality", "critical", "importance", "priority", "business_criticality"},
    "internet_exposed": {
        "internet_exposed",
        "exposed",
        "internet",
        "external",
        "internet_facing",
        "public",
    },
    "data_lifetime_years": {
        "data_lifetime_years",
        "lifetime",
        "data_lifetime",
        "retention_years",
        "lifetime_years",
    },
    "dependencies": {"dependencies", "depends_on", "deps", "depends", "prerequisites"},
    "migration_status": {"migration_status", "status", "migration"},
    "aliases": {"aliases", "alias"},
}


@dataclass
class ParseResult:
    ok: bool
    format: str
    filename: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    valid_count: int = 0
    attention_count: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sheets: List[str] = field(default_factory=list)
    needs_sheet_choice: bool = False
    needs_review: bool = False
    csv_text: str = ""
    message: str = ""


def _ext(name: str) -> str:
    return Path(name or "").suffix.lower().lstrip(".")


def _normalize_header(h: str) -> Optional[str]:
    key = re.sub(r"[^a-z0-9]+", "_", (h or "").strip().lower()).strip("_")
    for canon, aliases in HEADER_ALIASES.items():
        if key in aliases or key == canon:
            return canon
    return None


def _score_headers(headers: List[str]) -> int:
    mapped = {_normalize_header(h) for h in headers}
    score = 0
    for req in ("asset_id", "name", "algorithm", "criticality"):
        if req in mapped:
            score += 3
    for opt in ("dependencies", "key_size", "protocol", "internet_exposed"):
        if opt in mapped:
            score += 1
    return score


def _map_row(raw: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {k: "" for k in REQUIRED + OPTIONAL}
    for k, v in raw.items():
        canon = _normalize_header(str(k))
        if not canon:
            continue
        if v is None:
            val = ""
        else:
            val = str(v).strip()
        out[canon] = val
    # defaults only for non-semantic structural empties — never invent criticality/algorithm
    if not out.get("protocol"):
        out["protocol"] = "unknown"
    if not out.get("key_size"):
        out["key_size"] = "0"
    if not out.get("internet_exposed"):
        out["internet_exposed"] = "false"
    if not out.get("data_lifetime_years"):
        out["data_lifetime_years"] = "0"
    if not out.get("migration_status"):
        out["migration_status"] = "not_started"
    if not out.get("name") and out.get("asset_id"):
        out["name"] = out["asset_id"]
    if not out.get("asset_id") and out.get("name"):
        # derive safe id from name
        aid = re.sub(r"[^A-Za-z0-9._@-]+", "-", out["name"]).strip("-")[:64]
        out["asset_id"] = aid or ""
    return out


def _row_issues(row: Dict[str, str]) -> List[str]:
    issues = []
    if not row.get("asset_id"):
        issues.append("missing asset_id")
    if not row.get("name"):
        issues.append("missing name")
    if not row.get("algorithm"):
        issues.append("missing algorithm")
    crit = (row.get("criticality") or "").strip().lower()
    if not crit:
        issues.append("missing criticality")
    elif crit not in VALID_CRIT:
        issues.append(f"invalid criticality '{crit}' (expected low|medium|high|critical)")
    return issues


def _rows_to_csv(rows: List[Dict[str, str]]) -> str:
    buf = io.StringIO()
    cols = REQUIRED + ["migration_status"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in cols})
    return buf.getvalue()


def _from_dataframe_records(records: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    rows = []
    for rec in records:
        # skip fully empty
        if not any(str(v).strip() for v in rec.values() if v is not None):
            continue
        rows.append(_map_row(rec))
    return rows


def parse_csv_bytes(data: bytes, filename: str) -> ParseResult:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return ParseResult(False, "csv", filename, errors=[f"CSV must be UTF-8: {exc}"], message="IMPORT FAILED")
    # Let existing Core loader validate; here we only package
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return ParseResult(False, "csv", filename, errors=["No header row"], message="NO INVENTORY DATA FOUND")
    rows = _from_dataframe_records(list(reader))
    return _finalize(rows, "csv", filename, csv_passthrough=text)


def parse_excel_bytes(data: bytes, filename: str, sheet: Optional[str] = None) -> ParseResult:
    try:
        import pandas as pd
    except ImportError:
        return ParseResult(False, "xlsx", filename, errors=["pandas not available"], message="IMPORT FAILED")
    try:
        xl = pd.ExcelFile(io.BytesIO(data))
    except Exception as exc:
        return ParseResult(False, "xlsx", filename, errors=[f"Could not read Excel: {exc}"], message="IMPORT FAILED")
    sheets = list(xl.sheet_names)
    if not sheets:
        return ParseResult(False, "xlsx", filename, errors=["Workbook has no sheets"], message="NO INVENTORY DATA FOUND")

    candidates: List[Tuple[str, int, List[Dict[str, str]]]] = []
    for name in sheets:
        try:
            df = xl.parse(name)
        except Exception:
            continue
        if df is None or df.empty:
            continue
        df = df.dropna(how="all")
        headers = [str(c) for c in df.columns]
        score = _score_headers(headers)
        if score < 3:
            continue
        records = df.fillna("").to_dict(orient="records")
        rows = _from_dataframe_records(records)
        if rows:
            candidates.append((name, score, rows))

    if sheet:
        chosen = [c for c in candidates if c[0] == sheet]
        if not chosen:
            # force parse named sheet even if low score
            try:
                df = xl.parse(sheet).dropna(how="all")
                rows = _from_dataframe_records(df.fillna("").to_dict(orient="records"))
                return _finalize(rows, "xlsx", filename, sheets=sheets)
            except Exception as exc:
                return ParseResult(
                    False, "xlsx", filename, sheets=sheets, errors=[f"Sheet '{sheet}' unreadable: {exc}"], message="IMPORT FAILED"
                )
        return _finalize(chosen[0][2], "xlsx", filename, sheets=sheets)

    if not candidates:
        return ParseResult(
            False,
            "xlsx",
            filename,
            sheets=sheets,
            errors=["Could not identify a valid inventory table in any sheet"],
            message="NO INVENTORY DATA FOUND",
        )

    candidates.sort(key=lambda x: (-x[1], x[0]))
    top_score = candidates[0][1]
    top = [c for c in candidates if c[1] == top_score]
    if len(top) > 1 and not sheet:
        return ParseResult(
            ok=False,
            format="xlsx",
            filename=filename,
            sheets=[c[0] for c in top],
            needs_sheet_choice=True,
            message="MULTIPLE DATA TABLES FOUND",
            errors=["Please choose the sheet containing your cryptographic inventory."],
        )
    return _finalize(candidates[0][2], "xlsx", filename, sheets=sheets)


def parse_docx_bytes(data: bytes, filename: str) -> ParseResult:
    try:
        from docx import Document
    except ImportError:
        return ParseResult(False, "docx", filename, errors=["python-docx not installed"], message="IMPORT FAILED")
    try:
        doc = Document(io.BytesIO(data))
    except Exception as exc:
        return ParseResult(False, "docx", filename, errors=[f"Could not read Word document: {exc}"], message="IMPORT FAILED")

    best_rows: List[Dict[str, str]] = []
    best_score = -1
    for table in doc.tables:
        grid = []
        for row in table.rows:
            grid.append([cell.text.strip() for cell in row.cells])
        if len(grid) < 2:
            continue
        headers = grid[0]
        score = _score_headers(headers)
        if score < 3:
            continue
        records = []
        for line in grid[1:]:
            rec = {}
            for i, h in enumerate(headers):
                rec[h] = line[i] if i < len(line) else ""
            records.append(rec)
        rows = _from_dataframe_records(records)
        if score > best_score and rows:
            best_score = score
            best_rows = rows
    if not best_rows:
        return ParseResult(
            False,
            "docx",
            filename,
            errors=["No inventory table found in Word document"],
            message="NO INVENTORY DATA FOUND",
        )
    return _finalize(best_rows, "docx", filename)


def parse_pdf_bytes(data: bytes, filename: str) -> ParseResult:
    text = ""
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        parts = []
        for page in reader.pages:
            parts.append(page.extract_text() or "")
        text = "\n".join(parts)
    except Exception as exc:
        return ParseResult(
            False,
            "pdf",
            filename,
            errors=[f"DOCUMENT COULD NOT BE READ RELIABLY: {exc}"],
            message="DOCUMENT COULD NOT BE READ RELIABLY",
        )
    if not text.strip():
        return ParseResult(
            False,
            "pdf",
            filename,
            errors=["PDF has no extractable text (scanned/image-only not supported without OCR)"],
            message="DOCUMENT COULD NOT BE READ RELIABLY",
        )
    from importers.document_parse import parse_document_inventory
    return parse_document_inventory(text, filename, fmt="pdf")


def parse_text_inventory(text: str, filename: str, fmt: str = "txt") -> ParseResult:
    from importers.document_parse import parse_document_inventory
    return parse_document_inventory(text, filename, fmt=fmt)

def _finalize(
    rows: List[Dict[str, str]],
    fmt: str,
    filename: str,
    sheets: Optional[List[str]] = None,
    csv_passthrough: Optional[str] = None,
) -> ParseResult:
    if not rows:
        return ParseResult(
            False,
            fmt,
            filename,
            sheets=sheets or [],
            errors=["No inventory rows detected"],
            message="NO INVENTORY DATA FOUND",
        )
    annotated = []
    valid = 0
    attention = 0
    for r in rows:
        issues = _row_issues(r)
        item = dict(r)
        item["_issues"] = issues
        item["_status"] = "VALID" if not issues else "ACTION REQUIRED"
        if issues:
            attention += 1
        else:
            valid += 1
        annotated.append(item)
    needs_review = attention > 0 or fmt != "csv"
    # Build csv only from rows that may still fail Core validation — include all for transparency
    csv_text = csv_passthrough if csv_passthrough is not None else _rows_to_csv(rows)
    ok = valid > 0 and attention == 0
    return ParseResult(
        ok=ok,
        format=fmt,
        filename=filename,
        rows=annotated,
        valid_count=valid,
        attention_count=attention,
        sheets=sheets or [],
        needs_review=needs_review,
        csv_text=csv_text,
        message="OK" if ok else ("ACTION REQUIRED" if attention else "IMPORT FAILED"),
    )


def parse_inventory_file(
    data: bytes,
    filename: str,
    sheet: Optional[str] = None,
) -> ParseResult:
    if len(data) > MAX_UPLOAD_BYTES:
        return ParseResult(
            False,
            _ext(filename) or "unknown",
            filename,
            errors=[f"File exceeds maximum size of {MAX_UPLOAD_BYTES // (1024*1024)} MB"],
            message="IMPORT FAILED",
        )
    ext = _ext(filename)
    if ext == "csv":
        return parse_csv_bytes(data, filename)
    if ext in ("xlsx", "xls"):
        return parse_excel_bytes(data, filename, sheet=sheet)
    if ext == "docx":
        return parse_docx_bytes(data, filename)
    if ext == "pdf":
        return parse_pdf_bytes(data, filename)
    if ext == "txt":
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
        return parse_text_inventory(text, filename, fmt="txt")
    return ParseResult(
        False,
        ext or "unknown",
        filename,
        errors=["UNSUPPORTED FILE TYPE"],
        message="UNSUPPORTED FILE TYPE",
        warnings=["Supported: csv · xlsx · xls · docx · pdf · txt"],
    )
