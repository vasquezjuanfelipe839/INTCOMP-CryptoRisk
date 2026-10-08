"""Document understanding for inventory extraction.

Deterministic, evidence-based extraction from full documents:
TEXT + TABLES + HEADINGS + SECTIONS + LISTS + PAGE CONTEXT

Does NOT invent risk/priority/decision. Does NOT call Core.
Does NOT use an LLM as authority — pattern/heuristic extraction only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

VALID_CRIT = {"low", "medium", "high", "critical"}

# Algorithm tokens commonly found in enterprise crypto docs
ALGO_PATTERNS = [
    (re.compile(r"\bRSA[-\s]?(\d{3,4})\b", re.I), "RSA", 1),
    (re.compile(r"\bECDSA[-\s]?P?(\d{3})\b", re.I), "ECDSA", 1),
    (re.compile(r"\bECDH[-\s]?P?(\d{3})\b", re.I), "ECDH", 1),
    (re.compile(r"\bEd25519\b", re.I), "Ed25519", None),
    (re.compile(r"\bAES[-\s]?(\d{3})\b", re.I), "AES", 1),
    (re.compile(r"\b3DES\b", re.I), "3DES", None),
    (re.compile(r"\bSHA[-\s]?(\d{3})\b", re.I), "SHA", 1),
    (re.compile(r"\bML-KEM\b", re.I), "ML-KEM", None),
    (re.compile(r"\bML-DSA\b", re.I), "ML-DSA", None),
]

CRIT_PAT = re.compile(
    r"\b(criticality|classified as|classification|priority)\s*[:=]?\s*(critical|high|medium|low)\b",
    re.I,
)
CRIT_PAT2 = re.compile(
    r"\b(critical|high|medium|low)\b(?:\s+(?:criticality|priority|classification))?\b",
    re.I,
)

DEPEND_PATTERNS = [
    re.compile(
        r"(?P<a>[A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40}?)\s+(?:depends on|relies on|requires|uses)\s+(?P<b>[A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40})",
        re.I,
    ),
    re.compile(
        r"(?P<b>[A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40}?)\s+protects\s+(?:the\s+)?(?:private\s+)?keys?\s+(?:used\s+by\s+)?(?P<a>[A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40})",
        re.I,
    ),
    re.compile(
        r"(?P<a>[A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40}?)\s+authenticates\s+(?:users\s+)?through\s+(?P<b>[A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40})",
        re.I,
    ),
]

# Asset-like identifiers: ALLCAPS-WITH-HYPHENS or Title Case multi-word near crypto verbs
ASSET_ID_PAT = re.compile(r"\b([A-Z][A-Z0-9]+(?:-[A-Z0-9]+){1,6})\b")
TITLE_ASSET_PAT = re.compile(
    r"\b((?:Mission Control|Identity Core|API Gateway|Payment(?:s)? Core|Customer Portal|"
    r"Ground Station [A-Z]|Satellite Communications|Global SSO|Mission SSO|"
    r"Root CA|Issuing CA)(?:\s+(?:DR|EU|Platform|System|Service))?)\b",
    re.I,
)


@dataclass
class Evidence:
    field: str
    value: str
    quote: str
    page: Optional[int] = None
    confidence: str = "MEDIUM"  # HIGH | MEDIUM | REVIEW_REQUIRED
    source: str = "text"


@dataclass
class DocEntity:
    canonical_id: str
    display_name: str
    aliases: List[str] = field(default_factory=list)
    algorithm: str = ""
    key_size: str = ""
    protocol: str = ""
    criticality: str = ""
    dependencies: List[str] = field(default_factory=list)
    internet_exposed: str = ""
    data_lifetime_years: str = ""
    migration_status: str = "not_started"
    evidence: List[Evidence] = field(default_factory=list)
    relations: List[Dict[str, str]] = field(default_factory=list)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        conf = ev.confidence
        if ev.field == "algorithm" and ev.value and (not self.algorithm or conf == "HIGH"):
            if conf != "REVIEW_REQUIRED" or not self.algorithm:
                parts = ev.value.replace(" ", "-").split("-")
                if parts[0].upper() in ("RSA", "ECDSA", "ECDH", "AES", "SHA", "3DES", "ED25519", "ML-KEM", "ML-DSA"):
                    self.algorithm = parts[0].upper() if parts[0].upper() != "ED25519" else "Ed25519"
                    if len(parts) > 1 and parts[1].isdigit():
                        self.key_size = parts[1]
                else:
                    self.algorithm = ev.value
        if ev.field == "key_size" and ev.value and (not self.key_size or conf == "HIGH"):
            if conf != "REVIEW_REQUIRED" or not self.key_size:
                self.key_size = ev.value
        if ev.field == "criticality" and ev.value:
            v = ev.value.lower()
            if v in VALID_CRIT:
                if conf == "HIGH" or not self.criticality:
                    self.criticality = v
        if ev.field == "dependency" and ev.value:
            dep = normalize_entity_id(ev.value)
            if dep and dep != self.canonical_id and dep not in self.dependencies:
                self.dependencies.append(dep)
        if ev.field == "protocol" and ev.value and not self.protocol:
            self.protocol = ev.value


@dataclass
class DocumentModel:
    text: str
    pages: List[str] = field(default_factory=list)
    tables: List[List[List[str]]] = field(default_factory=list)
    headings: List[str] = field(default_factory=list)
    filename: str = ""


def normalize_entity_id(name: str) -> str:
    s = (name or "").strip()
    if not s:
        return ""
    # Prefer already-canonical IDs
    if re.match(r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$", s):
        return s
    s = re.sub(r"[^A-Za-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s.upper()[:64]


def _split_pages(text: str) -> List[str]:
    # form feed or explicit page markers
    if "\f" in text:
        return text.split("\f")
    parts = re.split(r"\n\s*Page\s+\d+\s*\n", text, flags=re.I)
    return parts if len(parts) > 1 else [text]


def build_document_model(text: str, filename: str = "", tables: Optional[List] = None) -> DocumentModel:
    pages = _split_pages(text)
    headings = []
    for line in text.splitlines():
        ln = line.strip()
        if not ln:
            continue
        if len(ln) < 80 and (
            ln.isupper()
            or re.match(r"^\d+(\.\d+)*\s+\S+", ln)
            or re.match(r"^(Appendix|Section|Chapter)\b", ln, re.I)
        ):
            headings.append(ln)
    return DocumentModel(text=text, pages=pages, tables=tables or [], headings=headings, filename=filename)


def _extract_algos_from_span(span: str) -> List[Tuple[str, str, str]]:
    """Return list of (algo, key_size, matched_text)."""
    found = []
    for pat, family, group in ALGO_PATTERNS:
        for m in pat.finditer(span):
            ks = m.group(group) if group else ""
            token = m.group(0)
            found.append((family, ks, token))
    return found


def _nearby_asset_names(span: str, window: str = "") -> List[str]:
    names = set()
    for m in ASSET_ID_PAT.finditer(span):
        names.add(m.group(1))
    for m in TITLE_ASSET_PAT.finditer(span):
        names.add(m.group(1).strip())
    if window:
        for m in ASSET_ID_PAT.finditer(window):
            names.add(m.group(1))
        for m in TITLE_ASSET_PAT.finditer(window):
            names.add(m.group(1).strip())
    return list(names)


def extract_entities_from_text(doc: DocumentModel) -> Dict[str, DocEntity]:
    entities: Dict[str, DocEntity] = {}

    def ensure(name: str) -> DocEntity:
        cid = normalize_entity_id(name)
        if not cid:
            raise ValueError("empty")
        if cid not in entities:
            entities[cid] = DocEntity(canonical_id=cid, display_name=name.strip(), aliases=[name.strip()])
        else:
            if name.strip() not in entities[cid].aliases:
                entities[cid].aliases.append(name.strip())
        return entities[cid]

    # Seed from explicit asset IDs anywhere
    for m in ASSET_ID_PAT.finditer(doc.text):
        try:
            ensure(m.group(1))
        except ValueError:
            pass

    # Page-aware sentence scan
    for page_idx, page_text in enumerate(doc.pages or [doc.text]):
        page_no = page_idx + 1
        # sentences roughly
        chunks = re.split(r"(?<=[.!?])\s+|\n+", page_text)
        for sent in chunks:
            s = sent.strip()
            if len(s) < 12:
                continue
            s_lower = s.lower()

            # Algorithm sentences
            algos = _extract_algos_from_span(s)
            if algos:
                assets = _nearby_asset_names(s)
                # patterns like "X uses RSA-3072"
                m_use = re.search(
                    r"([A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40}?)\s+uses\s+(RSA|ECDSA|ECDH|AES|Ed25519|3DES)[-\s]?(\d{3,4})?",
                    s,
                    re.I,
                )
                if m_use:
                    assets = [m_use.group(1)] + assets
                m_dep = re.search(
                    r"(RSA|ECDSA|ECDH|AES|Ed25519)[-\s]?(\d{3,4})?\s+certificates?\s+are\s+deployed\s+across\s+([A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40})",
                    s,
                    re.I,
                )
                if m_dep:
                    assets.append(m_dep.group(3))
                for aname in assets[:3]:
                    try:
                        ent = ensure(aname)
                    except ValueError:
                        continue
                    family, ks, token = algos[0]
                    val = f"{family}-{ks}" if ks else family
                    conf = "HIGH" if re.search(r"\buses\b|\bdeployed\b|\bcertificates?\b", s_lower) else "MEDIUM"
                    if re.search(r"\bappears\b|\bmay\b|\bpossibly\b|\blikely\b", s_lower):
                        conf = "REVIEW_REQUIRED"
                    ent.add_evidence(
                        Evidence("algorithm", val, s[:240], page=page_no, confidence=conf, source="text")
                    )
                    if ks:
                        ent.add_evidence(
                            Evidence("key_size", ks, s[:240], page=page_no, confidence=conf, source="text")
                        )

            # Criticality
            cm = CRIT_PAT.search(s)
            if cm:
                crit = cm.group(2).lower()
                assets = _nearby_asset_names(s)
                m_env = re.search(
                    r"([A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40}?)\s+(?:environment|platform|system)?\s*is\s+classified\s+as\s+(critical|high|medium|low)",
                    s,
                    re.I,
                )
                if m_env:
                    assets = [m_env.group(1)] + assets
                for aname in assets[:3]:
                    try:
                        ent = ensure(aname)
                    except ValueError:
                        continue
                    ent.add_evidence(
                        Evidence("criticality", crit, s[:240], page=page_no, confidence="HIGH", source="text")
                    )

            # Dependencies / protects / authenticates
            for pat in DEPEND_PATTERNS:
                for m in pat.finditer(s):
                    try:
                        a = ensure(m.group("a"))
                        bname = m.group("b").strip()
                        b = normalize_entity_id(bname)
                    except (ValueError, IndexError):
                        continue
                    conf = "HIGH"
                    if re.search(r"\bappears\b|\bmay\b", s_lower):
                        conf = "REVIEW_REQUIRED"
                    a.add_evidence(
                        Evidence("dependency", bname, s[:240], page=page_no, confidence=conf, source="text")
                    )
                    a.relations.append({"type": "DEPENDS_ON", "target": b, "quote": s[:180]})

            # Key protection phrasing
            m_prot = re.search(
                r"([A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40}?)\s+keys?\s+are\s+protected\s+by\s+([A-Z][A-Za-z0-9][A-Za-z0-9 _\-/]{1,40})",
                s,
                re.I,
            )
            if m_prot:
                try:
                    a = ensure(m_prot.group(1))
                    a.add_evidence(
                        Evidence(
                            "dependency",
                            m_prot.group(2),
                            s[:240],
                            page=page_no,
                            confidence="HIGH",
                            source="text",
                        )
                    )
                except ValueError:
                    pass


    # Explicit classification sentences across full document
    for m in re.finditer(
        r"([A-Z][A-Za-z0-9][A-Za-z0-9 \-/]{1,50}?)\s+is\s+classified\s+as\s+(critical|high|medium|low)\b",
        doc.text,
        re.I,
    ):
        try:
            ent = ensure(m.group(1))
        except ValueError:
            continue
        ent.add_evidence(
            Evidence(
                "criticality",
                m.group(2).lower(),
                m.group(0)[:240],
                page=None,
                confidence="HIGH",
                source="text",
            )
        )
    # "X depends on Y" / "X relies on Y"
    for m in re.finditer(
        r"([A-Z][A-Za-z0-9][A-Za-z0-9 \-/]{1,40}?)\s+(?:depends on|relies on)\s+([A-Z][A-Za-z0-9][A-Za-z0-9 \-/]{1,40})",
        doc.text,
        re.I,
    ):
        try:
            ent = ensure(m.group(1))
            ent.add_evidence(
                Evidence("dependency", m.group(2).strip(), m.group(0)[:240], confidence="HIGH", source="text")
            )
        except ValueError:
            pass

    return entities


def fuse_table_rows_with_entities(
    table_rows: List[Dict[str, str]],
    entities: Dict[str, DocEntity],
) -> List[Dict[str, str]]:
    """Merge prose-derived facts into table rows; add prose-only entities as rows."""
    by_id: Dict[str, Dict[str, str]] = {}
    for r in table_rows:
        aid = normalize_entity_id(r.get("asset_id") or r.get("name") or "")
        if not aid:
            continue
        by_id[aid] = dict(r)

    for cid, ent in entities.items():
        if cid in by_id:
            row = by_id[cid]
            if ent.algorithm and (not row.get("algorithm") or row.get("algorithm") in ("", "unknown")):
                row["algorithm"] = ent.algorithm
            if ent.key_size and (not row.get("key_size") or row.get("key_size") in ("", "0", "unavailable")):
                row["key_size"] = ent.key_size
            if ent.criticality and not row.get("criticality"):
                row["criticality"] = ent.criticality
            if ent.dependencies:
                existing = [d for d in (row.get("dependencies") or "").split(";") if d.strip()]
                for d in ent.dependencies:
                    if d not in existing and d != cid:
                        existing.append(d)
                row["dependencies"] = ";".join(existing)
            # evidence flag
            if any(e.confidence == "REVIEW_REQUIRED" for e in ent.evidence):
                row["_review"] = "REVIEW_REQUIRED"
            by_id[cid] = row
        else:
            # prose-only entity — include only if we have algorithm or criticality signal
            if not (ent.algorithm or ent.criticality or ent.dependencies):
                continue
            by_id[cid] = {
                "asset_id": cid,
                "name": ent.display_name or cid,
                "algorithm": ent.algorithm or "unknown",
                "key_size": ent.key_size or "0",
                "protocol": ent.protocol or "unknown",
                "criticality": ent.criticality or "",
                "internet_exposed": ent.internet_exposed or "false",
                "data_lifetime_years": ent.data_lifetime_years or "0",
                "dependencies": ";".join(ent.dependencies),
                "migration_status": "not_started",
                "_review": "REVIEW_REQUIRED" if not ent.criticality or not ent.algorithm else "",
                "_evidence": [
                    {"field": e.field, "value": e.value, "page": e.page, "confidence": e.confidence, "quote": e.quote}
                    for e in ent.evidence[:6]
                ],
            }

    return list(by_id.values())


def understand_document(
    text: str,
    filename: str = "",
    table_rows: Optional[List[Dict[str, str]]] = None,
) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """Full document understanding pipeline.

    Returns (normalized_rows, meta) where meta includes entity count, evidence samples.
    """
    doc = build_document_model(text, filename=filename)
    entities = extract_entities_from_text(doc)
    fused = fuse_table_rows_with_entities(table_rows or [], entities)
    meta = {
        "document_model": {
            "pages": len(doc.pages),
            "headings": len(doc.headings),
            "entities_from_text": len(entities),
        },
        "evidence_samples": [],
    }
    for ent in list(entities.values())[:12]:
        for e in ent.evidence[:2]:
            meta["evidence_samples"].append(
                {
                    "asset": ent.canonical_id,
                    "field": e.field,
                    "value": e.value,
                    "page": e.page,
                    "confidence": e.confidence,
                    "quote": e.quote[:160],
                }
            )
    return fused, meta
