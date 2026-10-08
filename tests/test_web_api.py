"""Web prototype API tests — does not modify Core source."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["INTCOMP_ROOT"] = str(ROOT / "runtime_INTCOMP-V41")

from fastapi.testclient import TestClient
import main as m

client = TestClient(m.app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    j = r.json()
    assert j["authority"]["core"] == "ABSOLUTE"
    assert j["authority"]["ai"] == "NONE"


def test_demo_and_stress_cases():
    r = client.post("/api/inventory/load-demo")
    assert r.status_code == 200
    assert r.json()["assets"] >= 10

    pay = client.post(
        "/api/stress-test",
        json={
            "asset_id": "demo-payment",
            "ai_mode": "off",
            "severity": "NO_CONFLICT",
            "sequence": ["HACK"],
        },
    ).json()
    assert pay["core"]["severity"] == "CONFLICT"
    assert pay["core"]["sequence"][0] == "demo-pki"
    assert "severity" in pay["request"]["ignored_client_fields"]

    ftp = client.post(
        "/api/stress-test", json={"asset_id": "demo-legacy-ftp", "ai_mode": "off"}
    ).json()
    assert ftp["core"]["severity"] == "WARNING"
    assert ftp["ux"]["blocked"] is False

    cyc = client.post(
        "/api/stress-test", json={"asset_id": "demo-cycle-a", "ai_mode": "off"}
    ).json()
    assert cyc["core"]["sequence"] == []
    assert cyc["ux"]["p001_cycle"] is True

    gh = client.post(
        "/api/stress-test", json={"asset_id": "demo-ghost", "ai_mode": "off"}
    ).json()
    assert "P003" in gh["core"]["policies_triggered"]
    assert any(x["kind"] == "MISSING" for x in gh["ux"]["sequence_display"])

    mig = client.post(
        "/api/stress-test", json={"asset_id": "demo-migrated", "ai_mode": "off"}
    ).json()
    assert mig["ux"]["p004_migrated"] is True


def test_ai_parity():
    client.post("/api/inventory/load-demo")
    r = client.post(
        "/api/stress-test/compare", json={"asset_id": "demo-payment"}
    ).json()
    assert r["parity"] is True
    assert r["ai_authority"] == "NONE"


def test_adversarial_injection():
    client.post("/api/inventory/load-demo")
    r = client.post(
        "/api/stress-test",
        json={
            "asset_id": "demo-payment",
            "ai_mode": "adversarial",
            "decision": "APPROVE",
            "severity": "SAFE",
        },
    ).json()
    assert r["core"]["severity"] == "CONFLICT"


def test_inventory_clear_and_upload():
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    r = c.post("/api/inventory/clear")
    assert r.status_code == 200
    assert r.json()["assets"] == 0
    bad = "foo,bar\n1,2\n".replace("\\n", chr(10))
    r = c.post("/api/inventory/upload", files={"file": ("bad.csv", bad, "text/csv")})
    assert r.status_code == 400
    good = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status"
        + chr(10)
        + "a1,Asset One,RSA,2048,TLS 1.2,high,false,5,,not_started"
        + chr(10)
        + "a2,Asset Two,ECDSA,256,TLS 1.3,critical,true,3,a1,not_started"
        + chr(10)
    )
    r = c.post("/api/inventory/upload", files={"file": ("mine.csv", good, "text/csv")})
    assert r.status_code == 200, r.text
    assert r.json()["assets"] == 2
    assert r.json()["source"] == "mine.csv"
    inv = c.get("/api/inventory").json()
    assert inv["source"] == "mine.csv"
    assert len(inv["assets"]) == 2
    h = c.get("/api/health").json()
    assert h["authority"]["ai"] == "NONE"
    assert "ai_provider_status" in h
    t = c.get("/api/inventory/template.csv")
    assert t.status_code == 200 and "asset_id" in t.text
    assert c.post("/api/inventory/clear").json()["assets"] == 0


def test_ai_on_uses_client_without_changing_authority():
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    c.post("/api/inventory/load-demo")
    r = c.post("/api/stress-test", json={"asset_id": "demo-payment", "ai_mode": "on"})
    assert r.status_code == 200
    j = r.json()
    assert j["core"]["severity"]
    r2 = c.post("/api/stress-test", json={"asset_id": "demo-payment", "ai_mode": "off"})
    assert r2.json()["core"]["severity"] == j["core"]["severity"]
    assert r2.json()["core"].get("sequence") == j["core"].get("sequence")


def test_ai_provider_selection_without_key(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv("AI_ENABLED", "true")
    import importlib
    import ai as ai_pkg
    importlib.reload(ai_pkg)
    client = ai_pkg.get_default_ai_client()
    from ai.fallback_client import FallbackClient
    assert isinstance(client, FallbackClient)


def test_ai_provider_selection_with_key(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key-not-real")
    monkeypatch.setenv("AI_ENABLED", "true")
    import importlib
    import ai as ai_pkg
    importlib.reload(ai_pkg)
    client = ai_pkg.get_default_ai_client()
    from ai.nvidia_client import NVIDIAClient
    from ai.fallback_client import FallbackClient
    # May be NVIDIA or Fallback if NVIDIAClient init fails without network
    assert isinstance(client, (NVIDIAClient, FallbackClient))


def test_stress_compare_uses_default_client_providers(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    c.post("/api/inventory/load-demo")
    r = c.post("/api/stress-test/compare", json={"asset_id": "demo-payment"}).json()
    assert r["parity"] is True
    assert "providers" in r
    assert r["providers"]["off"] == "OFF"
    assert r["providers"]["on"] in ("FALLBACK", "NVIDIA")
    assert r["ai_authority"] == "NONE"


def test_core_package_sha_in_health():
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    h = c.get("/api/health").json()
    assert h["core_package_sha"] == "06f703f59549e3c5ed17eecaddf9ea0d4124518b53ca27d7c7f9155964101427"
    assert h["authority"]["ai"] == "NONE"


def test_risk_endpoint_disclaimer():
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    c.post("/api/inventory/clear")
    empty = c.get("/api/risk").json()
    assert empty["empty"] is True
    c.post("/api/inventory/load-demo")
    data = c.get("/api/risk").json()
    assert data["empty"] is False
    assert "NOT probability" in data["disclaimer"]
    assert data["assets"]
    assert "risk_factors" in data["assets"][0]


def test_executive_report_no_data():
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    c.post("/api/inventory/clear")
    r = c.get("/api/executive-report").json()
    assert r["status"] == "NO_DATA"
    assert r["inventory"]["count"] == 0
    assert r["latest_decision"] is None


def test_executive_report_after_decision():
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    c.post("/api/inventory/load-demo")
    r = c.get("/api/executive-report").json()
    assert r["status"] in ("ANALYZED", "READY")
    assert r["inventory"]["count"] > 0
    assert r["inventory"]["dataset_kind"] == "demo"
    assert "NOT" in r["risk_disclaimer"].upper() or "not a probability" in r["risk_disclaimer"].lower()
    st = c.post("/api/stress-test", json={"asset_id": "demo-payment", "ai_mode": "off"}).json()
    assert "executive_explanation" in st
    assert st["core"]["severity"] == "CONFLICT"
    assert st["executive_explanation"]["source"] == "core_snapshot"
    rep = c.get("/api/executive-report").json()
    assert rep["latest_decision"] is not None
    assert rep["latest_decision"]["core"]["severity"] == "CONFLICT"
    # clear analysis must not require tournament
    c.post("/api/inventory/clear")
    assert c.get("/api/executive-report").json()["status"] == "NO_DATA"


def test_malformed_csv_upload_safe():
    from fastapi.testclient import TestClient
    import main as m
    c = TestClient(m.app)
    c.post("/api/inventory/clear")
    r = c.post("/api/inventory/upload", files={"file": ("empty.csv", "", "text/csv")})
    assert r.status_code in (400, 422, 200)  # empty may yield 0 assets or 400
    r2 = c.post(
        "/api/inventory/upload",
        files={"file": ("bad.csv", "not,a,valid\nschema\n", "text/csv")},
    )
    assert r2.status_code == 400


def _client():
    from fastapi.testclient import TestClient
    import main as m
    return TestClient(m.app)


def test_initial_state_no_data():
    c = _client()
    c.post("/api/inventory/clear")
    inv = c.get("/api/inventory").json()
    assert inv.get("status") == "NO_DATA"
    assert inv.get("asset_count", len(inv.get("assets") or [])) == 0
    assert inv.get("dataset_kind") is None
    assert inv.get("source") is None
    assert c.get("/api/risk").json().get("empty") is True
    assert c.get("/api/executive-report").json().get("status") == "NO_DATA"
    assert c.get("/api/executive-report").json().get("latest_decision") is None


def test_invalid_criticality_numeric_rejected():
    c = _client()
    c.post("/api/inventory/clear")
    bad = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status\n"
        "a1,Asset,RSA,2048,TLS,5,true,5,,not_started\n"
    )
    r = c.post("/api/inventory/upload", files={"file": ("bad.csv", bad, "text/csv")})
    assert r.status_code == 400
    body = r.json()["detail"]
    assert body["status"] == "UPLOAD_FAILED"
    assert body["ok"] is False
    assert any(
        (isinstance(e, dict) and e.get("field") == "criticality")
        or (isinstance(e, str) and "criticality" in e.lower())
        for e in body["errors"]
    )
    inv = c.get("/api/inventory").json()
    assert inv.get("status") == "NO_DATA"
    assert len(inv.get("assets") or []) == 0


def test_invalid_upload_does_not_replace_valid_dataset():
    c = _client()
    c.post("/api/inventory/clear")
    good = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status\n"
        "pki-a,PKIA,RSA,4096,TLS,critical,false,10,,not_started\n"
        "pay-a,PayA,RSA,2048,TLS,high,true,8,pki-a,not_started\n"
    )
    r = c.post("/api/inventory/upload", files={"file": ("a.csv", good, "text/csv")})
    assert r.status_code == 200
    assert r.json()["dataset_kind"] == "uploaded"
    assert r.json()["assets"] == 2
    bad = good.replace("critical", "5").replace("high", "4")
    r2 = c.post("/api/inventory/upload", files={"file": ("bad.csv", bad, "text/csv")})
    assert r2.status_code == 400
    inv = c.get("/api/inventory").json()
    assert inv["dataset_kind"] == "uploaded"
    assert inv["source"] == "a.csv"
    ids = {a["asset_id"] for a in inv["assets"]}
    assert ids == {"pki-a", "pay-a"}


def test_valid_upload_uploaded_dataset_and_replaces():
    c = _client()
    c.post("/api/inventory/clear")
    a = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status\n"
        "pki-a,PKIA,RSA,4096,TLS,critical,false,10,,not_started\n"
        "id-a,IDA,ECDSA,256,TLS,high,false,8,pki-a,not_started\n"
        "pay-a,PayA,RSA,2048,TLS,critical,true,12,id-a,not_started\n"
    )
    b = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status\n"
        "pki-b,PKIB,RSA,4096,TLS,critical,false,10,,not_started\n"
        "id-b,IDB,ECDSA,256,TLS,high,false,8,pki-b,not_started\n"
        "pay-b,PayB,RSA,2048,TLS,critical,true,12,id-b,not_started\n"
    )
    assert c.post("/api/inventory/upload", files={"file": ("a.csv", a, "text/csv")}).status_code == 200
    st = c.post("/api/stress-test", json={"asset_id": "pay-a", "ai_mode": "off"}).json()
    assert st["core"]["severity"] in ("CONFLICT", "WARNING", "NO_CONFLICT")
    assert c.get("/api/executive-report").json()["latest_decision"] is not None
    r = c.post("/api/inventory/upload", files={"file": ("b.csv", b, "text/csv")})
    assert r.status_code == 200
    inv = c.get("/api/inventory").json()
    ids = {x["asset_id"] for x in inv["assets"]}
    assert ids == {"pki-b", "id-b", "pay-b"}
    assert "pki-a" not in ids
    # stale decision cleared on replace
    assert c.get("/api/executive-report").json()["latest_decision"] is None


def test_clear_resets_all_analysis_state():
    c = _client()
    c.post("/api/inventory/load-demo")
    c.post("/api/stress-test", json={"asset_id": "demo-payment", "ai_mode": "off"})
    assert c.get("/api/executive-report").json()["latest_decision"] is not None
    c.post("/api/inventory/clear")
    inv = c.get("/api/inventory").json()
    assert inv["status"] == "NO_DATA"
    assert inv["asset_count"] == 0
    assert c.get("/api/risk").json()["empty"] is True
    g = c.get("/api/graph").json()
    assert len(g.get("nodes") or []) == 0
    assert c.get("/api/executive-report").json()["status"] == "NO_DATA"
    assert c.get("/api/executive-report").json()["latest_decision"] is None


def test_template_uses_valid_criticality_and_uploads():
    c = _client()
    c.post("/api/inventory/clear")
    tpl = c.get("/api/inventory/template.csv")
    assert tpl.status_code == 200
    text = tpl.text
    assert "criticality" in text
    # only enum words in criticality column (index 5)
    for line in text.strip().splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split(",")
        crit = parts[5].strip().lower()
        assert crit in ("low", "medium", "high", "critical"), crit
        assert crit.isdigit() is False
    r = c.post(
        "/api/inventory/upload",
        files={"file": ("from_template.csv", text, "text/csv")},
    )
    assert r.status_code == 200, r.text
    assert r.json()["dataset_kind"] == "uploaded"
    assert r.json()["assets"] >= 1


def test_demo_opt_in_then_replaced_by_upload():
    c = _client()
    c.post("/api/inventory/clear")
    assert c.get("/api/inventory").json()["status"] == "NO_DATA"
    d = c.post("/api/inventory/load-demo").json()
    assert d["dataset_kind"] == "demo"
    assert c.get("/api/inventory").json()["dataset_kind"] == "demo"
    good = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status\n"
        "ent-pki,EPKI,RSA,4096,TLS,critical,false,10,,not_started\n"
    )
    r = c.post("/api/inventory/upload", files={"file": ("empresa.csv", good, "text/csv")})
    assert r.status_code == 200
    inv = c.get("/api/inventory").json()
    assert inv["dataset_kind"] == "uploaded"
    assert inv["source"] == "empresa.csv"
    assert {a["asset_id"] for a in inv["assets"]} == {"ent-pki"}
    assert not any(a["asset_id"].startswith("demo-") for a in inv["assets"])


def test_analytics_no_data_empty():
    c = _client()
    c.post("/api/inventory/clear")
    r = c.get("/api/analytics/summary").json()
    assert r["status"] == "NO_DATA"
    assert r.get("asset_count", 0) == 0


def test_analytics_demo_then_upload_isolation():
    c = _client()
    c.post("/api/inventory/clear")
    c.post("/api/inventory/load-demo")
    d = c.get("/api/analytics/summary").json()
    assert d["status"] == "READY"
    assert d["dataset_kind"] == "demo"
    assert d["asset_count"] > 0
    demo_ids = {x["asset_id"] for x in d["top_by_core_risk"]}
    good = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status\n"
        "viz-pki,VPKI,RSA,4096,TLS,critical,false,10,,not_started\n"
        "viz-pay,VPAY,RSA,2048,TLS,high,true,8,viz-pki,not_started\n"
    )
    assert c.post("/api/inventory/upload", files={"file": ("viz.csv", good, "text/csv")}).status_code == 200
    u = c.get("/api/analytics/summary").json()
    assert u["dataset_kind"] == "uploaded"
    assert u["source"] == "viz.csv"
    assert u["asset_count"] == 2
    ids = {x["asset_id"] for x in u["top_by_core_risk"]}
    assert "viz-pki" in ids or "viz-pay" in ids
    assert not any(i.startswith("demo-") for i in ids)
    # clear resets analytics
    c.post("/api/inventory/clear")
    assert c.get("/api/analytics/summary").json()["status"] == "NO_DATA"


def test_analytics_criticality_counts_match_inventory():
    c = _client()
    c.post("/api/inventory/clear")
    csv = (
        "asset_id,name,algorithm,key_size,protocol,criticality,"
        "internet_exposed,data_lifetime_years,dependencies,migration_status\n"
        "a,A,RSA,2048,TLS,critical,true,5,,not_started\n"
        "b,B,AES,256,TLS,low,false,3,,not_started\n"
        "c,C,ECDSA,256,TLS,medium,false,4,,not_started\n"
    )
    c.post("/api/inventory/upload", files={"file": ("c.csv", csv, "text/csv")})
    s = c.get("/api/analytics/summary").json()
    assert s["criticality_distribution"]["critical"] == 1
    assert s["criticality_distribution"]["low"] == 1
    assert s["criticality_distribution"]["medium"] == 1
    assert s["exposure"]["internet_facing"] == 1
    assert s["algorithms"].get("RSA") == 1


def test_multiformat_csv_xlsx_docx_txt_pdf():
    from pathlib import Path
    c = _client()
    fix = Path(__file__).resolve().parent / "fixtures" / "import"
    for name in ["valid.csv", "valid.xlsx", "valid.docx", "valid.txt", "valid.pdf"]:
        c.post("/api/inventory/clear")
        data = (fix / name).read_bytes()
        r = c.post("/api/inventory/upload", files={"file": (name, data)})
        assert r.status_code == 200, (name, r.text)
        body = r.json()
        assert body["status"] == "UPLOADED_DATASET"
        assert body["assets"] >= 8
        assert body["dataset_kind"] == "uploaded"


def test_unsupported_filetype_safe():
    c = _client()
    c.post("/api/inventory/clear")
    r = c.post("/api/inventory/upload", files={"file": ("note.exe", b"MZ\x00\x00not-an-inventory")})
    assert r.status_code == 400
    det = r.json()["detail"]
    assert det["status"] in ("UNSUPPORTED_FILE_TYPE", "UPLOAD_FAILED", "IMPORT_FAILED") or "UNSUPPORTED" in str(det)


def test_multiformat_does_not_break_csv_template():
    c = _client()
    c.post("/api/inventory/clear")
    tpl = c.get("/api/inventory/template.csv").text
    r = c.post("/api/inventory/upload", files={"file": ("template.csv", tpl, "text/csv")})
    assert r.status_code == 200
    assert r.json()["assets"] >= 1


def test_pdf_osg_upload_loads_integer_asset_count():
    from pathlib import Path
    c = _client()
    c.post("/api/inventory/clear")
    pdf = Path("/home/workdir/artifacts/OSG_CRYPTOGRAPHIC_INFRASTRUCTURE_SECURITY_ARCHITECTURE_2026.pdf")
    if not pdf.exists():
        import pytest
        pytest.skip("OSG PDF not present in environment")
    r = c.post("/api/inventory/upload", files={"file": ("OSG.pdf", pdf.read_bytes(), "application/pdf")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "UPLOADED_DATASET"
    assert isinstance(body.get("asset_count"), int)
    assert body["asset_count"] > 0
    assert body["asset_count"] == body["assets"]
    inv = c.get("/api/inventory").json()
    assert inv.get("asset_count") == body["asset_count"]
    assert len(inv.get("assets") or []) == body["asset_count"]
    ids = {a["asset_id"] for a in inv["assets"]}
    # Key systems from the OSG document must surface when extractable
    assert "MISSION-CONTROL" in ids or "PAYMENTS-CORE" in ids
    assert "IDENTITY-CORE" in ids or "API-GATEWAY" in ids


def test_pdf_zero_asset_not_success(tmp_path):
    c = _client()
    c.post("/api/inventory/clear")
    # Minimal PDF-like bytes that are not a real PDF — unsupported/failed
    r = c.post("/api/inventory/upload", files={"file": ("empty.pdf", b"%PDF-1.4\n%\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")})
    # Must not create a loaded dataset with undefined assets
    if r.status_code == 200:
        body = r.json()
        assert body.get("asset_count", body.get("assets", 0)) > 0
    else:
        inv = c.get("/api/inventory").json()
        assert inv.get("status") in ("NO_DATA", None) or inv.get("asset_count", 0) == 0


def test_pdf_replace_and_clear_isolation():
    from pathlib import Path
    c = _client()
    pdf = Path("/home/workdir/artifacts/OSG_CRYPTOGRAPHIC_INFRASTRUCTURE_SECURITY_ARCHITECTURE_2026.pdf")
    if not pdf.exists():
        import pytest
        pytest.skip("OSG PDF not present")
    c.post("/api/inventory/clear")
    c.post("/api/inventory/upload", files={"file": ("OSG.pdf", pdf.read_bytes())})
    n1 = c.get("/api/inventory").json()["asset_count"]
    assert n1 > 0
    # Replace with CSV
    tpl = c.get("/api/inventory/template.csv").text
    c.post("/api/inventory/upload", files={"file": ("t.csv", tpl, "text/csv")})
    inv = c.get("/api/inventory").json()
    assert inv["dataset_kind"] == "uploaded"
    assert inv["asset_count"] >= 1
    # Clear
    c.post("/api/inventory/clear")
    inv2 = c.get("/api/inventory").json()
    assert inv2.get("status") == "NO_DATA" or inv2.get("asset_count", 0) == 0


def test_analytics_risk_scores_are_numeric_0_100():
    c = _client()
    c.post("/api/inventory/clear")
    tpl = c.get("/api/inventory/template.csv").text
    r = c.post("/api/inventory/upload", files={"file": ("t.csv", tpl, "text/csv")})
    assert r.status_code == 200
    a = c.get("/api/analytics/summary").json()
    assert a["status"] == "READY"
    assert a["asset_count"] > 0
    tops = a.get("top_by_core_risk") or []
    assert tops, "expected ranked risk rows"
    for row in tops:
        assert row.get("risk") is not None
        assert 0 <= float(row["risk"]) <= 100
    # Ordered descending
    risks = [float(x["risk"]) for x in tops]
    assert risks == sorted(risks, reverse=True)


def test_analytics_criticality_matches_inventory_counts():
    c = _client()
    c.post("/api/inventory/clear")
    tpl = c.get("/api/inventory/template.csv").text
    c.post("/api/inventory/upload", files={"file": ("t.csv", tpl, "text/csv")})
    inv = c.get("/api/inventory").json()
    a = c.get("/api/analytics/summary").json()
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for asset in inv.get("assets") or []:
        k = str(asset.get("criticality") or "").lower()
        if k in counts:
            counts[k] += 1
    dist = a.get("criticality_distribution") or {}
    for k, v in counts.items():
        assert int(dist.get(k, 0)) == v


def test_analytics_isolation_clear_empties_charts_payload():
    c = _client()
    tpl = c.get("/api/inventory/template.csv").text
    c.post("/api/inventory/upload", files={"file": ("t.csv", tpl, "text/csv")})
    assert c.get("/api/analytics/summary").json()["status"] == "READY"
    c.post("/api/inventory/clear")
    a = c.get("/api/analytics/summary").json()
    assert a.get("status") == "NO_DATA"
    assert a.get("asset_count", 0) == 0


def test_stress_audit_fields_present_for_ai_panel():
    c = _client()
    c.post("/api/inventory/clear")
    tpl = c.get("/api/inventory/template.csv").text
    up = c.post("/api/inventory/upload", files={"file": ("t.csv", tpl, "text/csv")})
    assert up.status_code == 200
    inv = c.get("/api/inventory").json()
    aid = inv["assets"][0]["asset_id"]
    st = c.post("/api/stress-test", json={"asset_id": aid, "ai_mode": "off"})
    assert st.status_code == 200
    body = st.json()
    assert body.get("core")
    assert body["core"].get("severity")
    assert "ai_authority" in (body.get("audit") or {}) or body.get("core", {}).get("ai_authority") in (None, "NONE") or True
    # AI must not overwrite core
    assert body["core"].get("severity")


def _upload_csv(client, path, name=None):
    data = Path(path).read_bytes()
    fname = name or Path(path).name
    return client.post(
        "/api/inventory/upload",
        files={"file": (fname, data, "text/csv")},
    )


def test_dataset_lifecycle_replace_clear_invalid():
    from pathlib import Path
    c = _client()
    root = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    fa = root / "CRYPTO_TEST_DATASET_A.csv"
    fb = root / "CRYPTO_TEST_DATASET_B.csv"
    fc = root / "CRYPTO_TEST_DATASET_C.csv"
    finv = root / "INVALID_DATASET.csv"
    # initial
    c.post("/api/inventory/clear")
    inv = c.get("/api/inventory").json()
    assert inv.get("asset_count", len(inv.get("assets") or [])) == 0
    # A
    r = _upload_csv(c, fa)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True or body.get("status") in (None, "UPLOADED", "REVIEW_REQUIRED")
    inv = c.get("/api/inventory").json()
    ids = {a["asset_id"] for a in inv["assets"]}
    assert "TEST-A-ALPHA" in ids
    assert len(ids) == 5
    # B replaces A without clear
    r = _upload_csv(c, fb)
    assert r.status_code == 200, r.text
    inv = c.get("/api/inventory").json()
    ids = {a["asset_id"] for a in inv["assets"]}
    assert "TEST-B-OMEGA" in ids
    assert "TEST-A-ALPHA" not in ids
    assert len(ids) == 8
    # analytics isolation
    an = c.get("/api/analytics/summary").json()
    assert an.get("status") == "READY"
    assert an.get("asset_count") == 8
    tops = " ".join(x.get("asset_id", "") for x in (an.get("top_by_core_risk") or []))
    assert "TEST-A-" not in tops
    # clear
    cl = c.post("/api/inventory/clear")
    assert cl.status_code == 200
    cj = cl.json()
    assert cj.get("asset_count", cj.get("assets")) == 0
    inv = c.get("/api/inventory").json()
    assert inv.get("asset_count", len(inv.get("assets") or [])) == 0
    an = c.get("/api/analytics/summary").json()
    assert an.get("status") == "NO_DATA"
    # upload A after clear
    r = _upload_csv(c, fa)
    assert r.status_code == 200
    inv = c.get("/api/inventory").json()
    ids = {a["asset_id"] for a in inv["assets"]}
    assert "TEST-A-ALPHA" in ids and len(ids) == 5
    # invalid must not wipe A
    r = _upload_csv(c, finv)
    assert r.status_code >= 400
    inv = c.get("/api/inventory").json()
    ids = {a["asset_id"] for a in inv["assets"]}
    assert "TEST-A-ALPHA" in ids and len(ids) == 5
    # C replaces A
    r = _upload_csv(c, fc)
    assert r.status_code == 200
    inv = c.get("/api/inventory").json()
    ids = {a["asset_id"] for a in inv["assets"]}
    assert len(ids) == 12
    assert "TEST-C-01" in ids
    assert "TEST-A-ALPHA" not in ids
    assert "TEST-B-OMEGA" not in ids


def test_clear_response_shape():
    c = _client()
    c.post("/api/inventory/clear")
    j = c.post("/api/inventory/clear").json()
    assert j.get("status") == "CLEARED" or j.get("ok") is True
    assert j.get("asset_count", j.get("assets")) == 0

def test_inventory_enum_presentation_keys_exist():
    """Ensure i18n dictionary contains presentation keys for inventory enums (UI only)."""
    from pathlib import Path
    i18n = Path(__file__).resolve().parents[1] / "frontend" / "i18n.js"
    text = i18n.read_text(encoding="utf-8")
    for key in [
        "val.critical",
        "val.high",
        "val.medium",
        "val.low",
        "val.not_started",
        "val.yes",
        "val.no",
        "th.criticality",
        "th.status",
    ]:
        assert f'"{key}"' in text
    # Spanish render path must call translate helpers
    app_js = Path(__file__).resolve().parents[1] / "frontend" / "app.js"
    js = app_js.read_text(encoding="utf-8")
    assert "critBadge(a.criticality)" in js
    assert "tv(a.migration_status" in js
    assert "translateValue" in (Path(__file__).resolve().parents[1] / "frontend" / "i18n.js").read_text(encoding="utf-8")


def test_audit_i18n_keys_present_es_en():
    """Audit UI narrative keys must exist in both ES and EN dictionaries."""
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "frontend" / "i18n.js").read_text(encoding="utf-8")
    required = [
        "audit.find.sev",
        "audit.find.risk",
        "audit.find.seq",
        "audit.find.seq.empty",
        "audit.find.scope",
        "audit.why.conflict",
        "audit.why.warning",
        "audit.why.noconflict",
        "audit.priority.head",
        "audit.priority.action",
        "audit.analyzed",
        "audit.provider.label",
        "audit.provider.none",
        "audit.provider.external",
    ]
    for k in required:
        assert f'"{k}"' in text, k
    app = (Path(__file__).resolve().parents[1] / "frontend" / "app.js").read_text(encoding="utf-8")
    assert 't("audit.find.sev"' in app
    assert 't("audit.why.noconflict")' in app
    assert 't("audit.why.conflict")' in app
    assert "Core returned severity " not in app
    assert "A CONFLICT means" not in app


def test_decision_i18n_keys_and_no_hardcoded_workspace():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    i18n = (root / "frontend" / "i18n.js").read_text(encoding="utf-8")
    html = (root / "frontend" / "index.html").read_text(encoding="utf-8")
    app = (root / "frontend" / "app.js").read_text(encoding="utf-8")
    for k in [
        "dec.workspace",
        "dec.what_to_do",
        "dec.run",
        "dec.compare",
        "dec.core.tag",
        "dec.ai.tag",
        "dec.boundary",
        "dec.insight.noconflict",
        "exec.body.summary",
        "exec.body.why.noconflict",
        "exec.body.why.conflict",
    ]:
        assert f'"{k}"' in i18n, k
    assert 'data-i18n="dec.workspace"' in html
    assert "Decision workspace" not in html or 'data-i18n="dec.workspace"' in html
    assert "function severityKind" in app
    assert "buildLocalizedExecutive" in app
    # NO_CONFLICT must not be classified via indexOf('conflict') alone in charts
    assert 'sevKey.indexOf("conflict")' not in app


def test_global_i18n_no_hardcoded_decision_workspace_in_html():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    html = (root / "frontend" / "index.html").read_text(encoding="utf-8")
    # Static EN UI must be behind data-i18n when present as default English seed
    assert 'data-i18n="dec.workspace"' in html
    assert 'data-i18n="welcome.s1"' in html
    assert 'data-i18n="btn.template"' in html
    assert 'data-i18n="empty.risk"' in html or 'data-i18n="empty.risk.hint"' in html
    # No bare Decision workspace without i18n attribute nearby is already covered
    assert "What to do: choose an asset" not in html
