"""Wave 3 — API-key-authenticated, tenant-scoped Findings & Compliance
read surface for yads-mcp. Mirrors the auth/scoping conventions of
test_v1_tags.py."""

import pytest


@pytest.fixture
def findings_fixture(db_session, test_tenant):
    """A target with three SecurityFindings (crit/high/low, mixed status) and
    a compliance status row, all owned by test_tenant."""
    from yads.models import Target, SecurityFinding, ComplianceTargetStatus
    from sqlmodel import select, delete

    tgt = db_session.exec(
        select(Target).where(Target.domain == "findings-fixture.example.com",
                             Target.tenant_id == test_tenant.id)
    ).first()
    if not tgt:
        tgt = Target(domain="findings-fixture.example.com", tenant_id=test_tenant.id)
        db_session.add(tgt)
        db_session.commit()
        db_session.refresh(tgt)

    # Clean any prior fixture findings for a deterministic count
    db_session.exec(delete(SecurityFinding).where(SecurityFinding.target_id == tgt.id))
    db_session.exec(delete(ComplianceTargetStatus).where(ComplianceTargetStatus.target_id == tgt.id))
    db_session.commit()

    specs = [
        ("YF-TEST-001", "sig1", "critical", "open", "nuclei_scanner", "RCE"),
        ("YF-TEST-002", "sig2", "high", "open", "ssl_scanner", "Weak cipher"),
        ("YF-TEST-003", "sig3", "low", "fixed", "http_headers", "Missing HSTS"),
    ]
    for yf_id, h, sev, status, module, issue in specs:
        db_session.add(SecurityFinding(
            yf_id=yf_id, finding_hash=h, tenant_id=test_tenant.id, target_id=tgt.id,
            domain=tgt.domain, module=module, issue=issue, severity=sev, status=status,
        ))
    db_session.add(ComplianceTargetStatus(
        target_id=tgt.id, framework="bsi", score=72, grade="C",
        passing_controls=18, failing_controls=7, findings=[],
    ))
    db_session.commit()
    return tgt


def test_findings_requires_api_key(client):
    assert client.get("/api/v1/findings").status_code == 401


def test_list_findings_returns_tenant_findings(api_key_client, findings_fixture):
    r = api_key_client.get("/api/v1/findings")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body and "total" in body
    yf_ids = {f["yf_id"] for f in body["items"]}
    assert {"YF-TEST-001", "YF-TEST-002", "YF-TEST-003"} <= yf_ids


def test_list_findings_filter_by_severity(api_key_client, findings_fixture):
    r = api_key_client.get("/api/v1/findings?severity=critical")
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(f["severity"] == "critical" for f in items)
    assert any(f["yf_id"] == "YF-TEST-001" for f in items)


def test_list_findings_filter_by_status(api_key_client, findings_fixture):
    r = api_key_client.get("/api/v1/findings?status=open")
    assert r.status_code == 200
    assert all(f["status"] == "open" for f in r.json()["items"])


def test_findings_summary_counts_by_severity(api_key_client, findings_fixture):
    r = api_key_client.get("/api/v1/findings/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["by_severity"].get("critical", 0) >= 1
    assert body["by_severity"].get("high", 0) >= 1
    assert body["by_status"].get("open", 0) >= 2


def test_get_finding_by_yf_id(api_key_client, findings_fixture):
    r = api_key_client.get("/api/v1/findings/YF-TEST-001")
    assert r.status_code == 200
    assert r.json()["issue"] == "RCE"


def test_get_unknown_finding_returns_404(api_key_client, findings_fixture):
    assert api_key_client.get("/api/v1/findings/YF-DOES-NOT-EXIST").status_code == 404


def test_compliance_status_lists_rows_with_domain(api_key_client, findings_fixture):
    r = api_key_client.get("/api/v1/compliance/status")
    assert r.status_code == 200
    rows = r.json()["items"]
    row = next((x for x in rows if x["domain"] == "findings-fixture.example.com"), None)
    assert row is not None
    assert row["framework"] == "bsi"
    assert row["score"] == 72
    assert row["grade"] == "C"


def test_compliance_summary_aggregates_by_framework(api_key_client, findings_fixture):
    r = api_key_client.get("/api/v1/compliance/summary")
    assert r.status_code == 200
    frameworks = r.json()["frameworks"]
    assert "bsi" in frameworks
    assert frameworks["bsi"]["target_count"] >= 1
    assert "avg_score" in frameworks["bsi"]
