"""Wave 4 — API-key-authenticated, tenant-scoped Reports & Export read
surface for yads-mcp. Structured JSON views (executive summary, security
trends, targets export) — the report data an LLM agent can reason over,
distinct from the dashboard's binary PDF/Excel downloads."""

import pytest


@pytest.fixture
def reports_fixture(db_session, test_tenant):
    from yads.models import Target, SecurityTrend
    from sqlmodel import select, delete
    from datetime import datetime, timedelta

    t = db_session.exec(
        select(Target).where(Target.domain == "reports-fixture.example.com",
                             Target.tenant_id == test_tenant.id)
    ).first()
    if not t:
        t = Target(domain="reports-fixture.example.com", tenant_id=test_tenant.id)
        db_session.add(t); db_session.commit(); db_session.refresh(t)

    db_session.exec(delete(SecurityTrend).where(SecurityTrend.tenant_id == test_tenant.id))
    db_session.commit()
    now = datetime.utcnow()
    for days_ago, score, grade in [(20, 60, "D"), (10, 72, "C"), (1, 85, "B")]:
        db_session.add(SecurityTrend(
            tenant_id=test_tenant.id, score=score, grade=grade,
            recorded_at=now - timedelta(days=days_ago),
        ))
    db_session.commit()
    return t


def test_reports_require_api_key(client):
    assert client.get("/api/v1/reports/executive").status_code == 401


def test_executive_summary_shape(api_key_client, reports_fixture):
    r = api_key_client.get("/api/v1/reports/executive")
    assert r.status_code == 200
    body = r.json()
    for key in ("total_targets", "findings", "security_score", "grade"):
        assert key in body


def test_security_trends_returns_points(api_key_client, reports_fixture):
    r = api_key_client.get("/api/v1/reports/trends?days=30")
    assert r.status_code == 200
    points = r.json()["points"]
    assert len(points) >= 3
    assert {"score", "grade", "recorded_at"} <= set(points[0].keys())


def test_security_trends_respects_days_window(api_key_client, reports_fixture):
    r = api_key_client.get("/api/v1/reports/trends?days=5")
    assert r.status_code == 200
    # only the 1-day-ago point falls in a 5-day window
    assert len(r.json()["points"]) == 1


def test_targets_export_returns_rows(api_key_client, reports_fixture):
    r = api_key_client.get("/api/v1/reports/targets/export")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body and "total" in body
    domains = {row["domain"] for row in body["items"]}
    assert "reports-fixture.example.com" in domains
