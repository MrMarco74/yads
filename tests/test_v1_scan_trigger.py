"""Covers the existing /api/v1/dast/scan route's new scope requirement,
and the new per-target-id scan trigger."""

import pytest


@pytest.fixture
def scan_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    existing = db_session.exec(
        select(Target).where(Target.domain == "v1-scan-fixture.example.com")
    ).first()
    if existing:
        return existing
    target = Target(domain="v1-scan-fixture.example.com", tenant_id=test_tenant.id, tags=[])
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target


def test_dast_scan_requires_scan_execute_scope(client, db_session, test_tenant):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-scan-execute",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.post(
        "/api/v1/dast/scan",
        json={"target_url": "https://scope-check.example.com"},
        headers={"X-API-Key": plain_key},
    )
    assert r.status_code == 403


def test_scan_trigger_by_target_id(api_key_client, scan_target):
    r = api_key_client.post(f"/api/v1/targets/{scan_target.id}/scan", json={"scan_types": ["ssl_scanner"]})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "queued"
    assert body["target_id"] == scan_target.id


def test_scan_trigger_rejects_invalid_scan_types(api_key_client, scan_target):
    r = api_key_client.post(f"/api/v1/targets/{scan_target.id}/scan", json={"scan_types": ["not-a-real-module"]})
    assert r.status_code == 400


def test_scan_trigger_other_tenant_target_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = db_session.exec(
        select(Tenant).where(Tenant.name == "Other Tenant For Scan Test")
    ).first()
    if not other_tenant:
        other_tenant = Tenant(name="Other Tenant For Scan Test")
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)

    other_target = db_session.exec(
        select(Target).where(Target.domain == "other-tenant-scan-target.example.com")
    ).first()
    if not other_target:
        other_target = Target(domain="other-tenant-scan-target.example.com", tenant_id=other_tenant.id, tags=[])
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

    r = api_key_client.post(f"/api/v1/targets/{other_target.id}/scan", json={"scan_types": ["ssl_scanner"]})
    assert r.status_code == 404
