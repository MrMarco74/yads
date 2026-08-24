"""Covers get_target_changes, get_scan_status, get_network_context."""

import pytest


@pytest.fixture
def status_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-status-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if existing:
        return existing
    t = Target(domain=domain, tenant_id=test_tenant.id, tags=[], scan_status="idle")
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


def test_get_target_changes_returns_list(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/changes")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_get_target_changes_caps_limit(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/changes", params={"limit": 500})
    assert r.status_code == 422  # manual bounds check in the handler body


def test_get_target_changes_rejects_negative_limit(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/changes", params={"limit": -1})
    assert r.status_code == 422


def test_get_target_changes_other_tenant_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = Tenant(name="Other Tenant For Status Test")
    existing = db_session.exec(select(Tenant).where(Tenant.name == other_tenant.name)).first()
    if not existing:
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)
        existing = other_tenant

    other_target = db_session.exec(select(Target).where(Target.domain == "other-tenant-status.example.com")).first()
    if not other_target:
        other_target = Target(domain="other-tenant-status.example.com", tenant_id=existing.id, tags=[])
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

    r = api_key_client.get(f"/api/v1/targets/{other_target.id}/changes")
    assert r.status_code == 404


def test_get_scan_status_returns_status(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/scan-status")
    assert r.status_code == 200
    assert "status" in r.json()


def test_get_scan_status_other_tenant_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = db_session.exec(select(Tenant).where(Tenant.name == "Other Tenant For Status Test")).first()
    if not other_tenant:
        other_tenant = Tenant(name="Other Tenant For Status Test")
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)

    other_target = db_session.exec(select(Target).where(Target.domain == "other-tenant-status.example.com")).first()
    if not other_target:
        other_target = Target(domain="other-tenant-status.example.com", tenant_id=other_tenant.id, tags=[])
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

    r = api_key_client.get(f"/api/v1/targets/{other_target.id}/scan-status")
    assert r.status_code == 404


def test_get_network_context_returns_shape(api_key_client, status_target):
    r = api_key_client.get(f"/api/v1/targets/{status_target.id}/network-context")
    assert r.status_code == 200
    body = r.json()
    assert "network_context" in body
    assert "target_domain" in body
