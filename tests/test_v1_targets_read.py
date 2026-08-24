"""Covers GET /api/v1/targets (list) and GET /api/v1/targets/{id} (detail)."""

import pytest


@pytest.fixture
def sample_targets(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domains = ["v1-list-fixture-1.example.com", "v1-list-fixture-2.example.com"]
    created = []
    for d in domains:
        existing = db_session.exec(select(Target).where(Target.domain == d, Target.tenant_id == test_tenant.id)).first()
        if existing:
            created.append(existing)
            continue
        t = Target(domain=d, tenant_id=test_tenant.id, tags=["fixture-tag"])
        db_session.add(t)
        db_session.commit()
        db_session.refresh(t)
        created.append(t)
    return created


def test_list_targets_requires_api_key(client):
    r = client.get("/api/v1/targets")
    assert r.status_code == 401


def test_list_targets_returns_shape(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets")
    assert r.status_code == 200
    body = r.json()
    assert "targets" in body
    assert "total" in body
    assert "page" in body


def test_list_targets_online_false_excludes_never_scanned(api_key_client, sample_targets, db_session):
    from yads.models import ScanResult
    from sqlmodel import select

    scanned_target = sample_targets[0]
    existing = db_session.exec(select(ScanResult).where(ScanResult.target_id == scanned_target.id, ScanResult.module_name == "web_analyzer")).first()
    if not existing:
        db_session.add(ScanResult(target_id=scanned_target.id, module_name="web_analyzer", data={"status_code": 0}, result_hash="x"))
        db_session.commit()

    r = api_key_client.get("/api/v1/targets", params={"online": False})
    assert r.status_code == 200
    domains = [t["domain"] for t in r.json()["targets"]]
    assert scanned_target.domain in domains
    assert "v1-list-fixture-2.example.com" not in domains


def test_list_targets_rejects_negative_limit(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets", params={"limit": -1})
    assert r.status_code == 422


def test_list_targets_rejects_limit_over_cap(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets", params={"limit": 500})
    assert r.status_code == 422


def test_list_targets_filters_by_tag(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets", params={"tag": "fixture-tag"})
    assert r.status_code == 200
    domains = [t["domain"] for t in r.json()["targets"]]
    assert "v1-list-fixture-1.example.com" in domains
    assert "v1-list-fixture-2.example.com" in domains


def test_list_targets_filters_by_domain_search(api_key_client, sample_targets):
    r = api_key_client.get("/api/v1/targets", params={"domain_search": "list-fixture-1"})
    assert r.status_code == 200
    domains = [t["domain"] for t in r.json()["targets"]]
    assert "v1-list-fixture-1.example.com" in domains
    assert "v1-list-fixture-2.example.com" not in domains


def test_get_target_returns_summary(api_key_client, sample_targets):
    target = sample_targets[0]
    r = api_key_client.get(f"/api/v1/targets/{target.id}")
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == target.domain
    assert "scan_status" in body
    assert "module_count" in body


def test_get_target_other_tenant_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = Tenant(name="Other Tenant For Targets Read Test")
    existing = db_session.exec(select(Tenant).where(Tenant.name == other_tenant.name)).first()
    if not existing:
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)
        existing = other_tenant

    other_target = db_session.exec(select(Target).where(Target.domain == "other-tenant-v1-targets-read.example.com")).first()
    if not other_target:
        other_target = Target(domain="other-tenant-v1-targets-read.example.com", tenant_id=existing.id, tags=[])
        db_session.add(other_target)
        db_session.commit()
        db_session.refresh(other_target)

    r = api_key_client.get(f"/api/v1/targets/{other_target.id}")
    assert r.status_code == 404
