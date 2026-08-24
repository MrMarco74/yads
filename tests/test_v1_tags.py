"""Covers the full tags surface: list, per-target add/remove, bulk
assign/add, and global delete -- all API-key-authenticated and
tenant-scoped."""

import pytest


@pytest.fixture
def owned_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    existing = db_session.exec(
        select(Target).where(Target.domain == "v1-tags-fixture.example.com")
    ).first()
    if existing:
        return existing
    target = Target(domain="v1-tags-fixture.example.com", tenant_id=test_tenant.id, tags=[])
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)
    return target


def test_tags_list_requires_api_key(client):
    r = client.get("/api/v1/tags")
    assert r.status_code == 401


def test_tags_list_returns_list(api_key_client):
    r = api_key_client.get("/api/v1/tags")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_add_and_remove_tag_on_target(api_key_client, owned_target):
    r = api_key_client.post(f"/api/v1/targets/{owned_target.id}/tags", json={"tag": "sedoparking"})
    assert r.status_code == 200
    assert "sedoparking" in r.json()

    r = api_key_client.delete(f"/api/v1/targets/{owned_target.id}/tags/sedoparking")
    assert r.status_code == 200
    assert "sedoparking" not in r.json()


def test_add_tag_on_other_tenant_target_returns_404(api_key_client, db_session):
    from yads.models import Target, Tenant

    other_tenant = Tenant(name="Other Tenant For Tags Test", slug="other-tenant-tags")
    db_session.add(other_tenant)
    db_session.commit()
    db_session.refresh(other_tenant)

    other_target = Target(domain="other-tenant-target.example.com", tenant_id=other_tenant.id, tags=[])
    db_session.add(other_target)
    db_session.commit()
    db_session.refresh(other_target)

    r = api_key_client.post(f"/api/v1/targets/{other_target.id}/tags", json={"tag": "sedoparking"})
    assert r.status_code == 404


def test_bulk_assign_add_action(api_key_client, owned_target):
    r = api_key_client.post("/api/v1/tags/bulk-assign", json={
        "target_ids": [owned_target.id], "tags": ["bulk-tag-a"], "action": "add",
    })
    assert r.status_code == 200
    assert r.json()["updated"] == 1


def test_bulk_add_by_ids(api_key_client, owned_target):
    r = api_key_client.post("/api/v1/targets/bulk/tag", json={
        "target_ids": [owned_target.id], "tag": "bulk-tag-b",
    })
    assert r.status_code == 200
    assert r.json()["updated"] >= 1


def test_delete_tag_globally_requires_destructive_scope(client, db_session, test_tenant):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive-tags",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.delete("/api/v1/tags/sedoparking", headers={"X-API-Key": plain_key})
    assert r.status_code == 403


def test_delete_tag_globally_with_destructive_scope(api_key_client, owned_target):
    api_key_client.post(f"/api/v1/targets/{owned_target.id}/tags", json={"tag": "delete-me-globally"})
    r = api_key_client.delete("/api/v1/tags/delete-me-globally")
    assert r.status_code == 200
    assert r.json()["removed_from"] >= 1
