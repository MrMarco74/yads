"""Covers POST /api/v1/targets/bulk-delete and its undo companion."""

import pytest


@pytest.fixture
def deletable_targets(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domains = ["v1-delete-fixture-1.example.com", "v1-delete-fixture-2.example.com"]
    created = []
    for d in domains:
        existing = db_session.exec(select(Target).where(Target.domain == d, Target.tenant_id == test_tenant.id)).first()
        if existing:
            created.append(existing)
            continue
        t = Target(domain=d, tenant_id=test_tenant.id, tags=[])
        db_session.add(t)
        db_session.commit()
        db_session.refresh(t)
        created.append(t)
    return created


def test_bulk_delete_requires_confirm(api_key_client, deletable_targets):
    ids = [t.id for t in deletable_targets]
    r = api_key_client.post("/api/v1/targets/bulk-delete", json={"target_ids": ids, "confirm": False})
    assert r.status_code == 400


def test_bulk_delete_requires_destructive_scope(client, db_session, test_tenant, deletable_targets):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive-targets",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    ids = [t.id for t in deletable_targets]
    r = client.post("/api/v1/targets/bulk-delete", json={"target_ids": ids, "confirm": True}, headers={"X-API-Key": plain_key})
    assert r.status_code == 403


def test_bulk_delete_and_undo(api_key_client, db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-delete-and-undo-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if not existing:
        existing = Target(domain=domain, tenant_id=test_tenant.id, tags=["keep-me"])
        db_session.add(existing)
        db_session.commit()
        db_session.refresh(existing)
    target_id = existing.id

    r = api_key_client.post("/api/v1/targets/bulk-delete", json={"target_ids": [target_id], "confirm": True})
    assert r.status_code == 200
    body = r.json()
    assert body["deleted_count"] == 1
    assert body["undo_batch"]

    gone = db_session.exec(select(Target).where(Target.id == target_id)).first()
    assert gone is None

    r2 = api_key_client.post("/api/v1/targets/bulk-delete/undo", json={"undo_batch": body["undo_batch"]})
    assert r2.status_code == 200
    assert r2.json()["restored_count"] == 1

    restored = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    assert restored is not None
    assert restored.tags == ["keep-me"]


def test_undo_bulk_delete_expired_batch_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/targets/bulk-delete/undo", json={"undo_batch": "nonexistent-batch"})
    assert r.status_code == 404
