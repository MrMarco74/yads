"""Covers bulk-archive, archive-dead, and restore endpoints."""

import pytest


@pytest.fixture
def archivable_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-archive-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if existing:
        return existing
    t = Target(domain=domain, tenant_id=test_tenant.id, tags=[])
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


def test_bulk_archive_and_restore(api_key_client, archivable_target, db_session):
    from yads.models import Target
    from sqlmodel import select

    r = api_key_client.post("/api/v1/targets/bulk-archive", json={"target_ids": [archivable_target.id]})
    assert r.status_code == 200
    assert r.json()["archived_count"] == 1

    db_session.refresh(archivable_target)
    assert archivable_target.is_archived is True
    assert archivable_target.archived_reason == "manual"

    r2 = api_key_client.post(f"/api/v1/targets/{archivable_target.id}/restore")
    assert r2.status_code == 200

    db_session.refresh(archivable_target)
    assert archivable_target.is_archived is False
    assert archivable_target.archived_reason is None


def test_archive_dead_targets_returns_count(api_key_client):
    r = api_key_client.post("/api/v1/targets/archive-dead")
    assert r.status_code == 200
    assert "archived_count" in r.json()


def test_restore_nonexistent_target_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/targets/999999999/restore")
    assert r.status_code == 404
