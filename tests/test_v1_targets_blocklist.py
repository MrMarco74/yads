"""Covers POST /api/v1/targets/bulk-blocklist -- destructive (archives +
adds an exact-match blocklist pattern, no single-action undo)."""

import pytest


@pytest.fixture
def blocklistable_target(db_session, test_tenant):
    from yads.models import Target
    from sqlmodel import select

    domain = "v1-blocklist-fixture.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == test_tenant.id)).first()
    if existing:
        return existing
    t = Target(domain=domain, tenant_id=test_tenant.id, tags=[])
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)
    return t


def test_bulk_blocklist_requires_confirm(api_key_client, blocklistable_target):
    r = api_key_client.post("/api/v1/targets/bulk-blocklist", json={"target_ids": [blocklistable_target.id], "confirm": False})
    assert r.status_code == 400


def test_bulk_blocklist_requires_destructive_scope(client, db_session, test_tenant, blocklistable_target):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive-blocklist",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.post(
        "/api/v1/targets/bulk-blocklist",
        json={"target_ids": [blocklistable_target.id], "confirm": True},
        headers={"X-API-Key": plain_key},
    )
    assert r.status_code == 403


def test_bulk_blocklist_archives_and_adds_pattern(api_key_client, blocklistable_target, db_session, test_tenant):
    from yads.models import DiscoveryDomainBlocklist
    from sqlmodel import select

    r = api_key_client.post(
        "/api/v1/targets/bulk-blocklist",
        json={"target_ids": [blocklistable_target.id], "confirm": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["blocklisted_count"] == 1
    assert body["archived_count"] == 1

    db_session.refresh(blocklistable_target)
    assert blocklistable_target.is_archived is True
    assert blocklistable_target.archived_reason == "blocklisted"

    pattern_row = db_session.exec(
        select(DiscoveryDomainBlocklist).where(
            DiscoveryDomainBlocklist.tenant_id == test_tenant.id,
            DiscoveryDomainBlocklist.pattern == "v1-blocklist-fixture.example.com",
        )
    ).first()
    assert pattern_row is not None
