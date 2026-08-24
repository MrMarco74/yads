"""Covers the require_tenant_scoped_key guard (yads/auth/deps.py): a
NULL-tenant_id API key (owned by a Platform Admin) must be rejected with
403 on every tenant-scoped /api/v1 route in v1_queue.py, v1_tags.py, and
v1_scan.py -- per the fail-closed invariant documented on
APIKey.tenant_id in yads/models.py. Before this guard existed, a
NULL-tenant key fell through to `None`-vs-`None` comparisons or an
"else: return everything" branch in three places and ended up scoped to
ALL tenants instead of NONE."""

import pytest


@pytest.fixture
def null_tenant_api_key_headers(db_session):
    """A real APIKey row with tenant_id=None and every scope, so a 403
    from these tests can only be coming from the tenant guard -- not from
    a missing scope."""
    from yads.models import APIKey
    from yads.auth.security import generate_api_key
    from sqlmodel import select

    existing = db_session.exec(
        select(APIKey).where(APIKey.name == "pytest-null-tenant-key")
    ).first()
    if existing:
        db_session.delete(existing)
        db_session.commit()

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=None,
        name="pytest-null-tenant-key",
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=["read", "write", "scan_execute", "destructive"],
    )
    db_session.add(key_row)
    db_session.commit()

    return {"X-API-Key": plain_key}


def test_queue_status_rejects_null_tenant_key(client, null_tenant_api_key_headers):
    r = client.get("/api/v1/queue/status", headers=null_tenant_api_key_headers)
    assert r.status_code == 403


def test_tags_list_rejects_null_tenant_key(client, null_tenant_api_key_headers):
    r = client.get("/api/v1/tags", headers=null_tenant_api_key_headers)
    assert r.status_code == 403


def test_bulk_scan_preview_count_rejects_null_tenant_key(client, null_tenant_api_key_headers):
    r = client.get("/api/v1/targets/bulk-scan/preview-count", headers=null_tenant_api_key_headers)
    assert r.status_code == 403
