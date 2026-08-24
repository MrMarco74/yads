"""Covers POST /api/v1/queue/purge and POST /api/v1/queue/undo-purge —
the destructive-scope + confirm:bool pair."""


def test_purge_requires_confirm_true(api_key_client):
    r = api_key_client.post("/api/v1/queue/purge", json={"confirm": False})
    assert r.status_code == 400


def test_purge_with_confirm_succeeds(api_key_client):
    r = api_key_client.post("/api/v1/queue/purge", json={"confirm": True})
    assert r.status_code == 200
    body = r.json()
    assert "purged_count" in body
    assert "revoked_count" in body


def test_purge_rejects_key_without_destructive_scope(db_session, test_tenant, client):
    from yads.models import APIKey
    from yads.auth.security import generate_api_key

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id, name="pytest-no-destructive",
        key_prefix=prefix, key_hash=key_hash, scopes=["read", "write"],
    )
    db_session.add(key_row)
    db_session.commit()

    r = client.post("/api/v1/queue/purge", json={"confirm": True}, headers={"X-API-Key": plain_key})
    assert r.status_code == 403


def test_undo_purge_with_expired_batch_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/queue/undo-purge", json={"undo_batch": "nonexistent-batch-id"})
    assert r.status_code == 404
