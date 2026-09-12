"""Confirms the new 'destructive' scope is accepted by API-key creation."""


def test_destructive_is_a_valid_scope():
    from yads.api.routers.api_keys import VALID_SCOPES
    assert "destructive" in VALID_SCOPES


def test_create_key_with_destructive_scope_succeeds(admin_client, test_tenant):
    # tenant_id is now required for a Platform Admin (admin_client has
    # tenant_id=NULL): a NULL-tenant key is rejected by
    # require_tenant_scoped_key on every /api/v1 route, so this test used to
    # assert that an unusable key could be created.
    r = admin_client.post(
        "/api-keys/",
        params={"name": "pytest-destructive-key", "scopes": ["read", "destructive"],
                "tenant_id": test_tenant.id},
    )
    assert r.status_code == 201
    body = r.json()
    assert "destructive" in body["scopes"] or "token" in body
