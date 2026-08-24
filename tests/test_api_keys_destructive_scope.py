"""Confirms the new 'destructive' scope is accepted by API-key creation."""


def test_destructive_is_a_valid_scope():
    from yads.api.routers.api_keys import VALID_SCOPES
    assert "destructive" in VALID_SCOPES


def test_create_key_with_destructive_scope_succeeds(admin_client):
    r = admin_client.post(
        "/api-keys/",
        params={"name": "pytest-destructive-key", "scopes": ["read", "destructive"]},
    )
    assert r.status_code == 201
    body = r.json()
    assert "destructive" in body["scopes"] or "token" in body
