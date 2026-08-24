"""Confirms the new api_key fixtures authenticate against a real API-key row."""


def test_api_key_headers_missing_key_is_rejected(client):
    r = client.get("/api/v1/findings")
    assert r.status_code == 401


def test_api_key_headers_authenticate(api_key_client):
    r = api_key_client.get("/api/v1/findings")
    assert r.status_code in (200, 404)  # 404 = no findings yet, not an auth failure
