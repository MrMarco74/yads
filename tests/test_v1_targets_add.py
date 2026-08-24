"""Covers POST /api/v1/targets (add a single target)."""


def test_add_target_creates_new(api_key_client):
    r = api_key_client.post("/api/v1/targets", json={"domain": "v1-add-fixture.example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == "v1-add-fixture.example.com"
    assert "id" in body


def test_add_target_is_idempotent_find_or_create(api_key_client):
    r1 = api_key_client.post("/api/v1/targets", json={"domain": "v1-add-idempotent.example.com"})
    r2 = api_key_client.post("/api/v1/targets", json={"domain": "v1-add-idempotent.example.com"})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["id"] == r2.json()["id"]


def test_add_target_blocks_internal_domain(api_key_client):
    r = api_key_client.post("/api/v1/targets", json={"domain": "localhost"})
    assert r.status_code == 400
