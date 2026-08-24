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


def test_add_target_cross_tenant_domain_collision_returns_409(api_key_client, db_session):
    from yads.models import Target, Tenant
    from sqlmodel import select

    other_tenant = db_session.exec(select(Tenant).where(Tenant.name == "Other Tenant For Add Collision Test")).first()
    if not other_tenant:
        other_tenant = Tenant(name="Other Tenant For Add Collision Test")
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)

    domain = "v1-add-cross-tenant-collision.example.com"
    existing = db_session.exec(select(Target).where(Target.domain == domain)).first()
    if not existing:
        db_session.add(Target(domain=domain, tenant_id=other_tenant.id, tags=[]))
        db_session.commit()

    r = api_key_client.post("/api/v1/targets", json={"domain": domain})
    assert r.status_code == 409
