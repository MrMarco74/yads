"""API-key management from the Platform Admin's settings page.

A Platform Admin has tenant_id=NULL, so the key endpoints were effectively
dead for them: create produced a NULL-tenant key that require_tenant_scoped_key
rejects on the whole /api/v1 surface, list filtered on NULL and always came
back empty, and delete compared against NULL and 404'd on every key. A key is
only useful when it belongs to a tenant, so a Platform Admin now names the
tenant the key is for.
"""
import uuid


def _name(basis: str) -> str:
    """Eindeutig pro Lauf -- die Test-DB ueberlebt den Lauf, und ein
    gleichnamiger Key aus einem frueheren Lauf wuerde zuerst gefunden."""
    return f"{basis}-{uuid.uuid4().hex[:8]}"


def _tenant_admin_client(app, db_session, tenant_id, username="pytest-tadmin"):
    """A logged-in tenant_admin of *tenant_id* (no fixture for this exists)."""
    from starlette.testclient import TestClient
    from sqlmodel import select
    from yads.models import User
    from yads.auth.security import create_access_token, get_password_hash
    from yads.core.csrf import generate_csrf_token, CSRF_COOKIE, CSRF_HEADER

    # Rolle und Tenant immer setzen, nicht nur beim Anlegen: die Test-DB
    # ueberlebt den Lauf, und eine Zeile aus einem frueheren Lauf mit
    # tenant_id=NULL wuerde hier still als Platform Admin durchgehen -- der
    # Test bewiese dann das Gegenteil von dem, was er behauptet.
    user = db_session.exec(select(User).where(User.username == username)).first()
    if not user:
        user = User(username=username, password_hash=get_password_hash("irrelevant-for-token-auth"))
        db_session.add(user)
    user.role = "tenant_admin"
    user.tenant_id = tenant_id
    user.is_active = True
    user.force_password_change = False
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    assert user.tenant_id == tenant_id

    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set("access_token", create_access_token(username))
    token = generate_csrf_token()
    c.cookies.set(CSRF_COOKIE, token)
    c.headers.update({CSRF_HEADER: token})
    return c


def test_platform_admin_must_name_a_tenant(admin_client):
    """Without a tenant the key would be born unusable — refuse it up front
    instead of handing out a key that 403s on first use."""
    name = _name("pytest-no-tenant")
    r = admin_client.post("/api-keys/", params={"name": name, "scopes": ["read"]})
    assert r.status_code == 400
    assert "tenant" in r.json()["detail"].lower()


def test_platform_admin_creates_key_for_a_tenant(admin_client, test_tenant):
    name = _name("pytest-for-tenant")
    r = admin_client.post("/api-keys/", params={
        "name": name, "scopes": ["read", "destructive"],
        "tenant_id": test_tenant.id,
    })
    assert r.status_code == 201
    body = r.json()
    assert body["tenant_id"] == test_tenant.id
    assert "destructive" in body["scopes"]


def test_platform_admin_rejects_unknown_tenant(admin_client):
    name = _name("pytest-ghost-tenant")
    r = admin_client.post("/api-keys/", params={
        "name": name, "scopes": ["read"], "tenant_id": 999999,
    })
    assert r.status_code == 404


def test_list_shows_scopes(admin_client, test_tenant):
    """Today's list omits scopes, so the page could not show what a key may
    do — the exact gap that hid a missing 'destructive' scope."""
    name = _name("pytest-scope-visible")
    admin_client.post("/api-keys/", params={
        "name": name, "scopes": ["read", "write"], "tenant_id": test_tenant.id,
    })
    r = admin_client.get("/api-keys/")
    assert r.status_code == 200
    eintrag = next(k for k in r.json() if k["name"] == name)
    assert sorted(eintrag["scopes"]) == ["read", "write"]


def test_platform_admin_sees_keys_of_every_tenant(admin_client, test_tenant):
    name = _name("pytest-visible-to-platform")
    admin_client.post("/api-keys/", params={
        "name": name, "scopes": ["read"], "tenant_id": test_tenant.id,
    })
    r = admin_client.get("/api-keys/")
    assert r.status_code == 200
    eintrag = next(k for k in r.json() if k["name"] == name)
    assert eintrag["tenant_id"] == test_tenant.id
    assert eintrag["tenant_name"] == test_tenant.name


def test_platform_admin_may_delete_a_tenants_key(admin_client, test_tenant):
    name = _name("pytest-delete-me")
    angelegt = admin_client.post("/api-keys/", params={
        "name": name, "scopes": ["read"], "tenant_id": test_tenant.id,
    }).json()
    r = admin_client.delete(f"/api-keys/{angelegt['id']}")
    assert r.status_code == 200
    assert all(k["id"] != angelegt["id"] for k in admin_client.get("/api-keys/").json())


def test_tenant_admin_cannot_create_for_another_tenant(app, db_session, test_tenant):
    """Sonst waere der Parameter eine Rechteausweitung: ein tenant_admin
    koennte sich einen Key fuer fremde Daten ausstellen."""
    from yads.models import Tenant

    from sqlmodel import select

    fremd = db_session.exec(select(Tenant).where(Tenant.name == "pytest-fremdtenant")).first()
    if not fremd:
        fremd = Tenant(name="pytest-fremdtenant", slug="pytest-fremdtenant")
        db_session.add(fremd)
        db_session.commit()
        db_session.refresh(fremd)

    c = _tenant_admin_client(app, db_session, test_tenant.id)
    r = c.post("/api-keys/", params={
        "name": _name("pytest-escalation"), "scopes": ["read"], "tenant_id": fremd.id,
    })
    assert r.status_code == 403


def test_tenant_admin_keeps_working_without_a_tenant_id(app, db_session, test_tenant):
    """Der bestehende Weg darf nicht kaputtgehen: ein tenant_admin legt
    weiterhin ohne Parameter Keys fuer den eigenen Tenant an."""
    c = _tenant_admin_client(app, db_session, test_tenant.id)
    r = c.post("/api-keys/", params={"name": _name("pytest-own-tenant"), "scopes": ["read"]})
    assert r.status_code == 201
    assert r.json()["tenant_id"] == test_tenant.id


def test_settings_page_zeigt_die_key_verwaltung(admin_client):
    r = admin_client.get("/settings")
    assert r.status_code == 200
    assert "api-keys-panel" in r.text


def test_settings_page_bietet_provision_tenant_nicht_an(admin_client):
    """Der Scope erlaubt das Anlegen beliebiger Tenants und gehoert nicht in
    ein Formular, das man nebenbei ausfuellt."""
    r = admin_client.get("/settings")
    assert 'value="provision_tenant"' not in r.text
