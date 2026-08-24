"""
YADS Test Configuration
=======================
Requires docker-compose.test.yml services to be running:
    docker compose -f docker-compose.test.yml up -d

Environment is pointed at the isolated test DB (port 5433) and Redis (port 6380).
The YADS app starts in-process via starlette TestClient; the lifespan runs
DB migrations and seeds the default admin user automatically.
"""

import os

# ── Override environment BEFORE any YADS module is imported ──────────────────
os.environ.setdefault("DATABASE_URL", "postgresql://yads_test:yads_test@localhost:5433/yads_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6380/0")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-yads-testing-32chars!")
os.environ.setdefault("MFA_ENABLED", "false")
os.environ.setdefault("AUTH_MODE", "local")
os.environ.setdefault("METRICS_ENABLED", "false")
os.environ.setdefault("DEBUG", "true")          # disables TLS-enforcement middleware
os.environ.setdefault("LOG_DIR", "/tmp/yads-test-logs")
os.environ.setdefault("WORKER_MODE", "standalone")
os.environ.setdefault("YADS_ENCRYPTION_KEY", "test-encryption-key-bsi-compliant-123!")
# yads/api/main.py's lifespan only auto-seeds a default admin user on a fresh
# install (no users yet) when YADS_ADMIN_USER/YADS_ADMIN_PASS are set — a
# bare fresh DB otherwise skips seeding entirely and expects /setup/create-admin.
# Without this, admin_client below authenticates as a username with no matching
# User row and every protected route 401s.
os.environ.setdefault("YADS_ADMIN_USER", "admin")
os.environ.setdefault("YADS_ADMIN_PASS", "test-admin-password-for-yads-testing!")

import pytest
from starlette.testclient import TestClient


# ── App fixture (session-scoped: app starts once per pytest run) ──────────────

@pytest.fixture(scope="session")
def app():
    from yads.api.main import app as _app
    return _app


@pytest.fixture(scope="session")
def client(app):
    """Unauthenticated TestClient — lifespan runs once (migrations + admin seed)."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ── Token helpers ─────────────────────────────────────────────────────────────

def _make_token(username: str) -> str:
    from yads.auth.security import create_access_token
    return create_access_token(username)


def _auth_cookies(username: str) -> dict:
    """Return a cookies dict that authenticates as *username*."""
    return {"access_token": _make_token(username)}


# ── Per-role client fixtures ──────────────────────────────────────────────────

@pytest.fixture(scope="session")
def admin_cookies():
    return _auth_cookies("admin")


@pytest.fixture(scope="session")
def admin_client(client, admin_cookies):
    """TestClient pre-loaded with admin credentials.

    Also attaches a valid signed CSRF cookie + matching X-CSRF-Token header
    to every request, so POST/PUT/PATCH/DELETE calls pass CSRFMiddleware
    (yads/api/middleware/csrf_middleware.py) — required since that
    middleware was added after this fixture was originally written.
    """
    from yads.core.csrf import generate_csrf_token, CSRF_COOKIE, CSRF_HEADER

    client.cookies.set("access_token", admin_cookies["access_token"])
    csrf_token = generate_csrf_token()
    client.cookies.set(CSRF_COOKIE, csrf_token)
    client.headers.update({CSRF_HEADER: csrf_token})
    return client


# ── Database session helper (for setup/teardown inside tests) ─────────────────

@pytest.fixture(scope="session")
def db_session():
    from yads.database import engine
    from sqlmodel import Session
    with Session(engine) as session:
        yield session


# ── Tenant fixture (creates a test tenant, cleans up after session) ──────────

@pytest.fixture(scope="session")
def test_tenant(db_session):
    from yads.models import Tenant
    from sqlmodel import select

    existing = db_session.exec(
        select(Tenant).where(Tenant.name == "Test Tenant")
    ).first()
    if existing:
        yield existing
        return

    tenant = Tenant(name="Test Tenant", slug="test-tenant")
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)
    yield tenant

    # On a genuinely fresh test DB (first run against a new container), this
    # branch actually executes -- on a reused persistent container, "Test
    # Tenant" already exists and the early return above skips teardown
    # entirely, which is why this FK issue can stay latent for a long time.
    # Various tests write SecurityAuditLog rows referencing this tenant_id
    # (e.g. run_brand_watch_scan's audit log, _audit_scan_trigger); and
    # APIKey rows from api_key_headers fixture. Clean those up first so the
    # Tenant delete doesn't fail on the FK.
    from yads.models import SecurityAuditLog, APIKey
    db_session.query(APIKey).filter(APIKey.tenant_id == tenant.id).delete()
    db_session.query(SecurityAuditLog).filter(SecurityAuditLog.tenant_id == tenant.id).delete()
    db_session.commit()
    db_session.delete(tenant)
    db_session.commit()


# ── API key fixtures (X-API-Key header auth, distinct from cookie auth) ──────

@pytest.fixture(scope="session")
def api_key_headers(db_session, test_tenant):
    """A real APIKey row (scopes: read, write, scan_execute, destructive),
    scoped to test_tenant. Returns headers dict ready to attach to a client."""
    from yads.models import APIKey
    from yads.auth.security import generate_api_key
    from sqlmodel import select

    existing = db_session.exec(
        select(APIKey).where(APIKey.name == "pytest-fixture-key", APIKey.tenant_id == test_tenant.id)
    ).first()
    if existing:
        # Key was already created in a prior test run against a reused
        # container; the plain key itself isn't recoverable from the hash,
        # so recreate a fresh key row instead of reusing this stale one.
        db_session.delete(existing)
        db_session.commit()

    plain_key, prefix, key_hash = generate_api_key()
    key_row = APIKey(
        tenant_id=test_tenant.id,
        name="pytest-fixture-key",
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=["read", "write", "scan_execute", "destructive"],
    )
    db_session.add(key_row)
    db_session.commit()

    yield {"X-API-Key": plain_key}


@pytest.fixture(scope="session")
def api_key_client(client, api_key_headers):
    """TestClient pre-loaded with a scoped API key (see api_key_headers)."""
    client.headers.update(api_key_headers)
    return client
