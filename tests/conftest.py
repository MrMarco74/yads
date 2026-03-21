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
    """TestClient pre-loaded with admin credentials."""
    client.cookies.set("access_token", admin_cookies["access_token"])
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
    db_session.delete(tenant)
    db_session.commit()
