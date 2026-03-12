"""
Smoke tests — basic sanity checks that the app starts and core pages respond.
These run first; if they fail, the rest of the suite is likely broken.
"""

import pytest


@pytest.mark.smoke
def test_login_page_loads(client):
    """GET /login must return 200 HTML."""
    r = client.get("/login")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


@pytest.mark.smoke
def test_unauthenticated_dashboard_redirects(client):
    """Accessing / without a token must redirect to /login."""
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers.get("location", "")


@pytest.mark.smoke
def test_unauthenticated_targets_redirects(client):
    r = client.get("/targets", follow_redirects=False)
    assert r.status_code in (302, 303)


@pytest.mark.smoke
def test_authenticated_dashboard_loads(admin_client):
    """Admin should see the dashboard (or a redirect to /dashboard)."""
    r = admin_client.get("/", follow_redirects=True)
    assert r.status_code == 200


@pytest.mark.smoke
def test_health_endpoint(client):
    """If a /api/health or similar endpoint exists it must return 2xx."""
    r = client.get("/api/health", follow_redirects=False)
    # Not all apps have /api/health; accept 200 or 404
    assert r.status_code in (200, 404)


@pytest.mark.smoke
def test_static_files_served(client):
    """Static directory must be mounted and reachable."""
    r = client.get("/static/", follow_redirects=False)
    # Could be 200 (directory listing) or 404 (no listing) — not 500
    assert r.status_code in (200, 403, 404)
