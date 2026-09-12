"""
REST API v1 tests (Bearer token / API key auth).
Covers: /api/v1 endpoints, API key creation and usage.
"""

import pytest


@pytest.mark.auth
class TestAPIKeyAuth:
    def test_v1_without_auth_returns_401(self, client):
        """v1 API endpoints must reject unauthenticated requests."""
        r = client.get("/api/v1/findings", follow_redirects=False)
        assert r.status_code in (401, 403, 422)

    def test_v1_rejects_cookie_session_without_api_key(self, admin_client):
        """Die v1-Flaeche ist Maschinen-Schnittstelle: sie authentifiziert
        ueber X-API-Key, nicht ueber die Browser-Session.

        Der Test hiess vorher test_v1_with_cookie_auth und forderte das
        Gegenteil -- er war dauerhaft rot. Dass eine Session hier NICHT
        genuegt, ist die eigentlich schuetzenswerte Eigenschaft: sonst waere
        jeder tenant-scoped v1-Endpunkt ueber eine Browser-Session
        erreichbar, an den API-Key-Scopes vorbei.
        """
        r = admin_client.get("/api/v1/findings", follow_redirects=True)
        assert r.status_code == 401

    def test_v1_reachable_with_api_key(self, api_key_client):
        r = api_key_client.get("/api/v1/findings", follow_redirects=True)
        assert r.status_code in (200, 404)  # 404 = no findings yet, that's OK

    def test_developer_page_loads(self, admin_client):
        r = admin_client.get("/developer", follow_redirects=True)
        assert r.status_code == 200

    def test_create_api_key(self, admin_client):
        """Admin must be able to create an API key."""
        r = admin_client.post(
            "/developer/keys/create",
            data={"name": "pytest-key", "description": "Created by pytest"},
            follow_redirects=True,
        )
        assert r.status_code < 500
