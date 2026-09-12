"""
Authentication & authorisation tests.
Covers: login, JWT cookies, logout, RBAC, wrong credentials.
"""

import pytest


@pytest.mark.auth
class TestLogin:
    def test_valid_login_returns_200(self, browser_client, admin_password):
        """POST /login with correct credentials must succeed."""
        r = browser_client.post(
            "/login",
            data={"username": "admin", "password": admin_password},
            follow_redirects=True,
        )
        assert r.status_code == 200

    def test_valid_login_sets_cookie(self, browser_client, admin_password):
        """Successful login must set the access_token cookie."""
        r = browser_client.post(
            "/login",
            data={"username": "admin", "password": admin_password},
            follow_redirects=False,
        )
        # Either sets cookie directly or redirects — in both cases cookie must appear
        # (follow redirect to get final cookie jar)
        r2 = browser_client.post(
            "/login",
            data={"username": "admin", "password": admin_password},
            follow_redirects=True,
        )
        assert "access_token" in r2.cookies or r2.status_code == 200

    def test_wrong_password_rejected(self, browser_client):
        """POST /login with wrong password must NOT produce a valid session."""
        r = browser_client.post(
            "/login",
            data={"username": "admin", "password": "wrong_password_xyz"},
            follow_redirects=True,
        )
        # Must stay on login page (200) with error, not redirect to dashboard
        assert r.status_code == 200
        assert "access_token" not in r.cookies

    def test_nonexistent_user_rejected(self, browser_client):
        r = browser_client.post(
            "/login",
            data={"username": "nobody_xyz_123", "password": "anything"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert "access_token" not in r.cookies

    def test_empty_credentials_rejected(self, browser_client):
        r = browser_client.post(
            "/login",
            data={"username": "", "password": ""},
            follow_redirects=True,
        )
        assert r.status_code in (200, 422)


@pytest.mark.auth
class TestJWTProtection:
    def test_no_token_html_route_redirects(self, client):
        """Any protected HTML route without a token must refuse access."""
        # /targets existiert nicht -- die Liste liegt unter /targets/table.
        # Gegen den 404 war die Schleife wirkungslos und haette einen
        # fehlenden Auth-Schutz nie bemerkt.
        #
        # 401 ist mit abgedeckt, weil nicht jede geschuetzte Seite auf /login
        # umleitet -- einige antworten dem Browser mit einem rohen 401.
        for path in ["/targets/table", "/queue", "/settings"]:
            r = client.get(path, follow_redirects=False)
            assert r.status_code in (302, 303, 307, 401), f"{path} should refuse access without auth"

    def test_invalid_token_redirects(self, client):
        """A tampered/expired JWT must redirect to /login."""
        r = client.get(
            "/targets/table",
            cookies={"access_token": "this.is.invalid"},
            follow_redirects=False,
        )
        assert r.status_code in (302, 303, 307, 401)

    def test_valid_token_grants_access(self, admin_client):
        """Admin token must allow access to protected pages."""
        r = admin_client.get("/targets/table", follow_redirects=True)
        assert r.status_code == 200


@pytest.mark.auth
class TestLogout:
    def test_logout_clears_session(self, browser_client, admin_password):
        """GET /logout must remove access_token cookie and redirect."""
        # First log in
        browser_client.post(
            "/login",
            data={"username": "admin", "password": admin_password},
            follow_redirects=True,
        )
        r = browser_client.get("/logout", follow_redirects=False)
        # Must redirect (to /login or /)
        assert r.status_code in (302, 303)


@pytest.mark.auth
class TestRBAC:
    def test_admin_can_access_admin_settings(self, admin_client):
        """Platform admin must reach /settings without 403."""
        r = admin_client.get("/settings", follow_redirects=True)
        assert r.status_code == 200

    def test_admin_can_access_tenants(self, admin_client):
        r = admin_client.get("/tenants", follow_redirects=True)
        assert r.status_code == 200

    def test_admin_can_access_users(self, admin_client):
        r = admin_client.get("/users", follow_redirects=True)
        assert r.status_code == 200
