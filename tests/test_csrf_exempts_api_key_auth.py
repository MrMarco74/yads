"""Confirms X-API-Key-authenticated POST/DELETE requests bypass CSRF
validation, mirroring the existing Authorization: Bearer exemption --
without this, every /api/v1/* write endpoint (old and new) is rejected
with 403 CSRF errors in production despite valid API-key auth."""


def test_post_with_api_key_header_bypasses_csrf(client, api_key_headers):
    """A POST with a valid X-API-Key and NO CSRF cookie/header must not be
    rejected by CSRF middleware -- it may still 401/403/422/404 for other
    reasons (route-specific), but never with the CSRF-specific 403 body."""
    r = client.post("/api/v1/dast/scan", json={"target_url": "https://csrf-exempt-check.example.com"}, headers=api_key_headers)
    assert r.status_code != 403 or "CSRF" not in r.text


def test_post_without_any_auth_still_requires_csrf_or_401s():
    """Sanity check the exemption is narrow: an unauthenticated POST to a
    cookie-session route still gets rejected (401/403), not silently let
    through by an overly broad exemption."""
    from starlette.testclient import TestClient
    from yads.api.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post("/queue/control", data={"action": "pause"})
        assert r.status_code in (401, 403, 307, 303)
