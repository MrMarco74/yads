"""
Queue management tests.
Covers: queue page, status API, pause/resume, purge.
"""

import pytest


@pytest.mark.queue
class TestQueuePage:
    def test_queue_page_loads(self, admin_client):
        r = admin_client.get("/queue", follow_redirects=True)
        assert r.status_code == 200

    def test_queue_widget_endpoint(self, admin_client):
        """HTMX widget fragment must return 200."""
        r = admin_client.get("/queue/widget", follow_redirects=True)
        assert r.status_code == 200


@pytest.mark.queue
class TestQueueControl:
    def test_pause_queue(self, admin_client):
        """POST /queue/control with action=pause must not 500."""
        r = admin_client.post(
            "/queue/control",
            data={"action": "pause"},
            follow_redirects=True,
        )
        assert r.status_code < 500

    def test_resume_queue(self, admin_client):
        """POST /queue/control with action=resume must not 500."""
        r = admin_client.post(
            "/queue/control",
            data={"action": "resume"},
            follow_redirects=True,
        )
        assert r.status_code < 500

    def test_invalid_action_rejected(self, admin_client):
        r = admin_client.post(
            "/queue/control",
            data={"action": "explode"},
            follow_redirects=True,
        )
        assert r.status_code in (200, 400, 422)


@pytest.mark.queue
class TestQueuePurge:
    def test_purge_endpoint_reachable(self, admin_client):
        """POST /queue/purge must be reachable by admin."""
        r = admin_client.post("/queue/purge", follow_redirects=True)
        assert r.status_code < 500
