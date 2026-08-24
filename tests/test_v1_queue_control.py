"""Covers GET /api/v1/queue/status, POST /api/v1/queue/control,
POST /api/v1/queue/tasks/{id}/cancel."""


def test_queue_status_requires_api_key(client):
    r = client.get("/api/v1/queue/status")
    assert r.status_code == 401


def test_queue_status_returns_expected_shape(api_key_client):
    r = api_key_client.get("/api/v1/queue/status")
    assert r.status_code == 200
    body = r.json()
    for key in ("queue_active", "queued_count", "running_count", "active_tasks", "reserved_tasks", "rate_limited_module_count"):
        assert key in body


def test_queue_control_pause_and_resume(api_key_client):
    r = api_key_client.post("/api/v1/queue/control", json={"action": "pause"})
    assert r.status_code == 200
    assert r.json()["queue_active"] is False

    r = api_key_client.post("/api/v1/queue/control", json={"action": "resume"})
    assert r.status_code == 200
    assert r.json()["queue_active"] is True


def test_queue_control_rejects_bad_action(api_key_client):
    r = api_key_client.post("/api/v1/queue/control", json={"action": "not-a-real-action"})
    assert r.status_code == 400


def test_cancel_task_not_found_returns_404(api_key_client):
    r = api_key_client.post("/api/v1/queue/tasks/nonexistent-task-id/cancel")
    assert r.status_code == 404
