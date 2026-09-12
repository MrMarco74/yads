"""The v1 queue endpoints must act on the real broker (RabbitMQ), not on the
legacy Redis list named "celery".

Against a RabbitMQ BROKER_URL the Redis-list manipulation in v1_queue's purge
is a no-op, so an API purge left the backlog sitting in the broker and it
drained later — the same defect as the 2026-08-25 broker-backlog incident,
which was only ever fixed for the cookie-session UI handler (queue.py).
"""

from unittest.mock import patch

from yads.config import settings


def test_purge_clears_this_tenants_tasks_from_the_real_broker(api_key_client, test_tenant):
    """Mirrors the cookie-session handler: only this tenant's messages are
    dropped, and the dropped tasks feed the 60s undo window."""
    undo = [{"target_id": 1, "domain": "example.com", "scan_types": ["dns"], "tenant_id": test_tenant.id}]
    with patch("yads.core.broker_ops.purge_broker_queue_for_tenant", return_value=(3, undo)) as mock_purge:
        r = api_key_client.post("/api/v1/queue/purge", json={"confirm": True})

    assert r.status_code == 200
    mock_purge.assert_called_once_with(settings.BROKER_URL, test_tenant.id)
    body = r.json()
    assert body["purged_count"] == 3
    assert body["undo_batch"]


def test_purge_leaves_other_tenants_broker_messages_alone(api_key_client):
    """The fleet-wide purge_broker_queues() must not be used here — it would
    discard other tenants' pending scans from a tenant-scoped endpoint."""
    with patch("yads.core.broker_ops.purge_broker_queue_for_tenant", return_value=(0, [])), \
         patch("yads.core.broker_ops.purge_broker_queues") as mock_fleet_purge:
        r = api_key_client.post("/api/v1/queue/purge", json={"confirm": True})

    assert r.status_code == 200
    mock_fleet_purge.assert_not_called()


def test_pause_purges_the_broker_backlog(api_key_client):
    with patch("yads.core.broker_ops.purge_broker_queues", return_value=42) as mock_purge:
        r = api_key_client.post("/api/v1/queue/control", json={"action": "pause"})

    assert r.status_code == 200
    mock_purge.assert_called_once_with(settings.BROKER_URL)
    assert r.json()["broker_purged_count"] == 42


def test_resume_does_not_purge_the_broker(api_key_client):
    with patch("yads.core.broker_ops.purge_broker_queues", return_value=42) as mock_purge:
        r = api_key_client.post("/api/v1/queue/control", json={"action": "resume"})

    assert r.status_code == 200
    mock_purge.assert_not_called()


def test_status_reports_the_broker_queue_depth(api_key_client):
    depths = {"celery": 12, "discovery": 3}
    with patch("yads.core.broker_ops.get_broker_queue_depth", return_value=depths) as mock_depth:
        r = api_key_client.get("/api/v1/queue/status")

    assert r.status_code == 200
    mock_depth.assert_called_once_with(settings.BROKER_URL)
    body = r.json()
    assert body["broker_depth"] == depths
    assert body["broker_pending"] == 15
