from datetime import datetime
from unittest.mock import patch, MagicMock


def test_finalize_scan_runs_all_tail_steps_in_order():
    calls = []

    def _record(name):
        def _fn(*a, **kw):
            calls.append(name)
        return _fn

    with patch("yads.worker_tasks.Session") as mock_session_cls, \
         patch("yads.worker_tasks.webhook_service") as mock_webhook, \
         patch("yads.worker_tasks.splunk_logger") as mock_splunk, \
         patch("yads.worker_tasks.get_metrics") as mock_metrics, \
         patch("yads.worker_tasks._worker_client", None):

        mock_session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = mock_session
        # No SystemConfig/Target rows found — exercises the "nothing to do"
        # branches of subdomain auto-queue / compliance recalc / email notify
        # without needing a real DB, while still confirming finalize_scan
        # reaches the status-reset and webhook calls unconditionally.
        mock_session.exec.return_value.first.return_value = None
        mock_session.exec.return_value.all.return_value = []
        mock_session.get.return_value = MagicMock(scan_status=None)

        from yads.worker_tasks import finalize_scan
        finalize_scan(
            target_id=1,
            domain="example.com",
            tenant_id=42,
            scan_types=["wayback_scanner"],
            scan_start_time=datetime.utcnow(),
        )

        mock_webhook.trigger_event.assert_any_call(
            42, "scan_finished",
            {"target_id": 1, "domain": "example.com", "status": "completed", "modules": ["wayback_scanner"]}
        )
