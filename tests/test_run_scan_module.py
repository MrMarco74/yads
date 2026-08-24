from unittest.mock import MagicMock, patch
from yads.core.api_block_detection import ApiBlockedError


def test_run_scan_module_runs_module_normally():
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module") as mock_run, \
         patch("yads.worker_tasks.mark_rate_limited") as mock_mark, \
         patch("yads.worker_tasks.clear_rate_limited") as mock_clear:
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module
        run_scan_module(1, "example.com", "wayback_scanner", 42)

        mock_run.assert_called_once()
        mock_mark.assert_not_called()
        mock_clear.assert_called_once_with(1, "wayback_scanner")


def test_run_scan_module_marks_rate_limited_and_reschedules_on_block():
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module", side_effect=ApiBlockedError("wayback", retry_after=5)), \
         patch("yads.worker_tasks.mark_rate_limited") as mock_mark, \
         patch("yads.worker_tasks.run_scan_module.apply_async") as mock_apply_async:
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module
        run_scan_module(1, "example.com", "wayback_scanner", 42, attempt=0)

        mock_mark.assert_called_once()
        assert mock_mark.call_args[0][0] == 1
        assert mock_mark.call_args[0][1] == "wayback_scanner"

        mock_apply_async.assert_called_once()
        _, kwargs = mock_apply_async.call_args
        assert kwargs["kwargs"]["attempt"] == 1
        assert kwargs["countdown"] >= 5  # at least retry_after, jitter only adds


def test_run_scan_module_gives_up_after_max_attempts():
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module", side_effect=ApiBlockedError("wayback")), \
         patch("yads.worker_tasks.mark_rate_limited"), \
         patch("yads.worker_tasks.run_scan_module.apply_async") as mock_apply_async:
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module, MAX_BLOCKED_RETRIES
        run_scan_module(1, "example.com", "wayback_scanner", 42, attempt=MAX_BLOCKED_RETRIES)

        mock_apply_async.assert_not_called()


def test_run_scan_module_does_not_raise_on_block():
    """The chord this feeds must see this task complete, not fail, on a block."""
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module", side_effect=ApiBlockedError("wayback")), \
         patch("yads.worker_tasks.mark_rate_limited"), \
         patch("yads.worker_tasks.run_scan_module.apply_async"):
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module
        run_scan_module(1, "example.com", "wayback_scanner", 42)  # must not raise
