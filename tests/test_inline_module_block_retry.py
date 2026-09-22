"""
Regression test for the inline (custom_dispatch) scan steps in run_all_scans.

The chord-dispatched modules go through run_scan_module, which catches
ApiBlockedError, marks the module rate-limited for the target and schedules a
retry. The custom_dispatch modules never touch that task -- run_all_scans runs
them inline, each wrapped in its own `try: ... except Exception`. That generic
handler swallowed ApiBlockedError: no rate-limited marker, no retry, and the
target was finalized as if the module had simply produced nothing.

Observed in production on 2026-09-21: the ipinfo circuit breaker tripped six
times (escalating 300s -> 9600s) while the Infrastructure Scanner logged 1071
"'ipinfo' is blocking/rate-limiting us" errors and not a single reschedule, so
~590 targets ended the run without infrastructure data.
"""
import pytest
from unittest.mock import MagicMock, patch

from yads.core.api_block_detection import ApiBlockedError


def test_handle_api_block_marks_rate_limited_and_reschedules():
    from yads.worker_tasks import handle_api_block

    exc = ApiBlockedError("ipinfo", retry_after=600)

    with patch("yads.worker_tasks.mark_rate_limited") as mark, \
         patch("yads.worker_tasks.run_scan_module") as task:
        handle_api_block(exc, 42, "example.com", "infrastructure_scanner", 2)

    mark.assert_called_once()
    assert mark.call_args.args[:2] == (42, "infrastructure_scanner")
    task.apply_async.assert_called_once()
    kwargs = task.apply_async.call_args.kwargs
    assert kwargs["args"] == [42, "example.com", "infrastructure_scanner", 2]
    assert kwargs["kwargs"] == {"attempt": 1}
    assert 600 <= kwargs["countdown"] <= 900


def test_handle_api_block_stops_rescheduling_once_the_budget_is_spent():
    from yads.worker_tasks import handle_api_block, MAX_BLOCKED_RETRIES

    exc = ApiBlockedError("ipinfo", retry_after=600)

    with patch("yads.worker_tasks.mark_rate_limited"), \
         patch("yads.worker_tasks.run_scan_module") as task:
        handle_api_block(exc, 42, "example.com", "infrastructure_scanner", 2,
                         attempt=MAX_BLOCKED_RETRIES)

    task.apply_async.assert_not_called()


def test_inline_infrastructure_step_reschedules_instead_of_swallowing():
    """The evidenced bug: a blocked provider must not end as a silent no-op."""
    from yads.worker_tasks import _run_infrastructure_scanner

    scanner_cls = MagicMock(__name__="InfrastructureScanner")
    scanner_cls.return_value.module_name = "infrastructure_scanner"
    scanner_cls.return_value.process.side_effect = ApiBlockedError("ipinfo", retry_after=600)

    with patch("yads.worker_tasks.InfrastructureScanner", scanner_cls, create=True), \
         patch("yads.worker_tasks.handle_api_block") as handler:
        _run_infrastructure_scanner(MagicMock(), 42, "example.com", 2)

    handler.assert_called_once()
    exc = handler.call_args.args[0]
    assert isinstance(exc, ApiBlockedError)
    assert exc.service == "ipinfo"
    assert handler.call_args.args[1:] == (42, "example.com", "infrastructure_scanner", 2)


def test_inline_infrastructure_step_still_swallows_other_errors():
    from yads.worker_tasks import _run_infrastructure_scanner

    scanner_cls = MagicMock(__name__="InfrastructureScanner")
    scanner_cls.return_value.module_name = "infrastructure_scanner"
    scanner_cls.return_value.process.side_effect = RuntimeError("boom")

    with patch("yads.worker_tasks.InfrastructureScanner", scanner_cls, create=True), \
         patch("yads.worker_tasks.handle_api_block") as handler:
        _run_infrastructure_scanner(MagicMock(), 42, "example.com", 2)  # must not raise

    handler.assert_not_called()
