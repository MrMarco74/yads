"""
Verifies run_all_scans computes is_parked unconditionally (not gated on
scan_types) right after the has_http/has_https pre-check, and tags the
target when parked. This test targets the specific block added in this
task in isolation via monkeypatching, not a full run_all_scans execution
(that's covered by later tasks' integration test).
"""
from unittest.mock import patch, MagicMock


def test_catchall_pre_check_tags_target_when_parked():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls, \
         patch("yads.worker_tasks.tag_parked_domain") as mock_tag:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.return_value = None
        mock_scanner.run_scan.return_value = {"is_catch_all": True, "matched_signature": "sedo"}

        # Exercise via the actual helper if Task 5 extracts one, or via a
        # minimal reproduction of the block's logic — see Step 3's exact
        # code. Import and call whatever name Step 3 actually defines.
        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is True
        mock_tag.assert_called_once_with(session, 1, "sedo")


def test_catchall_pre_check_not_parked_does_not_tag():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls, \
         patch("yads.worker_tasks.tag_parked_domain") as mock_tag:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.return_value = None
        mock_scanner.run_scan.return_value = {"is_catch_all": False, "matched_signature": None}

        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is False
        mock_tag.assert_not_called()


def test_catchall_pre_check_uncertain_verdict_is_not_parked():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls, \
         patch("yads.worker_tasks.tag_parked_domain") as mock_tag:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.return_value = None
        mock_scanner.run_scan.return_value = {"is_catch_all": None, "matched_signature": None}

        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is False
        mock_tag.assert_not_called()


def test_catchall_pre_check_skipped_when_no_http():
    with patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls:
        from yads.worker_tasks import _check_parked_domain
        session = MagicMock()
        is_parked = _check_parked_domain(session, 1, "example.com", has_http=False, has_https=False)

        assert is_parked is False
        mock_scanner_cls.assert_not_called()


def test_run_parked_precheck_exception_does_not_propagate_and_treats_as_not_parked():
    """
    The pre-check block runs unconditionally on every scan (not gated on
    scan_types selection) inside run_all_scans. Before this fix, it had no
    try/except of its own — unlike every other module block in that
    function — so an exception here (DB error, network error, LLM
    classification failure) would abort the whole run_all_scans task
    before its heartbeat-stop code runs, wedging the target in "running"
    status. Confirms _run_parked_precheck now swallows the exception,
    rolls back, and fails safe to is_parked=False.
    """
    with patch("yads.worker_tasks._check_parked_domain", side_effect=RuntimeError("boom")):
        from yads.worker_tasks import _run_parked_precheck
        session = MagicMock()
        is_parked = _run_parked_precheck(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is False
        session.rollback.assert_called_once()


def test_run_parked_precheck_exception_in_catchall_process_does_not_propagate():
    """Same failure mode, but the exception comes from the
    CatchallDetectorScanner.process() call rather than _check_parked_domain."""
    with patch("yads.worker_tasks._check_parked_domain", return_value=False), \
         patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.side_effect = RuntimeError("boom")

        from yads.worker_tasks import _run_parked_precheck
        session = MagicMock()
        is_parked = _run_parked_precheck(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is False
        session.rollback.assert_called_once()


def test_run_parked_precheck_happy_path_still_returns_true_when_parked():
    with patch("yads.worker_tasks._check_parked_domain", return_value=True), \
         patch("yads.worker_tasks.CatchallDetectorScanner") as mock_scanner_cls:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.process.return_value = None

        from yads.worker_tasks import _run_parked_precheck
        session = MagicMock()
        is_parked = _run_parked_precheck(session, 1, "example.com", has_http=True, has_https=False)

        assert is_parked is True
        session.rollback.assert_not_called()
