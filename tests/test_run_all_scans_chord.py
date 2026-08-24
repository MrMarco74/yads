from unittest.mock import patch, MagicMock


def test_run_all_scans_dispatches_chord_with_one_task_per_module():
    with patch("yads.worker_tasks.get_simple_dispatch_modules") as mock_get_mods, \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.run_scan_module") as mock_run_scan_module, \
         patch("yads.worker_tasks.finalize_scan") as mock_finalize:
        # (The real run_all_scans has a lot of DB-dependent setup before
        # reaching the dispatch block; this test targets only the dispatch
        # section's behavior via a focused monkeypatch of get_simple_dispatch_modules
        # rather than driving the whole task end-to-end — full-path coverage
        # is the manual smoke test in Step 6.)
        mod_a = MagicMock(name="wayback_scanner")
        mod_a.name = "wayback_scanner"
        mod_a.requires_https = False
        mod_a.requires_http = False
        mock_get_mods.return_value = [mod_a]

        mock_run_scan_module.s.return_value = "sig-a"
        mock_chord_instance = MagicMock()
        mock_chord.return_value = mock_chord_instance

        from yads.worker_tasks import _dispatch_module_chord
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=["wayback_scanner"], has_http=True, has_https=True,
            is_parked=False, scan_start_time=None,
        )

        mock_run_scan_module.s.assert_called_once_with(1, "example.com", "wayback_scanner", 42)
        mock_chord.assert_called_once()
        mock_chord_instance.assert_called_once()
        mock_finalize.assert_not_called()


def test_run_all_scans_calls_finalize_directly_when_no_modules_selected():
    with patch("yads.worker_tasks.get_simple_dispatch_modules", return_value=[]), \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.finalize_scan") as mock_finalize:

        from yads.worker_tasks import _dispatch_module_chord
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=[], has_http=True, has_https=True,
            is_parked=False, scan_start_time=None,
        )

        mock_chord.assert_not_called()
        mock_finalize.assert_called_once()


def test_run_all_scans_skips_modules_needing_unavailable_https_or_http():
    with patch("yads.worker_tasks.get_simple_dispatch_modules") as mock_get_mods, \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.run_scan_module") as mock_run_scan_module, \
         patch("yads.worker_tasks.finalize_scan") as mock_finalize:
        mod_https = MagicMock()
        mod_https.name = "ssl_scanner"
        mod_https.requires_https = True
        mod_https.requires_http = False

        mod_http = MagicMock()
        mod_http.name = "web_analyzer"
        mod_http.requires_https = False
        mod_http.requires_http = True

        mock_get_mods.return_value = [mod_https, mod_http]

        mock_chord_instance = MagicMock()
        mock_chord.return_value = mock_chord_instance

        from yads.worker_tasks import _dispatch_module_chord
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=["ssl_scanner", "web_analyzer"], has_http=False, has_https=False,
            is_parked=False, scan_start_time=None,
        )

        # Neither module's dependency (HTTPS / HTTP) is available, so both
        # are skipped and no modules remain -> finalize_scan called directly.
        mock_run_scan_module.s.assert_not_called()
        mock_chord.assert_not_called()
        mock_finalize.assert_called_once()
