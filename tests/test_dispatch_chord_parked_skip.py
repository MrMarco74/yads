from unittest.mock import patch, MagicMock


def _mod(name, requires_http=False, requires_https=False):
    m = MagicMock()
    m.name = name
    m.requires_http = requires_http
    m.requires_https = requires_https
    return m


def test_parked_skips_content_app_analysis_modules():
    with patch("yads.worker_tasks.get_simple_dispatch_modules") as mock_get_mods, \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.run_scan_module") as mock_run_scan_module, \
         patch("yads.worker_tasks.finalize_scan") as mock_finalize:
        mock_get_mods.return_value = [
            _mod("tech_stack_analyzer"),
            _mod("form_discovery", requires_http=True),
            _mod("api_discovery", requires_http=True),
            _mod("graphql_scanner", requires_http=True),
            _mod("websocket_scanner", requires_http=True),
            _mod("login_scanner", requires_http=True),
            _mod("password_spray_mapper", requires_http=True),
            _mod("dependency_confusion"),  # not in PARKED_SKIP_MODULES — must still run
        ]
        mock_run_scan_module.s.return_value = "sig"
        mock_chord.return_value = MagicMock()

        from yads.worker_tasks import _dispatch_module_chord
        scan_types = [
            "tech_stack_analyzer", "form_discovery", "api_discovery",
            "graphql_scanner", "websocket_scanner", "login_scanner",
            "password_spray_mapper", "dependency_confusion",
        ]
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=scan_types, has_http=True, has_https=True,
            is_parked=True, scan_start_time=None,
        )

        dispatched_names = [call.args[2] for call in mock_run_scan_module.s.call_args_list]
        assert dispatched_names == ["dependency_confusion"]


def test_not_parked_dispatches_all_selected_modules():
    with patch("yads.worker_tasks.get_simple_dispatch_modules") as mock_get_mods, \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.run_scan_module") as mock_run_scan_module, \
         patch("yads.worker_tasks.finalize_scan"):
        mock_get_mods.return_value = [_mod("form_discovery", requires_http=True), _mod("dependency_confusion")]
        mock_run_scan_module.s.return_value = "sig"
        mock_chord.return_value = MagicMock()

        from yads.worker_tasks import _dispatch_module_chord
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=["form_discovery", "dependency_confusion"], has_http=True, has_https=True,
            is_parked=False, scan_start_time=None,
        )

        dispatched_names = [call.args[2] for call in mock_run_scan_module.s.call_args_list]
        assert set(dispatched_names) == {"form_discovery", "dependency_confusion"}


def test_parked_skip_module_set_matches_spec():
    from yads.worker_tasks import PARKED_SKIP_MODULES
    assert PARKED_SKIP_MODULES == {
        "tech_stack_analyzer", "form_discovery", "api_discovery",
        "graphql_scanner", "websocket_scanner", "login_scanner",
        "password_spray_mapper",
    }
