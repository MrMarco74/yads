"""
run_all_scans must probe HTTP/HTTPS reachability whenever a selected module
needs it. catchall_detector is custom_dispatch (excluded from
get_simple_dispatch_modules()), so its requires_http flag was invisible to the
web-precheck decision — leaving has_http/has_https False on a catchall-only
scan, which made the parked-domain tagging gate in _check_parked_domain
short-circuit and never tag. These pin the decision down.
"""


def test_catchall_only_scan_needs_web_precheck():
    """The regression: selecting only catchall_detector must still trigger the
    web pre-check, or parked-domain tagging can never fire."""
    from yads.worker_tasks import _scan_needs_web_precheck
    assert _scan_needs_web_precheck(["catchall_detector"]) is True


def test_web_analyzer_scan_needs_web_precheck():
    from yads.worker_tasks import _scan_needs_web_precheck
    assert _scan_needs_web_precheck(["web_analyzer"]) is True


def test_passive_non_web_scan_does_not_need_web_precheck():
    """A purely non-web module (no requires_http/https) must not force a probe."""
    from yads.worker_tasks import _scan_needs_web_precheck
    assert _scan_needs_web_precheck(["typosquat_scanner"]) is False
