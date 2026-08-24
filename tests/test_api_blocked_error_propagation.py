"""
Integration-style regression test for the ApiBlockedError propagation gap.

Every other test that exercises the "block -> reschedule" mechanism injects
ApiBlockedError directly at the run_scan_module -> _run_parallel_module
boundary via mocking (see test_worker_modules_block_propagation.py,
test_run_scan_module.py). None of them ever go through a real module's real
HTTP-call helper or through the real BaseScannerModule.process(). That gap
is exactly what let a generic `except Exception` in every migrated module's
helper function silently swallow ApiBlockedError before it ever reached
run_scan_module.

This test closes that gap: it mocks only the underlying HTTP call (via
`responses`) and exercises AsnScanner's real _ipinfo() -> run_scan() ->
process() chain, asserting ApiBlockedError actually propagates out.
"""
import pytest
import responses
from unittest.mock import MagicMock

from yads.core.api_block_detection import ApiBlockedError
from yads.core.api_circuit_breaker import get_circuit_breaker
from yads.core import throttled_http
from yads.core.throttled_http import ThrottledSession
from yads.modules.asn_scanner import AsnScanner


@pytest.fixture(autouse=True)
def _clean():
    get_circuit_breaker().clear("ipinfo")
    yield
    get_circuit_breaker().clear("ipinfo")


@pytest.fixture(autouse=True)
def _fast_throttled_session(monkeypatch):
    """
    AsnScanner calls the module-level throttled_get() convenience function,
    which uses a lazily-created global ThrottledSession with the real
    per-domain rate limiter and bandwidth limiter enabled. Swap in a session
    with both disabled so the test doesn't depend on Redis-backed rate
    limiting timing -- this only touches throttling/bandwidth bookkeeping,
    not the block-detection/circuit-breaker path this test is verifying.
    """
    fast_session = ThrottledSession(use_rate_limiter=False, use_bandwidth_limiter=False)
    monkeypatch.setattr(throttled_http, "_throttled_session", fast_session)


def _mock_ipinfo_429():
    responses.add(
        responses.GET,
        "https://ipinfo.io/93.184.216.34/json",
        status=429,
    )


@responses.activate
def test_asn_scanner_run_scan_propagates_api_blocked_error(monkeypatch):
    """The real _ipinfo() helper must not swallow ApiBlockedError."""
    _mock_ipinfo_429()
    monkeypatch.setattr(
        "yads.modules.asn_scanner._resolve_ips", lambda domain: ["93.184.216.34"]
    )

    scanner = AsnScanner(db_session=MagicMock())

    with pytest.raises(ApiBlockedError):
        scanner.run_scan("example.com")


@responses.activate
def test_asn_scanner_process_propagates_api_blocked_error(monkeypatch):
    """
    The shared BaseScannerModule.process() chokepoint must also not
    swallow ApiBlockedError. A MagicMock db_session is safe here because
    the exception is raised (and re-raised) before process() touches
    self.db at all.
    """
    _mock_ipinfo_429()
    monkeypatch.setattr(
        "yads.modules.asn_scanner._resolve_ips", lambda domain: ["93.184.216.34"]
    )

    scanner = AsnScanner(db_session=MagicMock())

    with pytest.raises(ApiBlockedError):
        scanner.process(target_id=1, target_domain="example.com")
