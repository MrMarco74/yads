import pytest
import responses  # already a transitive dep via requests test tooling; if missing, use requests_mock instead — check requirements-test.txt first
from yads.core.throttled_http import ThrottledSession
from yads.core.api_block_detection import ApiBlockedError
from yads.core.api_circuit_breaker import get_circuit_breaker


@pytest.fixture(autouse=True)
def _clean():
    get_circuit_breaker().clear("test_throttle_service")
    yield
    get_circuit_breaker().clear("test_throttle_service")


@responses.activate
def test_request_raises_on_429():
    responses.add(responses.GET, "https://example.com/x", status=429)
    session = ThrottledSession(use_rate_limiter=False, use_bandwidth_limiter=False)
    with pytest.raises(ApiBlockedError):
        session.request("GET", "https://example.com/x", service="test_throttle_service")


@responses.activate
def test_request_skips_network_call_when_already_blocked():
    get_circuit_breaker().record_block("test_throttle_service")
    session = ThrottledSession(use_rate_limiter=False, use_bandwidth_limiter=False)
    with pytest.raises(ApiBlockedError):
        session.request("GET", "https://example.com/x", service="test_throttle_service")
    assert len(responses.calls) == 0


@responses.activate
def test_request_passes_through_on_200():
    responses.add(responses.GET, "https://example.com/x", status=200, body="ok")
    session = ThrottledSession(use_rate_limiter=False, use_bandwidth_limiter=False)
    resp = session.request("GET", "https://example.com/x", service="test_throttle_service")
    assert resp.status_code == 200


@responses.activate
def test_request_without_service_is_unaffected():
    responses.add(responses.GET, "https://example.com/x", status=429)
    session = ThrottledSession(use_rate_limiter=False, use_bandwidth_limiter=False)
    resp = session.request("GET", "https://example.com/x")  # no service kwarg
    assert resp.status_code == 429  # no ApiBlockedError raised
