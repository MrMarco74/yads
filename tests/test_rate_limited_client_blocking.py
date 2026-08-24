import pytest
import responses
from yads.modules._shared_osint_utils import RateLimitedClient
from yads.core.api_block_detection import ApiBlockedError
from yads.core.api_circuit_breaker import get_circuit_breaker


@pytest.fixture(autouse=True)
def _clean():
    get_circuit_breaker().clear("test_osint_service")
    yield
    get_circuit_breaker().clear("test_osint_service")


@responses.activate
def test_get_raises_on_429():
    responses.add(responses.GET, "https://example.com/x", status=429)
    client = RateLimitedClient()
    client.register_service("test_osint_service", requests_per_second=100)
    with pytest.raises(ApiBlockedError):
        client.get("test_osint_service", "https://example.com/x")


@responses.activate
def test_get_skips_network_call_when_already_blocked():
    get_circuit_breaker().record_block("test_osint_service")
    client = RateLimitedClient()
    client.register_service("test_osint_service", requests_per_second=100)
    with pytest.raises(ApiBlockedError):
        client.get("test_osint_service", "https://example.com/x")
    assert len(responses.calls) == 0


@responses.activate
def test_get_passes_through_on_200():
    responses.add(responses.GET, "https://example.com/x", status=200, body="ok")
    client = RateLimitedClient()
    client.register_service("test_osint_service", requests_per_second=100)
    resp = client.get("test_osint_service", "https://example.com/x")
    assert resp.status_code == 200
