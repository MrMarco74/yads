import responses
from yads.core.api_circuit_breaker import get_circuit_breaker


@responses.activate
def test_shodan_query_marks_rate_limited_on_429(monkeypatch):
    from yads.modules.shodan_censys_scanner import ShodanCensysScanner
    monkeypatch.setattr(
        "yads.modules.shodan_censys_scanner.get_api_rate_limiter",
        lambda: type("_L", (), {"acquire": staticmethod(lambda *a, **kw: True)})(),
    )
    responses.add(responses.GET, "https://api.shodan.io/shodan/host/1.2.3.4", status=429)
    get_circuit_breaker().clear("shodan")

    scanner = ShodanCensysScanner.__new__(ShodanCensysScanner)  # bypass __init__ (needs db_session)
    scanner.SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
    scanner.REQUEST_TIMEOUT = 5
    result = scanner._query_shodan("1.2.3.4", "example.com", "fake-key")

    assert result["status"] == "rate_limited"
    assert get_circuit_breaker().is_blocked("shodan") is True
    get_circuit_breaker().clear("shodan")


@responses.activate
def test_threat_intel_abuseipdb_marks_rate_limited_on_429(monkeypatch):
    from yads.modules.threat_intel_scanner import ThreatIntelScanner
    monkeypatch.setattr(
        "yads.modules.threat_intel_scanner.get_api_rate_limiter",
        lambda: type("_L", (), {"acquire": staticmethod(lambda *a, **kw: True)})(),
    )
    responses.add(responses.GET, "https://api.abuseipdb.com/api/v2/check", status=429)
    get_circuit_breaker().clear("abuseipdb")

    scanner = ThreatIntelScanner.__new__(ThreatIntelScanner)
    result = scanner._query_abuseipdb("1.2.3.4", "fake-key")

    assert result["status"] == "rate_limited"
    assert get_circuit_breaker().is_blocked("abuseipdb") is True
    get_circuit_breaker().clear("abuseipdb")
