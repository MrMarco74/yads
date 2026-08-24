from types import SimpleNamespace
import pytest
from yads.core.api_block_detection import (
    ApiBlockedError, detect_block, record_if_blocked, raise_if_blocked,
)
from yads.core.api_circuit_breaker import get_circuit_breaker


def _resp(status_code=200, text="", headers=None):
    return SimpleNamespace(status_code=status_code, text=text, headers=headers or {})


def test_detect_block_on_429():
    assert detect_block("some_service", _resp(status_code=429)) == 0


def test_detect_block_on_403():
    assert detect_block("some_service", _resp(status_code=403)) == 0


def test_detect_block_reads_retry_after_header():
    r = _resp(status_code=429, headers={"Retry-After": "42"})
    assert detect_block("some_service", r) == 42


def test_detect_block_none_on_normal_200():
    assert detect_block("some_service", _resp(status_code=200)) is None


def test_detect_block_hackertarget_quota_body():
    r = _resp(status_code=200, text="error check your search parameter API count exceeded")
    assert detect_block("hackertarget", r) == 0


def test_detect_block_ripestat_rate_body():
    r = _resp(status_code=200, text='{"status": "error", "messages": [["error", "Too many requests"]]}')
    assert detect_block("ripestat", r) == 0


def test_record_if_blocked_trips_breaker():
    get_circuit_breaker().clear("test_detect_service")
    assert record_if_blocked("test_detect_service", _resp(status_code=429)) is True
    assert get_circuit_breaker().is_blocked("test_detect_service") is True
    get_circuit_breaker().clear("test_detect_service")


def test_record_if_blocked_clears_breaker_on_success():
    cb = get_circuit_breaker()
    cb.record_block("test_detect_service_2")
    assert record_if_blocked("test_detect_service_2", _resp(status_code=200)) is False
    assert cb.is_blocked("test_detect_service_2") is False


def test_raise_if_blocked_raises_with_service_and_retry_after():
    get_circuit_breaker().clear("test_detect_service_3")
    r = _resp(status_code=429, headers={"Retry-After": "10"})
    with pytest.raises(ApiBlockedError) as exc_info:
        raise_if_blocked("test_detect_service_3", r)
    assert exc_info.value.service == "test_detect_service_3"
    assert exc_info.value.retry_after == 10
    get_circuit_breaker().clear("test_detect_service_3")


def test_raise_if_blocked_noop_on_normal_response():
    raise_if_blocked("test_detect_service_4", _resp(status_code=200))  # must not raise
