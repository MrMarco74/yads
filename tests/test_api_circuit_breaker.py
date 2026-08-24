import time
import pytest
from yads.database import redis_client
from yads.core.api_circuit_breaker import ApiCircuitBreaker, get_circuit_breaker

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _clean_redis():
    for key in redis_client.keys("circuit:*:test_service*"):
        redis_client.delete(key)
    yield
    for key in redis_client.keys("circuit:*:test_service*"):
        redis_client.delete(key)


def test_not_blocked_by_default():
    cb = ApiCircuitBreaker()
    assert cb.is_blocked("test_service") is False


def test_record_block_sets_blocked():
    cb = ApiCircuitBreaker()
    cb.record_block("test_service")
    assert cb.is_blocked("test_service") is True


def test_record_block_uses_retry_after_when_given():
    cb = ApiCircuitBreaker()
    cooldown = cb.record_block("test_service", retry_after=2)
    assert cooldown == 2
    assert cb.is_blocked("test_service") is True
    time.sleep(2.2)
    assert cb.is_blocked("test_service") is False


def test_repeated_block_doubles_cooldown_up_to_cap():
    cb = ApiCircuitBreaker()
    first = cb.record_block("test_service")
    assert first == 300  # 5 minute floor
    second = cb.record_block("test_service")
    assert second == 600
    third = cb.record_block("test_service")
    assert third == 1200


def test_clear_resets_cooldown_to_floor():
    cb = ApiCircuitBreaker()
    cb.record_block("test_service")
    cb.record_block("test_service")
    cb.clear("test_service")
    assert cb.is_blocked("test_service") is False
    cooldown = cb.record_block("test_service")
    assert cooldown == 300


def test_get_circuit_breaker_returns_singleton():
    assert get_circuit_breaker() is get_circuit_breaker()


def test_is_blocked_fails_open_on_redis_error(monkeypatch):
    cb = ApiCircuitBreaker()

    class _Boom:
        def get(self, *a, **kw):
            raise ConnectionError("redis down")

    monkeypatch.setattr(cb, "_redis", _Boom())
    assert cb.is_blocked("test_service") is False
