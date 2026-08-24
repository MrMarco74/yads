import pytest
from yads.database import redis_client
from yads.core.module_status import (
    mark_rate_limited, clear_rate_limited, is_rate_limited, get_rate_limited_module_count,
)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _clean():
    for key in redis_client.keys("yads:module_status:test_*"):
        redis_client.delete(key)
    yield
    for key in redis_client.keys("yads:module_status:test_*"):
        redis_client.delete(key)


def test_not_rate_limited_by_default():
    assert is_rate_limited(999999, "test_module") is False


def test_mark_and_check_rate_limited():
    mark_rate_limited(999999, "test_module", ttl_seconds=60)
    assert is_rate_limited(999999, "test_module") is True


def test_clear_rate_limited():
    mark_rate_limited(999999, "test_module", ttl_seconds=60)
    clear_rate_limited(999999, "test_module")
    assert is_rate_limited(999999, "test_module") is False


def test_get_rate_limited_module_count_reflects_marked_keys():
    before = get_rate_limited_module_count()
    mark_rate_limited(999999, "test_module_a", ttl_seconds=60)
    mark_rate_limited(999999, "test_module_b", ttl_seconds=60)
    after = get_rate_limited_module_count()
    assert after == before + 2
    clear_rate_limited(999999, "test_module_a")
    clear_rate_limited(999999, "test_module_b")
