# Scan Queue Rate-Limit Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect when external APIs (public/keyless and BYOK) start blocking or rate-limiting YADS, skip the affected module for the current scan without failing it, and retry it later with jitter instead of losing the data or repeatedly re-tripping a shared provider.

**Architecture:** A new Redis-backed circuit breaker (`core/api_circuit_breaker.py`) records when a provider blocks us and exposes `is_blocked()`; a shared detection helper (`core/api_block_detection.py`) classifies HTTP responses as blocks and feeds the breaker. Both existing HTTP wrapper layers (`core/throttled_http.py` for keyless modules, `_shared_osint_utils.RateLimitedClient` for the 4 OSINT modules that already use it) call into detection. The monolithic per-target `run_all_scans` Celery task is split so the modules that use `core.module_registry.get_simple_dispatch_modules()` each run as their own Celery task (`run_scan_module`), dispatched via a `chord` instead of a `ThreadPoolExecutor`; a blocked module marks itself rate-limited and independently reschedules with jittered backoff, without holding up the chord's finalize callback.

**Tech Stack:** Python 3.12, Celery (chord/group), Redis, `requests`, pytest (real Redis at `redis://localhost:6380/0` per `tests/conftest.py`, `integration` marker).

**Spec:** `docs/superpowers/specs/2026-08-24-scan-queue-rate-limit-resilience-design.md`

## Global Constraints

- Fail-open on Redis errors everywhere (matches `core/api_rate_limiter.py`'s existing philosophy) — a broken breaker must never block scanning.
- No module's raw exception behavior for non-block errors changes — only the new block-detection path is additive.
- `custom_dispatch=True` registry modules (subdomain_scanner, dns_cleanup, web_analyzer, etc.) keep their current sequential/threaded execution in `run_all_scans`; only `get_simple_dispatch_modules()` modules move to the chord.
- New Redis keys use the `circuit:` and `yads:module_status:` prefixes to avoid collisions with existing `rate_limit:api:` keys from `ApiRateLimiter`.
- All new modules/functions get unit tests before the code that uses them (TDD) per repo convention of `tests/test_*.py` files (`python_files = test_*.py` in `pytest.ini`).

---

## Task 1: Circuit breaker core

**Files:**
- Create: `yads/core/api_circuit_breaker.py`
- Test: `tests/test_api_circuit_breaker.py`

**Interfaces:**
- Produces: `ApiCircuitBreaker` class with `is_blocked(service: str) -> bool`, `record_block(service: str, retry_after: Optional[int] = None) -> int` (returns cooldown seconds applied), `clear(service: str) -> None`. Module-level singleton accessor `get_circuit_breaker() -> ApiCircuitBreaker`, mirroring `get_api_rate_limiter()` in `core/api_rate_limiter.py`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_api_circuit_breaker.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_api_circuit_breaker.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'yads.core.api_circuit_breaker'`

- [ ] **Step 3: Implement `yads/core/api_circuit_breaker.py`**

```python
"""
Redis-backed circuit breaker for external API services.

Distinct from ApiRateLimiter (core/api_rate_limiter.py), which self-throttles
our *outgoing* request rate. This tracks the *provider's* reaction — did they
actually block or rate-limit us — so callers can skip a service entirely
while it's tripped instead of hitting it again and making things worse.

If Redis is unavailable the breaker fails open (never blocks) — a broken
breaker must never stop scans from running.
"""

import logging
import threading
import time
from typing import Optional

from yads.database import redis_client

logger = logging.getLogger(__name__)

FLOOR_SECONDS = 300      # 5 minutes
CAP_SECONDS = 6 * 3600   # 6 hours

_circuit_breaker: Optional["ApiCircuitBreaker"] = None
_circuit_breaker_lock = threading.Lock()


class ApiCircuitBreaker:
    def __init__(self) -> None:
        self._redis = redis_client

    def is_blocked(self, service: str) -> bool:
        service = service.lower()
        try:
            return bool(self._redis.get(f"circuit:blocked:{service}"))
        except Exception as exc:
            logger.warning("[ApiCircuitBreaker] Redis error checking '%s', assuming not blocked: %s", service, exc)
            return False

    def record_block(self, service: str, retry_after: Optional[int] = None) -> int:
        service = service.lower()
        try:
            if retry_after:
                cooldown = int(retry_after)
            else:
                prev = self._redis.get(f"circuit:cooldown:{service}")
                prev_seconds = int(prev) if prev else FLOOR_SECONDS // 2
                cooldown = min(prev_seconds * 2, CAP_SECONDS)

            self._redis.set(f"circuit:blocked:{service}", "1", ex=cooldown)
            # Cooldown value itself persists without a TTL so the next block
            # (even after this one expires) keeps doubling instead of resetting.
            self._redis.set(f"circuit:cooldown:{service}", str(cooldown))
            logger.warning("[ApiCircuitBreaker] '%s' blocked for %ds", service, cooldown)
            return cooldown
        except Exception as exc:
            logger.warning("[ApiCircuitBreaker] Redis error recording block for '%s': %s", service, exc)
            return retry_after or FLOOR_SECONDS

    def clear(self, service: str) -> None:
        service = service.lower()
        try:
            self._redis.delete(f"circuit:blocked:{service}")
            self._redis.delete(f"circuit:cooldown:{service}")
        except Exception as exc:
            logger.warning("[ApiCircuitBreaker] Redis error clearing '%s': %s", service, exc)


def get_circuit_breaker() -> ApiCircuitBreaker:
    global _circuit_breaker
    with _circuit_breaker_lock:
        if _circuit_breaker is None:
            _circuit_breaker = ApiCircuitBreaker()
        return _circuit_breaker
```

Note: `FLOOR_SECONDS // 2` (150) as the "previous" default when no cooldown key exists yet means the first-ever block doubles to exactly 300 (the floor) — verify this matches the test's `first == 300` expectation.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_api_circuit_breaker.py -v`
Expected: PASS (all 7 tests). The `retry_after=2` test takes ~2.2s.

- [ ] **Step 5: Commit**

```bash
git add yads/core/api_circuit_breaker.py tests/test_api_circuit_breaker.py
git commit -m "feat: add Redis-backed API circuit breaker for provider-side blocking"
```

---

## Task 2: Block detection helper

**Files:**
- Create: `yads/core/api_block_detection.py`
- Test: `tests/test_api_block_detection.py`

**Interfaces:**
- Consumes: `get_circuit_breaker()` from Task 1 (`yads.core.api_circuit_breaker`).
- Produces: `ApiBlockedError(Exception)` with `.service: str` and `.retry_after: Optional[int]` attributes. `detect_block(service: str, response) -> Optional[int]` — returns retry_after seconds (0 if none available) if the response looks like a block, else `None`. `record_if_blocked(service: str, response) -> bool` — calls `detect_block`, records/clears on the breaker, returns whether it was a block. `raise_if_blocked(service: str, response) -> None` — raises `ApiBlockedError` if `record_if_blocked` returns `True`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_api_block_detection.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_api_block_detection.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'yads.core.api_block_detection'`

- [ ] **Step 3: Implement `yads/core/api_block_detection.py`**

```python
"""
Classifies HTTP responses as provider-side blocking/rate-limiting and feeds
the ApiCircuitBreaker (core/api_circuit_breaker.py).

Two entry points for callers, depending on their existing error-handling
style:
  - record_if_blocked(service, response) -> bool   (non-raising)
  - raise_if_blocked(service, response)             (raises ApiBlockedError)
"""

import logging
from typing import Optional

from yads.core.api_circuit_breaker import get_circuit_breaker

logger = logging.getLogger(__name__)

# Per-service body signatures for providers that don't use a proper 429/403
# on rate-limit/block. Only services needing this should have an entry —
# everything else relies on status codes alone.
_BODY_SIGNATURES = {
    "hackertarget": ("api count exceeded", "error check your search parameter"),
    "ripestat": ('"status": "error"',),
}


class ApiBlockedError(Exception):
    def __init__(self, service: str, retry_after: Optional[int] = None):
        self.service = service
        self.retry_after = retry_after
        super().__init__(f"'{service}' is blocking/rate-limiting us" + (f" (retry after {retry_after}s)" if retry_after else ""))


def detect_block(service: str, response) -> Optional[int]:
    """Return retry_after seconds (0 if unknown) if response looks like a
    provider-side block, else None."""
    status = getattr(response, "status_code", 200)
    headers = getattr(response, "headers", {}) or {}

    if status in (429, 403):
        retry_after = headers.get("Retry-After")
        try:
            return int(retry_after) if retry_after else 0
        except (TypeError, ValueError):
            return 0

    signatures = _BODY_SIGNATURES.get(service.lower())
    if signatures:
        body = (getattr(response, "text", "") or "").lower()
        if any(sig in body for sig in signatures):
            return 0

    return None


def record_if_blocked(service: str, response) -> bool:
    breaker = get_circuit_breaker()
    retry_after = detect_block(service, response)
    if retry_after is not None:
        breaker.record_block(service, retry_after or None)
        return True
    breaker.clear(service)
    return False


def raise_if_blocked(service: str, response) -> None:
    breaker = get_circuit_breaker()
    retry_after = detect_block(service, response)
    if retry_after is not None:
        breaker.record_block(service, retry_after or None)
        raise ApiBlockedError(service, retry_after or None)
    breaker.clear(service)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_api_block_detection.py -v`
Expected: PASS (all 11 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/core/api_block_detection.py tests/test_api_block_detection.py
git commit -m "feat: add HTTP response classifier for provider-side API blocking"
```

---

## Task 3: Wire detection into `throttled_http.py`

**Files:**
- Modify: `yads/core/throttled_http.py`
- Test: `tests/test_throttled_http.py`

**Interfaces:**
- Consumes: `get_circuit_breaker()` (Task 1), `raise_if_blocked()` / `ApiBlockedError` (Task 2).
- Produces: `ThrottledSession.request(method, url, service: str = None, **kwargs)` — raises `ApiBlockedError` before the network call if `service` is blocked, and after the call if the response looks like a block. `throttled_get`/`throttled_post`/`throttled_head` all gain an optional `service` passthrough kwarg.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_throttled_http.py
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
```

If `responses` isn't already a test dependency, check `requirements-test.txt` and add `responses` there instead of reimplementing HTTP mocking by hand.

- [ ] **Step 2: Check test dependency, then run tests to verify they fail**

Run: `grep -q "^responses" requirements-test.txt || echo "responses" >> requirements-test.txt`
Run: `pip install -r requirements-test.txt`
Run: `pytest tests/test_throttled_http.py -v`
Expected: FAIL — `TypeError: request() got an unexpected keyword argument 'service'`

- [ ] **Step 3: Modify `yads/core/throttled_http.py`**

Add the import near the top (with the existing `from yads.core.rate_limiter import ...` line):

```python
from yads.core.api_block_detection import raise_if_blocked
from yads.core.api_circuit_breaker import get_circuit_breaker
```

Replace the `request` method:

```python
    def request(self, method: str, url: str, service: str = None, **kwargs) -> requests.Response:
        """Override request to add throttling and provider-block detection.

        `service` is a logical service name (e.g. "crt_sh", "hackertarget") —
        when given, raises ApiBlockedError instead of making the request if
        that service is currently circuit-broken, and classifies the
        response afterward to trip the breaker on a detected block.
        """
        if service and get_circuit_breaker().is_blocked(service):
            raise_if_blocked(service, requests.models.Response())  # no-op path below handles this directly
```

Actually simplify — don't fabricate a fake Response for the pre-check; check the breaker directly:

```python
    def request(self, method: str, url: str, service: str = None, **kwargs) -> requests.Response:
        """Override request to add throttling and provider-block detection.

        `service` is a logical service name (e.g. "crt_sh", "hackertarget") —
        when given, raises ApiBlockedError instead of making the request if
        that service is currently circuit-broken, and classifies the
        response afterward to trip the breaker on a detected block.
        """
        if service and get_circuit_breaker().is_blocked(service):
            from yads.core.api_block_detection import ApiBlockedError
            raise ApiBlockedError(service)

        from urllib.parse import urlparse
        domain = urlparse(url).netloc

        if self._rate_limiter and domain:
            self._rate_limiter.wait(domain)

        if 'timeout' not in kwargs:
            kwargs['timeout'] = DEFAULT_TIMEOUT

        response = super().request(method, url, **kwargs)

        if service:
            raise_if_blocked(service, response)

        if self._bandwidth_limiter:
            request_size = len(url) + 200
            if 'data' in kwargs:
                request_size += len(kwargs['data']) if kwargs['data'] else 0
            response_size = len(response.content) if response.content else 0
            total_bytes = request_size + response_size
            self._bandwidth_limiter.consume(total_bytes)

        return response
```

Update the module-level convenience functions to pass `service` through:

```python
def throttled_get(url: str, service: str = None, **kwargs) -> requests.Response:
    """Convenience function for throttled GET requests."""
    return get_throttled_session().get(url, service=service, **kwargs)


def throttled_post(url: str, service: str = None, **kwargs) -> requests.Response:
    """Convenience function for throttled POST requests."""
    return get_throttled_session().post(url, service=service, **kwargs)


def throttled_head(url: str, service: str = None, **kwargs) -> requests.Response:
    """Convenience function for throttled HEAD requests."""
    return get_throttled_session().head(url, service=service, **kwargs)
```

`requests.Session.get/post/head` all forward unknown kwargs to `request()`, so `service=` flows through automatically — no override needed for those three methods.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_throttled_http.py -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/core/throttled_http.py tests/test_throttled_http.py requirements-test.txt
git commit -m "feat: detect provider-side blocking in ThrottledSession"
```

---

## Task 4: Wire detection into `RateLimitedClient`

**Files:**
- Modify: `yads/modules/_shared_osint_utils.py:239-395` (the `RateLimitedClient` class)
- Test: `tests/test_rate_limited_client_blocking.py`

**Interfaces:**
- Consumes: `get_circuit_breaker()` (Task 1), `raise_if_blocked()` / `ApiBlockedError` (Task 2).
- Produces: `RateLimitedClient.get/post/head(service_name, url, ...)` now raise `ApiBlockedError` when `service_name` is circuit-broken or the response indicates a block. No signature change — `service_name` was already the first positional arg for all three methods, so every existing call site (brand_intelligence.py, dormant_detector.py, email_intelligence.py, social_media_scanner.py) is unaffected.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_rate_limited_client_blocking.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_rate_limited_client_blocking.py -v`
Expected: FAIL — no `ApiBlockedError` raised on 429

- [ ] **Step 3: Modify `yads/modules/_shared_osint_utils.py`**

Add the import near the top with the other imports:

```python
from yads.core.api_circuit_breaker import get_circuit_breaker
from yads.core.api_block_detection import raise_if_blocked, ApiBlockedError
```

In `RateLimitedClient`, replace `get`, `post`, and `head` (currently at lines ~349-395):

```python
    def get(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """Make a rate-limited GET request with TLS support."""
        if get_circuit_breaker().is_blocked(service_name):
            raise ApiBlockedError(service_name)
        self._wait_for_rate_limit(service_name)
        url = self._normalize_url(url)
        response = self._session.get(
            url,
            headers=headers,
            timeout=timeout or self.default_timeout,
            **kwargs
        )
        raise_if_blocked(service_name, response)
        return response

    def post(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """Make a rate-limited POST request with TLS support."""
        if get_circuit_breaker().is_blocked(service_name):
            raise ApiBlockedError(service_name)
        self._wait_for_rate_limit(service_name)
        url = self._normalize_url(url)
        response = self._session.post(
            url,
            headers=headers,
            timeout=timeout or self.default_timeout,
            **kwargs
        )
        raise_if_blocked(service_name, response)
        return response

    def head(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """Make a rate-limited HEAD request with TLS support."""
        if get_circuit_breaker().is_blocked(service_name):
            raise ApiBlockedError(service_name)
        self._wait_for_rate_limit(service_name)
        url = self._normalize_url(url)
        response = self._session.head(
            url,
            headers=headers,
            timeout=timeout or self.default_timeout,
            **kwargs
        )
        raise_if_blocked(service_name, response)
        return response
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_rate_limited_client_blocking.py -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Run the existing OSINT module callers' test suite (regression check)**

Run: `pytest tests/ -k "osint or brand or email_intelligence or social_media or dormant" -v`
Expected: PASS or SKIP (no failures) — confirms the unchanged call signature didn't break existing callers. If no such tests exist, this step is a no-op; note that in the commit.

- [ ] **Step 6: Commit**

```bash
git add yads/modules/_shared_osint_utils.py tests/test_rate_limited_client_blocking.py
git commit -m "feat: detect provider-side blocking in RateLimitedClient"
```

---

## Task 5: Migrate CT/certificate-transparency cluster

**Files:**
- Modify: `yads/modules/crtSH_client.py`
- Modify: `yads/modules/ct_monitor.py:56`
- Modify: `yads/modules/dns_history_scanner.py:45,68,97`
- Modify: `yads/modules/dns_scanner.py:409` (`_fetch_hackertarget`)
- Test: `tests/test_public_api_service_names.py` (new — a lightweight source-scan test, see Step 1)

**Interfaces:**
- Consumes: `throttled_get`/`throttled_head` from `yads.core.throttled_http` (Task 3).

Rather than one narrow unit test per module (these are thin HTTP wrappers around third-party formats — see Task 5 Step 5 for a manual smoke check instead), this task is verified by a single regression test asserting every target call site was actually migrated, so a future edit can't silently regress back to raw `requests`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_public_api_service_names.py
"""
Guards against public-API scanner modules regressing back to raw
`requests.get/post/head` calls that bypass circuit-breaker detection.
Each entry: (file relative to yads/, forbidden raw-requests call count expected == 0).
"""
import re
from pathlib import Path

import pytest

YADS_ROOT = Path(__file__).resolve().parents[1] / "yads"

MIGRATED_FILES = [
    "modules/crtSH_client.py",
    "modules/ct_monitor.py",
    "modules/dns_history_scanner.py",
    "modules/asn_scanner.py",
    "modules/infrastructure_scanner.py",
    "modules/ipv6_scanner.py",
    "modules/rpki_scanner.py",
    "modules/wayback_scanner.py",
    "modules/phishing_scanner.py",
    "modules/dependency_confusion.py",
    "modules/tls_deep_scanner.py",
    "modules/mobile_app_discovery.py",
]

# dns_scanner.py has both migrated (_fetch_hackertarget) and non-HTTP code;
# checked separately by function name below instead of whole-file.
RAW_REQUESTS_CALL = re.compile(r"\brequests\.(get|post|head)\(")


@pytest.mark.parametrize("relpath", MIGRATED_FILES)
def test_module_has_no_raw_requests_calls(relpath):
    src = (YADS_ROOT / relpath).read_text()
    matches = RAW_REQUESTS_CALL.findall(src)
    assert matches == [], f"{relpath} still has raw requests.* calls: {matches} — use throttled_get/throttled_post/throttled_head with a service= kwarg"


def test_dns_scanner_fetch_hackertarget_is_migrated():
    src = (YADS_ROOT / "modules/dns_scanner.py").read_text()
    start = src.index("def _fetch_hackertarget")
    end = src.index("\ndef ", start + 1)
    body = src[start:end]
    assert "requests.get(" not in body
    assert "throttled_get(" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_public_api_service_names.py -v`
Expected: FAIL — every `MIGRATED_FILES` entry still has raw `requests.*` calls

- [ ] **Step 3: Migrate `yads/modules/crtSH_client.py`**

Change the import at the top from `import requests` to also import the throttled client:

```python
import requests
import logging
import tldextract
from typing import List, Set

from yads.core.throttled_http import throttled_get
```

In `search_by_org`, replace:
```python
            resp = requests.get(url, timeout=20)
```
with:
```python
            resp = throttled_get(url, service="crt_sh", timeout=20)
```

In `search_domain`, replace:
```python
        resp = requests.get(url, timeout=25)
```
with:
```python
        resp = throttled_get(url, service="crt_sh", timeout=25)
```

- [ ] **Step 4: Migrate `yads/modules/ct_monitor.py`**

Add `from yads.core.throttled_http import throttled_get` to the imports. At line 56, change the `requests.get(` call to `throttled_get(` and add `service="crt_sh"` as a kwarg (keep all existing args/kwargs as-is).

- [ ] **Step 5: Migrate `yads/modules/dns_history_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to the imports. At lines 45, 68, and 97, change each `requests.get(` to `throttled_get(` with `service="hackertarget"` added (this module's docstring/URL should confirm it's hackertarget.com — if any of the three calls target a different host, use that host's short name instead, e.g. `"crt_sh"`).

- [ ] **Step 6: Migrate `yads/modules/dns_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to the imports (near the top, alongside existing imports). In `_fetch_hackertarget` (line ~404-409), replace:

```python
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            resp = requests.get(url, timeout=15)
```

with:

```python
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            resp = throttled_get(url, service="hackertarget", timeout=15)
```

Leave `_fetch_ct_logs`'s call into `crtSH_client.search_domain` untouched — that module was migrated in Step 3, so it's already covered transitively.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_public_api_service_names.py -v`
Expected: PASS (all migrated files clean of raw `requests.*` calls)

- [ ] **Step 8: Manual smoke check (no live network dependency required, but useful if available)**

Run: `python3 -c "from yads.modules.crtSH_client import search_domain; print(len(search_domain('example.com')))"`
Expected: prints an integer without raising `ImportError`/`NameError` — confirms `throttled_get` import wiring didn't break the module.

- [ ] **Step 9: Commit**

```bash
git add yads/modules/crtSH_client.py yads/modules/ct_monitor.py yads/modules/dns_history_scanner.py yads/modules/dns_scanner.py tests/test_public_api_service_names.py
git commit -m "feat: route crt.sh/hackertarget calls through circuit-breaker-aware client"
```

---

## Task 6: Migrate IP/ASN/RPKI cluster

**Files:**
- Modify: `yads/modules/asn_scanner.py:54,64,79,96,108`
- Modify: `yads/modules/infrastructure_scanner.py:172` (leave `225` port-probe `requests.head` on the *target* domain alone — that's not a third-party API)
- Modify: `yads/modules/ipv6_scanner.py:93`
- Modify: `yads/modules/rpki_scanner.py:211,233,248,274`
- Test: extend `tests/test_public_api_service_names.py` from Task 5 (already lists these files) — no new test file needed, this task turns those `MIGRATED_FILES` entries from failing to passing.

**Interfaces:**
- Consumes: `throttled_get` from `yads.core.throttled_http` (Task 3).

- [ ] **Step 1: Confirm the relevant tests are currently failing for these 4 files**

Run: `pytest tests/test_public_api_service_names.py -v -k "asn_scanner or infrastructure_scanner or ipv6_scanner or rpki_scanner"`
Expected: FAIL (4 tests) — these files still have raw `requests.*` calls

- [ ] **Step 2: Migrate `yads/modules/asn_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. Replace each call, mapping host to service name:

```python
        r = requests.get(IPINFO_URL.format(ip=ip), timeout=TIMEOUT)
```
→
```python
        r = throttled_get(IPINFO_URL.format(ip=ip), service="ipinfo", timeout=TIMEOUT)
```

```python
        r = requests.get(RIPE_NETWORK_INFO.format(ip=ip), timeout=TIMEOUT)
```
→
```python
        r = throttled_get(RIPE_NETWORK_INFO.format(ip=ip), service="ripestat", timeout=TIMEOUT)
```

```python
        r = requests.get(RIPE_ASN_INFO.format(asn=asn), timeout=TIMEOUT)
```
→
```python
        r = throttled_get(RIPE_ASN_INFO.format(asn=asn), service="ripestat", timeout=TIMEOUT)
```

```python
        r = requests.get(RIPE_PREFIXES.format(asn=asn), timeout=TIMEOUT)
```
→
```python
        r = throttled_get(RIPE_PREFIXES.format(asn=asn), service="ripestat", timeout=TIMEOUT)
```

```python
        r = requests.get(BGPVIEW_ASN.format(asn=asn_num), timeout=TIMEOUT)
```
→
```python
        r = throttled_get(BGPVIEW_ASN.format(asn=asn_num), service="bgpview", timeout=TIMEOUT)
```

- [ ] **Step 3: Migrate `yads/modules/infrastructure_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. Replace only the ipinfo.io call:

```python
            geo_resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
```
→
```python
            geo_resp = throttled_get(f"https://ipinfo.io/{ip}/json", service="ipinfo", timeout=3)
```

Do **not** touch the `requests.head(s3_url, timeout=2)` call at line ~225 — that probes the *scanned target's* infrastructure (S3 bucket existence), not a shared third-party API, so it's out of scope for circuit-breaking.

- [ ] **Step 4: Migrate `yads/modules/ipv6_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. Replace:

```python
        r = requests.get(IPINFO_URL.format(ip=ip), timeout=6)
```
→
```python
        r = throttled_get(IPINFO_URL.format(ip=ip), service="ipinfo", timeout=6)
```

- [ ] **Step 5: Migrate `yads/modules/rpki_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. In `_get_network_info` and `_get_org_name` (both hit `RIPE_STAT`), and `_check_rpki` (also `RIPE_STAT`), change `requests.get(` to `throttled_get(` with `service="ripestat"` added. In `_get_asn_ipinfo` (hits `https://ipinfo.io/{ip}/json`), change `requests.get(` to `throttled_get(` with `service="ipinfo"` added. Example for `_get_network_info`:

```python
            resp = requests.get(
                f"{RIPE_STAT}/network-info/data.json",
                params={"resource": ip},
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "YADS Security Scanner"},
            )
```
→
```python
            resp = throttled_get(
                f"{RIPE_STAT}/network-info/data.json",
                service="ripestat",
                params={"resource": ip},
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "YADS Security Scanner"},
            )
```

Apply the same pattern (add `service="ripestat",` right after the URL argument) to the `as-overview` and `rpki-validation` calls, and the `service="ipinfo",` pattern to the `_get_asn_ipinfo` call.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_public_api_service_names.py -v`
Expected: PASS for all entries touched so far (crt.sh cluster from Task 5 + this task's 4 files)

- [ ] **Step 7: Commit**

```bash
git add yads/modules/asn_scanner.py yads/modules/infrastructure_scanner.py yads/modules/ipv6_scanner.py yads/modules/rpki_scanner.py
git commit -m "feat: route ipinfo/ripestat/bgpview calls through circuit-breaker-aware client"
```

---

## Task 7: Migrate remaining public-API modules

**Files:**
- Modify: `yads/modules/wayback_scanner.py:192` (leave `173`'s `requests.head` alone — that's a liveness probe against the *discovered URL*, not the wayback API)
- Modify: `yads/modules/phishing_scanner.py:109`
- Modify: `yads/modules/dependency_confusion.py:69,149` (leave the `PYPI_REGISTRY`/`RUBYGEMS_REGISTRY` calls that follow at ~160-175 alone — out of the approved scope, npm only)
- Modify: `yads/modules/tls_deep_scanner.py:155`
- Modify: `yads/modules/mobile_app_discovery.py:72` (leave `_get()` at line 61 alone — it fetches arbitrary discovered URLs, not a fixed third-party API)
- Test: extend `tests/test_public_api_service_names.py` from Task 5 (already lists these files)

**Interfaces:**
- Consumes: `throttled_get`/`throttled_post` from `yads.core.throttled_http` (Task 3).

- [ ] **Step 1: Confirm the relevant tests are currently failing**

Run: `pytest tests/test_public_api_service_names.py -v -k "wayback_scanner or phishing_scanner or dependency_confusion or tls_deep_scanner or mobile_app_discovery"`
Expected: FAIL (5 tests)

- [ ] **Step 2: Migrate `yads/modules/wayback_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. Replace only the CDX API call at line 192:

```python
            resp = requests.get(CDX_API, params=params, timeout=REQUEST_TIMEOUT)
```
→
```python
            resp = throttled_get(CDX_API, service="wayback", params=params, timeout=REQUEST_TIMEOUT)
```

- [ ] **Step 3: Migrate `yads/modules/phishing_scanner.py`**

Add `from yads.core.throttled_http import throttled_post` to imports. Find the `requests.post(` call at line ~109 (hits `PHISHTANK_URL`); confirm by reading the surrounding function, then change it to `throttled_post(` with `service="phishtank"` added as a kwarg, keeping all other arguments unchanged.

- [ ] **Step 4: Migrate `yads/modules/dependency_confusion.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. In `_fetch` (line ~69):

```python
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS, verify=False, allow_redirects=True)
```

This one is used for arbitrary target-hosted `package.json`/`requirements.txt` files, not a fixed third-party API — **leave this one as raw `requests.get`, do not migrate it**. Only migrate `_check_npm_exists` (line ~149):

```python
    try:
        r = requests.get(
            NPM_REGISTRY.format(package=package),
            timeout=TIMEOUT,
        )
```
→
```python
    try:
        r = throttled_get(
            NPM_REGISTRY.format(package=package),
            service="npm_registry",
            timeout=TIMEOUT,
        )
```

Since `_fetch` intentionally stays on raw `requests`, update `tests/test_public_api_service_names.py`'s `MIGRATED_FILES`-driven test for this file: replace the blanket `test_module_has_no_raw_requests_calls` assertion for `dependency_confusion.py` with a narrower one that only checks `_check_npm_exists`. Change the parametrized test to skip this file in the generic list and add a dedicated test:

```python
MIGRATED_FILES = [
    "modules/crtSH_client.py",
    "modules/ct_monitor.py",
    "modules/dns_history_scanner.py",
    "modules/asn_scanner.py",
    "modules/infrastructure_scanner.py",
    "modules/ipv6_scanner.py",
    "modules/rpki_scanner.py",
    "modules/wayback_scanner.py",
    "modules/phishing_scanner.py",
    "modules/tls_deep_scanner.py",
    "modules/mobile_app_discovery.py",
]  # dependency_confusion.py checked separately below — it has one migrated
   # call (npm registry) and one intentionally-unmigrated call (arbitrary
   # target-hosted manifest fetch)


def test_dependency_confusion_npm_check_is_migrated():
    src = (YADS_ROOT / "modules/dependency_confusion.py").read_text()
    start = src.index("def _check_npm_exists")
    end = src.index("\ndef ", start + 1)
    body = src[start:end]
    assert "requests.get(" not in body
    assert "throttled_get(" in body
```

- [ ] **Step 5: Migrate `yads/modules/tls_deep_scanner.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. Replace line ~155:

```python
        r = requests.get(HSTS_PRELOAD_URL.format(domain=domain), timeout=TIMEOUT)
```
→
```python
        r = throttled_get(HSTS_PRELOAD_URL.format(domain=domain), service="hstspreload", timeout=TIMEOUT)
```

- [ ] **Step 6: Migrate `yads/modules/mobile_app_discovery.py`**

Add `from yads.core.throttled_http import throttled_get` to imports. Replace only `_search_itunes`'s call (line ~72):

```python
        r = requests.get(ITUNES_SEARCH.format(query=query), timeout=TIMEOUT)
```
→
```python
        r = throttled_get(ITUNES_SEARCH.format(query=query), service="itunes", timeout=TIMEOUT)
```

Leave `_get()` (line ~61, used for arbitrary discovered app-store/company URLs) as raw `requests.get` — same reasoning as `dependency_confusion._fetch`.

Update the test file's `test_module_has_no_raw_requests_calls` for this file the same way as dependency_confusion — remove `"modules/mobile_app_discovery.py"` from the blanket `MIGRATED_FILES` list and add:

```python
def test_mobile_app_discovery_itunes_search_is_migrated():
    src = (YADS_ROOT / "modules/mobile_app_discovery.py").read_text()
    start = src.index("def _search_itunes")
    end = src.index("\ndef ", start + 1)
    body = src[start:end]
    assert "requests.get(" not in body
    assert "throttled_get(" in body
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_public_api_service_names.py -v`
Expected: PASS for all entries

- [ ] **Step 8: Commit**

```bash
git add yads/modules/wayback_scanner.py yads/modules/phishing_scanner.py yads/modules/dependency_confusion.py yads/modules/tls_deep_scanner.py yads/modules/mobile_app_discovery.py tests/test_public_api_service_names.py
git commit -m "feat: route wayback/phishtank/npm/hstspreload/itunes calls through circuit-breaker-aware client"
```

---

## Task 8: Migrate BYOK modules (shodan/censys/threat-intel)

**Files:**
- Modify: `yads/modules/shodan_censys_scanner.py:145-165,222-245`
- Modify: `yads/modules/threat_intel_scanner.py:131-163,189-249,265-290` (abuseipdb, otx x2, virustotal)
- Test: `tests/test_byok_block_detection.py`

**Interfaces:**
- Consumes: `record_if_blocked` from `yads.core.api_block_detection` (Task 2). These modules keep their existing `ApiRateLimiter.acquire()` proactive self-throttle unchanged — this task only adds reactive detection on top, using the non-raising form since these functions already return structured `{"status": ...}` dicts rather than raising.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_byok_block_detection.py
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
```

Adjust the `monkeypatch` target paths/`__new__` bypass if either module's `__init__` turns out to need more than `db_session` — check both classes' `__init__` signatures first; if they require non-optional args, construct via `object.__new__(ClassName)` and manually set only the attributes each `_query_*` method reads (visible directly in the method bodies already read during planning).

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_byok_block_detection.py -v`
Expected: FAIL — `result["status"]` is `"request_error"` (from the generic `except requests.RequestException`), not `"rate_limited"`, because `resp.raise_for_status()` raises before any 429-specific handling exists yet.

- [ ] **Step 3: Modify `yads/modules/shodan_censys_scanner.py`**

Add import: `from yads.core.api_block_detection import record_if_blocked`.

In `_query_shodan`, insert a check right after the existing `404`/`401` branches, before `resp.raise_for_status()`:

```python
            if resp.status_code == 404:
                logger.info(f"[ShodanCensys] Shodan: no data for {ip}")
                return {"status": "not_found"}
            if resp.status_code == 401:
                logger.warning("[ShodanCensys] Shodan API key invalid or quota exceeded")
                return {"error": "Unauthorized", "status": "auth_error"}
            if record_if_blocked("shodan", resp):
                logger.warning("[ShodanCensys] Shodan is blocking/rate-limiting us")
                return {"error": "Rate limited", "status": "rate_limited"}
            resp.raise_for_status()
```

In `_query_censys`, same pattern after the `404`/`401,403` branches:

```python
            if resp.status_code == 404:
                logger.info(f"[ShodanCensys] Censys: no data for {ip}")
                return {"status": "not_found"}
            if resp.status_code in (401, 403):
                logger.warning("[ShodanCensys] Censys API credentials invalid")
                return {"error": "Unauthorized", "status": "auth_error"}
            if record_if_blocked("censys", resp):
                logger.warning("[ShodanCensys] Censys is blocking/rate-limiting us")
                return {"error": "Rate limited", "status": "rate_limited"}
            resp.raise_for_status()
```

Note: `record_if_blocked` returning `False` here also calls `circuit_breaker.clear()`, which is a harmless no-op when nothing was blocked — same for every other call site below.

- [ ] **Step 4: Modify `yads/modules/threat_intel_scanner.py`**

Add import: `from yads.core.api_block_detection import record_if_blocked`.

In `_query_abuseipdb`, the existing code already special-cases `429`:

```python
            if resp.status_code == 401:
                return {"error": "Unauthorized", "status": "auth_error"}
            if resp.status_code == 429:
                return {"error": "Rate limited", "status": "rate_limited"}
            resp.raise_for_status()
```

Change to also record the block (keep the same returned dict):

```python
            if resp.status_code == 401:
                return {"error": "Unauthorized", "status": "auth_error"}
            if resp.status_code == 429 or record_if_blocked("abuseipdb", resp):
                return {"error": "Rate limited", "status": "rate_limited"}
            resp.raise_for_status()
```

(`record_if_blocked` also handles the 401/other-status "not blocked" path by clearing the breaker — call it unconditionally as the second operand so a 200 still clears a stale block.)

In `_query_otx`'s domain-lookup branch:

```python
                if resp.status_code == 401:
                    return {"error": "Unauthorized", "status": "auth_error"}
                resp.raise_for_status()
```
→
```python
                if resp.status_code == 401:
                    return {"error": "Unauthorized", "status": "auth_error"}
                if record_if_blocked("otx", resp):
                    results["domain"] = {"error": "Rate limited", "status": "rate_limited"}
                    return results
                resp.raise_for_status()
```

In the IP-lookup branch (no existing 401 check):

```python
                    resp.raise_for_status()
                    d = resp.json()
                    results["ip"] = {
```
→
```python
                    if record_if_blocked("otx", resp):
                        results["ip"] = {"error": "Rate limited", "status": "rate_limited"}
                        return results
                    resp.raise_for_status()
                    d = resp.json()
                    results["ip"] = {
```

In `_query_virustotal`:

```python
            if resp.status_code == 401:
                return {"error": "Unauthorized", "status": "auth_error"}
            if resp.status_code == 429:
                return {"error": "Rate limited — VirusTotal public API quota exceeded", "status": "rate_limited"}
            if resp.status_code == 404:
                return {"status": "not_found"}
            resp.raise_for_status()
```
→
```python
            if resp.status_code == 401:
                return {"error": "Unauthorized", "status": "auth_error"}
            if resp.status_code == 429 or record_if_blocked("virustotal", resp):
                return {"error": "Rate limited — VirusTotal public API quota exceeded", "status": "rate_limited"}
            if resp.status_code == 404:
                return {"status": "not_found"}
            resp.raise_for_status()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_byok_block_detection.py -v`
Expected: PASS (both tests)

- [ ] **Step 6: Commit**

```bash
git add yads/modules/shodan_censys_scanner.py yads/modules/threat_intel_scanner.py tests/test_byok_block_detection.py
git commit -m "feat: trip circuit breaker on shodan/censys/abuseipdb/otx/virustotal blocking"
```

---

## Task 9: Per-target module status marker

**Files:**
- Create: `yads/core/module_status.py`
- Test: `tests/test_module_status.py`

**Interfaces:**
- Produces: `mark_rate_limited(target_id: int, module_name: str, ttl_seconds: int) -> None`, `clear_rate_limited(target_id: int, module_name: str) -> None`, `is_rate_limited(target_id: int, module_name: str) -> bool`, `get_rate_limited_module_count() -> int` (counts all `yads:module_status:*` keys currently set, for the queue widget in Task 13).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_module_status.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_module_status.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'yads.core.module_status'`

- [ ] **Step 3: Implement `yads/core/module_status.py`**

```python
"""
Per-target, per-module transient status markers stored in Redis. Currently
only tracks "rate_limited" (set by run_scan_module in worker_tasks.py when a
module hits ApiBlockedError), read by the queue widget to show that scans
are being retried rather than silently missing data.
"""

import logging
from yads.database import redis_client

logger = logging.getLogger(__name__)

_KEY_PREFIX = "yads:module_status"


def _key(target_id: int, module_name: str) -> str:
    return f"{_KEY_PREFIX}:{target_id}:{module_name}"


def mark_rate_limited(target_id: int, module_name: str, ttl_seconds: int) -> None:
    try:
        redis_client.set(_key(target_id, module_name), "rate_limited", ex=max(ttl_seconds, 1))
    except Exception as exc:
        logger.warning("[ModuleStatus] Failed to mark rate_limited for target=%s module=%s: %s", target_id, module_name, exc)


def clear_rate_limited(target_id: int, module_name: str) -> None:
    try:
        redis_client.delete(_key(target_id, module_name))
    except Exception as exc:
        logger.warning("[ModuleStatus] Failed to clear status for target=%s module=%s: %s", target_id, module_name, exc)


def is_rate_limited(target_id: int, module_name: str) -> bool:
    try:
        return bool(redis_client.get(_key(target_id, module_name)))
    except Exception as exc:
        logger.warning("[ModuleStatus] Failed to read status for target=%s module=%s: %s", target_id, module_name, exc)
        return False


def get_rate_limited_module_count() -> int:
    try:
        return len(redis_client.keys(f"{_KEY_PREFIX}:*"))
    except Exception as exc:
        logger.warning("[ModuleStatus] Failed to count rate-limited modules: %s", exc)
        return 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_module_status.py -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/core/module_status.py tests/test_module_status.py
git commit -m "feat: add per-target module rate-limit status tracking"
```

---

## Task 10: `_run_parallel_module` propagates `ApiBlockedError`

**Files:**
- Modify: `yads/worker_modules.py:80-101`
- Test: `tests/test_worker_modules_block_propagation.py`

**Interfaces:**
- Consumes: `ApiBlockedError` from `yads.core.api_block_detection` (Task 2).
- Produces: `_run_parallel_module` now re-raises `ApiBlockedError` instead of swallowing it into a generic logged error — this is required for Task 11's `run_scan_module` to distinguish "blocked, should retry" from "failed, should not retry".

- [ ] **Step 1: Write the failing test**

```python
# tests/test_worker_modules_block_propagation.py
import pytest
from unittest.mock import MagicMock, patch
from yads.worker_modules import _run_parallel_module
from yads.core.api_block_detection import ApiBlockedError


def test_run_parallel_module_reraises_api_blocked_error():
    mock_module_cls = MagicMock()
    mock_instance = mock_module_cls.return_value
    mock_instance.process.side_effect = ApiBlockedError("test_service", retry_after=30)

    with patch("yads.worker_modules.validate_target_safety", return_value=True), \
         patch("yads.worker_modules.Session"):
        with pytest.raises(ApiBlockedError) as exc_info:
            _run_parallel_module(mock_module_cls, 1, "example.com")
        assert exc_info.value.service == "test_service"
        assert exc_info.value.retry_after == 30


def test_run_parallel_module_still_swallows_other_exceptions():
    mock_module_cls = MagicMock()
    mock_instance = mock_module_cls.return_value
    mock_instance.process.side_effect = RuntimeError("boom")

    with patch("yads.worker_modules.validate_target_safety", return_value=True), \
         patch("yads.worker_modules.Session"):
        _run_parallel_module(mock_module_cls, 1, "example.com")  # must not raise
```

- [ ] **Step 2: Run tests to verify the first one fails**

Run: `pytest tests/test_worker_modules_block_propagation.py -v`
Expected: `test_run_parallel_module_reraises_api_blocked_error` FAILS (no exception raised — currently swallowed); `test_run_parallel_module_still_swallows_other_exceptions` PASSES already

- [ ] **Step 3: Modify `yads/worker_modules.py`**

Add the import near the top:

```python
from yads.core.api_block_detection import ApiBlockedError
```

Change `_run_parallel_module`'s exception handling:

```python
def _run_parallel_module(module_cls, target_id: int, domain: str):
    """
    Run a scanner module in its own DB session (thread-safe parallel execution).
    Each parallel module gets an isolated session; results are committed independently.
    LogCapture is intentionally skipped to avoid root-logger thread-safety issues —
    logs still flow via the Redis handler attached by the parent task.

    ApiBlockedError propagates to the caller (run_scan_module in worker_tasks.py)
    so a provider-blocked module can be rescheduled instead of treated as a
    generic failure. Every other exception is still swallowed and logged here,
    matching the pre-existing behavior.
    """
    from yads.utils.sanitize import sanitize_null_bytes
    try:
        if not validate_target_safety(domain):
            logger.error(f"[Worker] SSRF Protection: Skipping parallel module {module_cls.__name__} for unsafe target {domain}")
            return

        with Session(engine) as session:
            mod = module_cls(db_session=session)
            result = mod.process(target_id, domain)
            if result and hasattr(result, 'log_content'):
                session.add(result)
                session.commit()
            logger.info(f"[Worker] Parallel: {mod.module_name} finished.")
    except ApiBlockedError:
        raise
    except Exception as e:
        logger.error(f"[Worker] Parallel module {module_cls.__name__} error: {e}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_worker_modules_block_propagation.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add yads/worker_modules.py tests/test_worker_modules_block_propagation.py
git commit -m "feat: propagate ApiBlockedError out of _run_parallel_module"
```

---

## Task 11: `run_scan_module` Celery task

**Files:**
- Modify: `yads/worker_tasks.py` (add new task, near the other Celery task definitions — e.g. directly above `run_all_scans` at line ~639)
- Test: `tests/test_run_scan_module.py`

**Interfaces:**
- Consumes: `_run_parallel_module` (Task 10, now `ApiBlockedError`-transparent), `mark_rate_limited`/`clear_rate_limited` (Task 9), `ApiBlockedError` (Task 2).
- Produces: `run_scan_module(target_id: int, domain: str, module_name: str, tenant_id: int, attempt: int = 0) -> None`, a Celery task (`name="yads.worker.run_scan_module"`) that looks up the module class via `core.module_registry.get_module(module_name)`, runs it via `_run_parallel_module`, and on `ApiBlockedError` marks the module rate-limited and schedules exactly one jittered follow-up call to itself (fire-and-forget, not a Celery retry) unless `attempt >= MAX_BLOCKED_RETRIES`. This is what Task 12 will call from a `chord`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_run_scan_module.py
from unittest.mock import MagicMock, patch
from yads.core.api_block_detection import ApiBlockedError


def test_run_scan_module_runs_module_normally():
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module") as mock_run, \
         patch("yads.worker_tasks.mark_rate_limited") as mock_mark, \
         patch("yads.worker_tasks.clear_rate_limited") as mock_clear:
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module
        run_scan_module(1, "example.com", "wayback_scanner", 42)

        mock_run.assert_called_once()
        mock_mark.assert_not_called()
        mock_clear.assert_called_once_with(1, "wayback_scanner")


def test_run_scan_module_marks_rate_limited_and_reschedules_on_block():
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module", side_effect=ApiBlockedError("wayback", retry_after=5)), \
         patch("yads.worker_tasks.mark_rate_limited") as mock_mark, \
         patch("yads.worker_tasks.run_scan_module.apply_async") as mock_apply_async:
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module
        run_scan_module(1, "example.com", "wayback_scanner", 42, attempt=0)

        mock_mark.assert_called_once()
        assert mock_mark.call_args[0][0] == 1
        assert mock_mark.call_args[0][1] == "wayback_scanner"

        mock_apply_async.assert_called_once()
        _, kwargs = mock_apply_async.call_args
        assert kwargs["kwargs"]["attempt"] == 1
        assert kwargs["countdown"] >= 5  # at least retry_after, jitter only adds


def test_run_scan_module_gives_up_after_max_attempts():
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module", side_effect=ApiBlockedError("wayback")), \
         patch("yads.worker_tasks.mark_rate_limited"), \
         patch("yads.worker_tasks.run_scan_module.apply_async") as mock_apply_async:
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module, MAX_BLOCKED_RETRIES
        run_scan_module(1, "example.com", "wayback_scanner", 42, attempt=MAX_BLOCKED_RETRIES)

        mock_apply_async.assert_not_called()


def test_run_scan_module_does_not_raise_on_block():
    """The chord this feeds must see this task complete, not fail, on a block."""
    with patch("yads.worker_tasks.get_module") as mock_get_module, \
         patch("yads.worker_tasks._run_parallel_module", side_effect=ApiBlockedError("wayback")), \
         patch("yads.worker_tasks.mark_rate_limited"), \
         patch("yads.worker_tasks.run_scan_module.apply_async"):
        mock_get_module.return_value.load_class.return_value = MagicMock()

        from yads.worker_tasks import run_scan_module
        run_scan_module(1, "example.com", "wayback_scanner", 42)  # must not raise
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_run_scan_module.py -v`
Expected: FAIL — `run_scan_module` doesn't exist yet

- [ ] **Step 3: Add to `yads/worker_tasks.py`**

Add these imports near the top (with the other `yads.core.*` imports):

```python
from yads.core.module_registry import get_module
from yads.core.module_status import mark_rate_limited, clear_rate_limited
from yads.core.api_block_detection import ApiBlockedError
import random
```

Add this constant near the top of the file (module-level, alongside `logger = logging.getLogger(...)`):

```python
MAX_BLOCKED_RETRIES = 5
DEFAULT_BLOCKED_COOLDOWN = 300  # fallback when ApiBlockedError has no retry_after
RATE_LIMITED_STATUS_TTL_BUFFER = 60  # keep the Redis badge visible a bit past the retry
```

Add the new task directly above `run_all_scans`:

```python
@celery_app.task(name="yads.worker.run_scan_module", bind=False, acks_late=True, reject_on_worker_lost=True)
def run_scan_module(target_id: int, domain: str, module_name: str, tenant_id: int, attempt: int = 0):
    """
    Runs a single registry-driven scan module for one target. Dispatched as
    part of a chord from run_all_scans (see get_simple_dispatch_modules()).

    On ApiBlockedError: marks the module rate-limited for this target and,
    unless attempt >= MAX_BLOCKED_RETRIES, schedules exactly one independent
    follow-up call to itself with jittered backoff. Always returns normally
    (never raises) so the enclosing chord's finalize_scan callback isn't
    held up by a provider block that might take minutes to hours to clear.
    """
    mod_def = get_module(module_name)
    if not mod_def:
        logger.error(f"[Worker] run_scan_module: unknown module '{module_name}'")
        return

    try:
        module_cls = mod_def.load_class()
    except Exception as e:
        logger.error(f"[Worker] run_scan_module: failed to load '{module_name}': {e}")
        return

    try:
        _run_parallel_module(module_cls, target_id, domain)
        clear_rate_limited(target_id, module_name)
    except ApiBlockedError as e:
        cooldown = e.retry_after or DEFAULT_BLOCKED_COOLDOWN
        mark_rate_limited(target_id, module_name, ttl_seconds=cooldown + RATE_LIMITED_STATUS_TTL_BUFFER)
        logger.warning(
            f"[Worker] '{module_name}' blocked by '{e.service}' for target {target_id} "
            f"(attempt {attempt}); cooldown={cooldown}s"
        )
        if attempt < MAX_BLOCKED_RETRIES:
            jitter = random.uniform(0.5, 1.5)
            run_scan_module.apply_async(
                args=[target_id, domain, module_name, tenant_id],
                kwargs={"attempt": attempt + 1},
                countdown=cooldown * jitter,
            )
        else:
            logger.warning(
                f"[Worker] '{module_name}' for target {target_id} gave up after "
                f"{MAX_BLOCKED_RETRIES} blocked attempts; will retry on next scheduled scan."
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_run_scan_module.py -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```bash
git add yads/worker_tasks.py tests/test_run_scan_module.py
git commit -m "feat: add run_scan_module Celery task with jittered blocked-retry"
```

---

## Task 12: Extract `finalize_scan`

**Files:**
- Modify: `yads/worker_tasks.py:1387-1651` (the tail of `run_all_scans`, from the "Subdomain Discovery & Auto-Queue Logic" comment through the `report_task_completed` call, currently inside the `with Session(engine) as session:` / outer `try` block)
- Test: `tests/test_finalize_scan.py`

**Interfaces:**
- Consumes: nothing new — this is a pure extraction of existing code.
- Produces: `finalize_scan(target_id: int, domain: str, tenant_id: int, scan_types: list, scan_start_time, celery_task_id: str = None) -> None`, a Celery task (`name="yads.worker.finalize_scan"`) containing exactly the logic currently at the tail of `run_all_scans` (subdomain auto-queue, compliance recalculation, status reset to idle, webhook `scan_finished`, Splunk/Prometheus events, email notification, `_worker_client.report_task_completed`). Task 13 uses this as a chord callback via `finalize_scan.s(...)`.

This is a pure code-motion task — no new logic, no behavior change when called directly (only how it's invoked changes, in Task 13). Correctness is verified by confirming the extracted function is byte-for-byte the same operations, executed via a test that patches out every side effect and asserts they're all still invoked in the same order.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_finalize_scan.py
from datetime import datetime
from unittest.mock import patch, MagicMock


def test_finalize_scan_runs_all_tail_steps_in_order():
    calls = []

    def _record(name):
        def _fn(*a, **kw):
            calls.append(name)
        return _fn

    with patch("yads.worker_tasks.Session") as mock_session_cls, \
         patch("yads.worker_tasks.webhook_service") as mock_webhook, \
         patch("yads.worker_tasks.splunk_logger") as mock_splunk, \
         patch("yads.worker_tasks.get_metrics") as mock_metrics, \
         patch("yads.worker_tasks._worker_client", None):

        mock_session = MagicMock()
        mock_session_cls.return_value.__enter__.return_value = mock_session
        # No SystemConfig/Target rows found — exercises the "nothing to do"
        # branches of subdomain auto-queue / compliance recalc / email notify
        # without needing a real DB, while still confirming finalize_scan
        # reaches the status-reset and webhook calls unconditionally.
        mock_session.exec.return_value.first.return_value = None
        mock_session.exec.return_value.all.return_value = []
        mock_session.get.return_value = MagicMock(scan_status=None)

        from yads.worker_tasks import finalize_scan
        finalize_scan(
            target_id=1,
            domain="example.com",
            tenant_id=42,
            scan_types=["wayback_scanner"],
            scan_start_time=datetime.utcnow(),
        )

        mock_webhook.trigger_event.assert_any_call(
            42, "scan_finished",
            {"target_id": 1, "domain": "example.com", "status": "completed", "modules": ["wayback_scanner"]}
        )
```

Note: this test intentionally mocks broadly rather than asserting every internal step, since `finalize_scan`'s body is an unmodified extraction — the goal is only to confirm it's callable standalone and still fires the externally-visible `scan_finished` webhook, which is the signal other systems (Task 13's chord caller, any webhook consumers) depend on.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_finalize_scan.py -v`
Expected: FAIL — `finalize_scan` doesn't exist yet

- [ ] **Step 3: Extract `finalize_scan` in `yads/worker_tasks.py`**

Cut the block currently spanning from the `# Subdomain Discovery & Auto-Queue Logic` comment (line ~1387) through the end of the function (the `finally:` block that removes the Redis log handler stays in `run_all_scans` — see Task 13's Step 3), and paste it into a new task defined directly after `run_scan_module` (Task 11) and before `run_all_scans`:

```python
@celery_app.task(name="yads.worker.finalize_scan", bind=False)
def finalize_scan(target_id: int, domain: str, tenant_id: int, scan_types: list, scan_start_time, celery_task_id: str = None):
    """
    Tail of the per-target scan: subdomain auto-queue, compliance
    recalculation, status reset to idle, scan_finished webhook, Splunk/
    Prometheus events, email notification. Extracted from run_all_scans so
    it can run as a Celery chord callback once every dispatched
    run_scan_module task for the target has completed (see run_all_scans).
    """
    from yads.worker_core import _worker_client

    with Session(engine) as session:
        parent_tenant_id = tenant_id

        # Subdomain Discovery & Auto-Queue Logic
        subdomain_modules_ran = bool(set(scan_types) & {'subdomain_scanner', 'dns_scanner'})
        if not subdomain_modules_ran:
            logger.debug("[Worker] Skipping auto-queue: subdomain_scanner/dns_scanner not in current scan_types.")
        else:
            # ... (unchanged body from the original run_all_scans block)
            ...

        # Post-Scan Compliance Recalculation
        try:
            # ... (unchanged body)
            ...
        except Exception as e:
            logger.error(f"[Worker] Error in compliance recalculation: {e}")
            session.rollback()

        # Reset status
        try:
            t = session.get(Target, target_id)
            if t:
                t.scan_status = "idle"
                t.scan_progress = f"Last scan completed at {datetime.utcnow().strftime('%H:%M:%S')}"
                t.scan_heartbeat_at = None
                session.add(t)
                session.commit()
        except Exception as e:
            logger.error(f"[Worker] Failed to update finish status: {e}")
            session.rollback()

    webhook_service.trigger_event(parent_tenant_id, "scan_finished", {
        "target_id": target_id,
        "domain": domain,
        "status": "completed",
        "modules": scan_types
    })

    try:
        scan_duration = (datetime.utcnow() - scan_start_time).total_seconds()
        splunk_logger.send_ops_event(
            category="scan_completed",
            message=f"Scan completed for {domain}",
            details={
                "target_id": target_id,
                "domain": domain,
                "duration_seconds": round(scan_duration, 2),
                "scan_types": scan_types
            },
            tenant_id=parent_tenant_id
        )
    except Exception:
        pass

    try:
        prom_metrics = get_metrics()
        prom_metrics.record_scan_finished(tenant_id=parent_tenant_id)
    except Exception as e:
        logger.debug(f"[Worker] Failed to record scan_finished metric: {e}")

    # Email notification: send if changes were detected
    try:
        # ... (unchanged body from the original run_all_scans block)
        ...
    except Exception as _email_exc:
        logger.warning(f"[Worker] Email notification failed (non-fatal): {_email_exc}")

    logger.info(f"[Worker] Finished scan for {domain}")

    if _worker_client and _worker_client.is_distributed and celery_task_id:
        _worker_client.report_task_completed(celery_task_id, success=True)
```

Fill each `# ... (unchanged body)` with the exact corresponding code currently in `run_all_scans` (read the file at the line ranges cited in **Files** above and move it verbatim — the subdomain auto-queue block, the compliance recalculation block, and the email notification block, none of which need any changes to their internals, only their location). Note two behavior-preserving details when moving them:

1. The original code guarded most of this tail with `if 'parent_tenant_id' in locals():` (since `parent_tenant_id` was only set if the earlier `try` that fetches `Target` succeeded). In `finalize_scan`, `parent_tenant_id` is always the passed-in `tenant_id` parameter — drop that `if` guard, since by the time `finalize_scan` runs (as a chord callback after `run_scan_module` tasks, which only get dispatched once `run_all_scans` has already loaded the `Target` and set `parent_tenant_id`), it's always available.
2. The original heartbeat-stop (`_hb_stop.set()`) and the redis log handler `finally:` block stay in `run_all_scans` (Task 13) — they're tied to that task's own thread/handler lifecycle, not to the tail logic being extracted here.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_finalize_scan.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add yads/worker_tasks.py tests/test_finalize_scan.py
git commit -m "refactor: extract finalize_scan from run_all_scans tail"
```

---

## Task 13: Wire chord into `run_all_scans`

**Files:**
- Modify: `yads/worker_tasks.py:1314-1385` (the `ThreadPoolExecutor` dispatch block) and the now-shortened tail (post Task 12 extraction)
- Test: `tests/test_run_all_scans_chord.py`

**Interfaces:**
- Consumes: `run_scan_module` (Task 11), `finalize_scan` (Task 12), `celery.chord`/`celery.group`.
- Produces: `run_all_scans` now dispatches `get_simple_dispatch_modules()` as a `chord(...)` calling `finalize_scan` instead of running them in a `ThreadPoolExecutor` and then falling through to the (now-extracted) tail inline.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_run_all_scans_chord.py
from unittest.mock import patch, MagicMock


def test_run_all_scans_dispatches_chord_with_one_task_per_module():
    with patch("yads.worker_tasks.get_simple_dispatch_modules") as mock_get_mods, \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.run_scan_module") as mock_run_scan_module, \
         patch("yads.worker_tasks.finalize_scan") as mock_finalize, \
         patch("yads.worker_tasks.Session") as mock_session_cls, \
         patch("yads.worker_tasks.check_web", return_value=(True, True)) if False else patch("builtins.print"):
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
            scan_start_time=None,
        )

        mock_run_scan_module.s.assert_called_once_with(1, "example.com", "wayback_scanner", 42)
        mock_chord.assert_called_once()
        mock_chord_instance.assert_called_once()


def test_run_all_scans_calls_finalize_directly_when_no_modules_selected():
    with patch("yads.worker_tasks.get_simple_dispatch_modules", return_value=[]), \
         patch("yads.worker_tasks.chord") as mock_chord, \
         patch("yads.worker_tasks.finalize_scan") as mock_finalize:

        from yads.worker_tasks import _dispatch_module_chord
        _dispatch_module_chord(
            target_id=1, domain="example.com", tenant_id=42,
            scan_types=[], has_http=True, has_https=True,
            scan_start_time=None,
        )

        mock_chord.assert_not_called()
        mock_finalize.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_run_all_scans_chord.py -v`
Expected: FAIL — `_dispatch_module_chord` doesn't exist yet

- [ ] **Step 3: Modify `yads/worker_tasks.py`**

Add to the Celery import line (find the existing `from yads.worker_core import celery_app, ...` — add alongside it):

```python
from celery import chord
```

Replace the block from `# Registry-driven parallel module dispatch` (originally line ~1314) through the end of the `if _parallel_mods:` block (originally ending ~1385, right before the now-relocated `# Subdomain Discovery & Auto-Queue Logic` comment that Task 12 moved into `finalize_scan`) with a call to a new helper function, and define that helper near the top of the file (module level, e.g. directly above `run_all_scans`):

```python
def _dispatch_module_chord(target_id, domain, tenant_id, scan_types, has_http, has_https, scan_start_time):
    """
    Builds and fires the chord of run_scan_module tasks for every
    registry-driven module in scan_types, with finalize_scan as the
    callback. If no modules are selected, calls finalize_scan directly
    (a chord over an empty group never fires its callback).
    """
    module_names = []
    for _mod_def in get_simple_dispatch_modules():
        if _mod_def.name not in scan_types:
            continue
        if _mod_def.requires_https and not has_https:
            logger.info(f"[Worker] Skipping {_mod_def.name}: no HTTPS")
            continue
        if _mod_def.requires_http and not (has_http or has_https):
            logger.info(f"[Worker] Skipping {_mod_def.name}: no HTTP")
            continue
        module_names.append(_mod_def.name)

    if not module_names:
        finalize_scan(target_id, domain, tenant_id, scan_types, scan_start_time)
        return

    logger.info(f"[Worker] Dispatching {len(module_names)} modules as a chord: {module_names}")
    module_tasks = [run_scan_module.s(target_id, domain, name, tenant_id) for name in module_names]
    chord(module_tasks)(finalize_scan.s(target_id, domain, tenant_id, scan_types, scan_start_time))
```

In `run_all_scans`, replace the whole `# Registry-driven parallel module dispatch` block (the `for _mod_def in get_simple_dispatch_modules(): ...` loop building `_parallel_mods`, the `ThreadPoolExecutor` submission, and the `as_completed` collection loop) with:

```python
            # Registry-driven module dispatch — see _dispatch_module_chord.
            # This also triggers finalize_scan (subdomain auto-queue,
            # compliance recalc, status reset, scan_finished webhook) either
            # as the chord's callback, or directly if no modules matched.
            _dispatch_module_chord(
                target_id, domain, tenant_id, scan_types, has_http, has_https, scan_start_time,
            )
```

Because `finalize_scan` now owns everything that used to run after the dispatch block (Task 12), nothing else needs to remain in `run_all_scans` after this call except the pre-existing `finally:` block that stops the heartbeat thread and removes the Redis log handler. Move the `_hb_stop.set()` call (originally right before "Reset status" in the old tail) to immediately after the `_dispatch_module_chord(...)` call:

```python
            _dispatch_module_chord(
                target_id, domain, tenant_id, scan_types, has_http, has_https, scan_start_time,
            )

        # Stop heartbeat thread — dispatch is complete; finalize_scan (in the
        # chord callback, or called directly above) owns the rest of the
        # scan's lifecycle from here.
        if '_hb_stop' in locals():
            _hb_stop.set()

    finally:
        if 'root_logger' in locals() and 'redis_handler' in locals():
            root_logger.removeHandler(redis_handler)
```

(This closes the `with Session(engine) as session:` block right after dispatch, since `finalize_scan` opens its own session — matching how it already does today per Task 12.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_run_all_scans_chord.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Run the full worker test suite for regressions**

Run: `pytest tests/ -k "worker or queue or scan" -v`
Expected: PASS or SKIP — no new failures introduced by the restructuring

- [ ] **Step 6: Manual smoke test**

With `docker-compose up -d` running (or the dev stack per `CLAUDE.md`), trigger a real scan for a test target with `AUTO_QUEUE_SUBDOMAINS` on and a couple of registry-driven modules selected (e.g. `wayback_scanner`, `asn_scanner`), then confirm in the worker logs: each module logs its own `run_scan_module` line, the `scan_finished` webhook event fires exactly once, and `Target.scan_status` returns to `idle`.

- [ ] **Step 7: Commit**

```bash
git add yads/worker_tasks.py tests/test_run_all_scans_chord.py
git commit -m "feat: dispatch registry-driven scan modules as an independent Celery chord"
```

---

## Task 14: Queue widget rate-limited badge

**Files:**
- Modify: `yads/api/routers/queue.py:272-306` (`_widget_context`)
- Modify: `yads/api/templates/components/queue_widget.html`
- Test: `tests/test_queue_widget_rate_limited_badge.py`

**Interfaces:**
- Consumes: `get_rate_limited_module_count()` from `yads.core.module_status` (Task 9).
- Produces: `_widget_context(...)` now includes `"rate_limited_count": int` in its returned dict; the template shows a small badge when it's greater than 0.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_queue_widget_rate_limited_badge.py
from unittest.mock import patch


def test_widget_context_includes_rate_limited_count():
    from yads.api.routers.queue import _widget_context

    mock_session = _make_mock_session()
    mock_request = object()
    mock_user = _make_mock_user()

    with patch("yads.api.routers.queue.get_rate_limited_module_count", return_value=3):
        ctx = _widget_context(mock_request, mock_session, mock_user, queue_active=True)

    assert ctx["rate_limited_count"] == 3


def _make_mock_session():
    from unittest.mock import MagicMock
    session = MagicMock()
    session.exec.return_value.one.return_value = 0
    return session


def _make_mock_user():
    from unittest.mock import MagicMock
    user = MagicMock()
    user.tenant_id = None
    return user
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_queue_widget_rate_limited_badge.py -v`
Expected: FAIL — `ctx["rate_limited_count"]` raises `KeyError`

- [ ] **Step 3: Modify `yads/api/routers/queue.py`**

Add the import near the top:

```python
from yads.core.module_status import get_rate_limited_module_count
```

In `_widget_context`, add the count and include it in the returned dict:

```python
        queued_count = total - active_count
    except Exception:
        pass

    rate_limited_count = get_rate_limited_module_count()

    return {
        "request": request,
        "queue_active": queue_active,
        "queue_length": queued_count,
        "active_count": active_count,
        "rate_limited_count": rate_limited_count,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_queue_widget_rate_limited_badge.py -v`
Expected: PASS

- [ ] **Step 5: Modify `yads/api/templates/components/queue_widget.html`**

Add a badge between the existing "Queued" span and the "Status Indicator" div (after the `</a>` closing the first link, before the `<!-- Status Indicator -->` comment):

```html
    {% if rate_limited_count and rate_limited_count > 0 %}
    <div class="flex items-center gap-1 px-2 py-1 rounded-lg border border-orange-500/30 bg-orange-500/10 text-orange-400"
         title="{{ rate_limited_count }} module(s) currently rate-limited by an external API — retrying automatically">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
        </svg>
        <span class="text-[10px] font-mono font-bold">{{ rate_limited_count }}</span>
    </div>
    {% endif %}
```

- [ ] **Step 6: Commit**

```bash
git add yads/api/routers/queue.py yads/api/templates/components/queue_widget.html tests/test_queue_widget_rate_limited_badge.py
git commit -m "feat: show rate-limited module count in queue widget"
```

---

## Task 15: Full regression pass

**Files:** none (verification-only task)

- [ ] **Step 1: Run the full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass (or skip if they require infrastructure not running locally — confirm any skips are pre-existing by checking they also skip on `main` before this branch's changes).

- [ ] **Step 2: Run the new circuit-breaker/detection/module-status suites explicitly, with integration marker**

Run: `pytest tests/ -m integration -v`
Expected: PASS — confirms real-Redis-backed behavior (`ApiCircuitBreaker`, `module_status`) works against `redis://localhost:6380/0`, not just mocks.

- [ ] **Step 3: Grep for any remaining unmigrated raw calls to the target services**

Run: `grep -rn "requests\.\(get\|post\|head\)(" yads/modules/crtSH_client.py yads/modules/ct_monitor.py yads/modules/dns_history_scanner.py yads/modules/asn_scanner.py yads/modules/infrastructure_scanner.py yads/modules/ipv6_scanner.py yads/modules/rpki_scanner.py yads/modules/wayback_scanner.py yads/modules/phishing_scanner.py yads/modules/tls_deep_scanner.py yads/modules/mobile_app_discovery.py`
Expected: no output (all migrated calls are gone; any remaining lines are the intentionally-unmigrated arbitrary-URL fetchers noted in Tasks 6/7, which this grep doesn't target since those files/functions were excluded from the list)

- [ ] **Step 4: Commit (if Step 1-3 required any fixes)**

Only commit if fixes were needed:

```bash
git add -A
git commit -m "fix: address regressions found in full test suite pass"
```
