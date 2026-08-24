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
