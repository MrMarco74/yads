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
