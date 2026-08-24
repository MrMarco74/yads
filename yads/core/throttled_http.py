"""
Throttled HTTP Client

Provides bandwidth-limited HTTP requests that respect the global NETWORK_RATE_LIMIT setting.
All scanner modules should use this instead of raw `requests` calls.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any
import logging

from yads.core.rate_limiter import get_bandwidth_limiter, RateLimiter
from yads.core.api_block_detection import raise_if_blocked
from yads.core.api_circuit_breaker import get_circuit_breaker

logger = logging.getLogger(__name__)

# Default timeout for requests
DEFAULT_TIMEOUT = 10

# Default headers
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}


class ThrottledSession(requests.Session):
    """
    A requests.Session that enforces bandwidth limits and per-domain rate limits.
    """

    def __init__(self, use_rate_limiter: bool = True, use_bandwidth_limiter: bool = True):
        super().__init__()
        self.use_rate_limiter = use_rate_limiter
        self.use_bandwidth_limiter = use_bandwidth_limiter

        if use_rate_limiter:
            self._rate_limiter = RateLimiter()
        else:
            self._rate_limiter = None

        if use_bandwidth_limiter:
            self._bandwidth_limiter = get_bandwidth_limiter()
        else:
            self._bandwidth_limiter = None

        # Setup retries
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

        # Set default headers
        self.headers.update(DEFAULT_HEADERS)

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

        # Extract domain for rate limiting
        from urllib.parse import urlparse
        domain = urlparse(url).netloc

        # Apply per-domain rate limit
        if self._rate_limiter and domain:
            self._rate_limiter.wait(domain)

        # Set default timeout if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = DEFAULT_TIMEOUT

        # Make the request
        response = super().request(method, url, **kwargs)

        if service:
            raise_if_blocked(service, response)

        # Track bandwidth usage
        if self._bandwidth_limiter:
            # Estimate request size (headers + body)
            request_size = len(url) + 200  # Approximate header size
            if 'data' in kwargs:
                request_size += len(kwargs['data']) if kwargs['data'] else 0

            # Track response size
            response_size = len(response.content) if response.content else 0

            # Consume bandwidth tokens
            total_bytes = request_size + response_size
            self._bandwidth_limiter.consume(total_bytes)

        return response


# Global throttled session instance
_throttled_session: Optional[ThrottledSession] = None


def get_throttled_session() -> ThrottledSession:
    """Get or create the global throttled session."""
    global _throttled_session
    if _throttled_session is None:
        _throttled_session = ThrottledSession()
    return _throttled_session


def throttled_get(url: str, service: str = None, **kwargs) -> requests.Response:
    """Convenience function for throttled GET requests."""
    return get_throttled_session().get(url, service=service, **kwargs)


def throttled_post(url: str, service: str = None, **kwargs) -> requests.Response:
    """Convenience function for throttled POST requests."""
    return get_throttled_session().post(url, service=service, **kwargs)


def throttled_head(url: str, service: str = None, **kwargs) -> requests.Response:
    """Convenience function for throttled HEAD requests."""
    return get_throttled_session().head(url, service=service, **kwargs)
