"""
Redis-backed sliding-window rate limiter for external API services.

Each service has a configurable request limit per time window. Limits are
shared across all Celery worker processes via Redis, preventing individual
workers from exceeding API quotas independently.

Limits can be overridden per service via SystemConfig DB keys:
    RATE_LIMIT_{SERVICE}_PER_MINUTE   (e.g. RATE_LIMIT_VIRUSTOTAL_PER_MINUTE=4)
    RATE_LIMIT_{SERVICE}_PER_SECOND   (e.g. RATE_LIMIT_SHODAN_PER_SECOND=1)

If Redis is unavailable the limiter logs a warning and allows the request
through — rate limiting is best-effort and must never block scans.
"""

import logging
import time
import threading
from typing import Dict, Optional

from yads.database import redis_client

logger = logging.getLogger(__name__)

# Singleton
_api_rate_limiter: Optional["ApiRateLimiter"] = None
_api_rate_limiter_lock = threading.Lock()


class ApiRateLimiter:
    """
    Token-bucket–style rate limiter per external API service, backed by Redis.
    Shared across all worker processes.

    Implementation uses Redis INCR + EXPIRE on a per-window key:
        rate_limit:api:{service}:{window_start_timestamp}
    where window_start_timestamp = int(now / window_seconds).

    This gives a fixed-window counter, which is simpler and more reliable
    than a true sliding window for our use-case (short windows, low contention).
    """

    # Default limits.  Keys are service names used in acquire()/try_acquire().
    # "rate" = max requests, "per" = window size in seconds.
    LIMITS: Dict[str, Dict[str, int]] = {
        "abuseipdb":  {"rate": 60,   "per": 60},    # 60 req/min free tier
        "virustotal": {"rate": 4,    "per": 60},    # 4 req/min free tier
        "otx":        {"rate": 100,  "per": 60},    # generous public tier
        "shodan":     {"rate": 1,    "per": 1},     # 1 req/sec (plan dependent)
        "censys":     {"rate": 60,   "per": 60},    # 60 req/min free tier
        "google_cse": {"rate": 100,  "per": 86400}, # 100 req/day free tier
        "crt_sh":     {"rate": 10,   "per": 60},    # conservative for public API
        "hibp":       {"rate": 10,   "per": 60},
        "default":    {"rate": 30,   "per": 60},
    }

    # How long to cache DB overrides before re-reading (seconds)
    _DB_CACHE_TTL = 120

    def __init__(self) -> None:
        self._redis = redis_client
        self._lock = threading.Lock()
        # In-memory cache for DB-sourced limit overrides
        self._limit_cache: Dict[str, Dict[str, int]] = {}
        self._cache_ts: float = 0.0
        logger.info("ApiRateLimiter initialized.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def acquire(self, service: str, timeout: float = 10.0) -> bool:
        """
        Block until a token is available for *service*, or until *timeout*
        seconds have elapsed.

        Returns True if a token was acquired, False if timed out.
        On Redis error: logs warning and returns True (fail-open).
        """
        deadline = time.monotonic() + timeout
        service = service.lower()
        limit_cfg = self._get_limit(service)
        rate = limit_cfg["rate"]
        per = limit_cfg["per"]

        while time.monotonic() < deadline:
            try:
                acquired = self._try_increment(service, rate, per)
                if acquired:
                    return True
                # Wait a fraction of the window before retrying
                retry_wait = min(per / max(rate, 1), 1.0)
                remaining = deadline - time.monotonic()
                time.sleep(min(retry_wait, remaining, 0.5))
            except Exception as exc:
                logger.warning(
                    "[ApiRateLimiter] Redis error for '%s', allowing request: %s",
                    service, exc,
                )
                return True  # fail-open

        logger.warning(
            "[ApiRateLimiter] Timed out waiting for '%s' token after %.1fs",
            service, timeout,
        )
        return False

    def try_acquire(self, service: str) -> bool:
        """
        Non-blocking token check.

        Returns True if a token is available (and consumes it).
        Returns False if the service is currently rate limited.
        On Redis error: logs warning and returns True (fail-open).
        """
        service = service.lower()
        limit_cfg = self._get_limit(service)
        try:
            return self._try_increment(service, limit_cfg["rate"], limit_cfg["per"])
        except Exception as exc:
            logger.warning(
                "[ApiRateLimiter] Redis error for '%s' (try_acquire), allowing: %s",
                service, exc,
            )
            return True  # fail-open

    def get_status(self) -> Dict[str, Dict]:
        """
        Return current window usage for all known services.
        Used by the monitoring endpoint.
        """
        status: Dict[str, Dict] = {}
        all_services = list(self.LIMITS.keys())

        for service in all_services:
            if service == "default":
                continue
            limit_cfg = self._get_limit(service)
            rate = limit_cfg["rate"]
            per = limit_cfg["per"]
            key = self._window_key(service, per)
            try:
                raw = self._redis.get(key) if self._redis else None
                used = int(raw) if raw else 0
            except Exception:
                used = 0

            status[service] = {
                "limit": rate,
                "window_seconds": per,
                "used_this_window": used,
                "remaining": max(0, rate - used),
                "limited": used >= rate,
            }

        return status

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_limit(self, service: str) -> Dict[str, int]:
        """
        Return effective limit config for *service*, applying any DB overrides.
        Falls back to "default" if service is unknown.
        """
        self._refresh_cache_if_stale()

        # Start from built-in defaults
        base = self.LIMITS.get(service) or self.LIMITS["default"]

        # Apply cached DB overrides
        override = self._limit_cache.get(service)
        if override:
            base = {**base, **override}

        return base

    def _refresh_cache_if_stale(self) -> None:
        now = time.monotonic()
        if now - self._cache_ts < self._DB_CACHE_TTL:
            return

        with self._lock:
            # Double-checked locking
            if now - self._cache_ts < self._DB_CACHE_TTL:
                return
            self._load_db_overrides()
            self._cache_ts = now

    def _load_db_overrides(self) -> None:
        """Read RATE_LIMIT_* keys from SystemConfig and update _limit_cache."""
        try:
            from sqlmodel import Session, select
            from yads.database import engine
            from yads.models import SystemConfig

            new_cache: Dict[str, Dict[str, int]] = {}
            with Session(engine) as session:
                configs = session.exec(
                    select(SystemConfig).where(
                        SystemConfig.key.like("RATE_LIMIT_%")  # type: ignore[attr-defined]
                    )
                ).all()

            for cfg in configs:
                # Expected formats:
                #   RATE_LIMIT_VIRUSTOTAL_PER_MINUTE=4
                #   RATE_LIMIT_SHODAN_PER_SECOND=1
                key = cfg.key.upper()  # e.g. RATE_LIMIT_VIRUSTOTAL_PER_MINUTE
                try:
                    val = int(cfg.value)
                except (ValueError, TypeError):
                    continue

                # Strip RATE_LIMIT_ prefix
                remainder = key[len("RATE_LIMIT_"):]  # e.g. VIRUSTOTAL_PER_MINUTE

                if remainder.endswith("_PER_MINUTE"):
                    service = remainder[: -len("_PER_MINUTE")].lower()
                    new_cache.setdefault(service, {})
                    new_cache[service]["rate"] = val
                    new_cache[service]["per"] = 60
                elif remainder.endswith("_PER_SECOND"):
                    service = remainder[: -len("_PER_SECOND")].lower()
                    new_cache.setdefault(service, {})
                    new_cache[service]["rate"] = val
                    new_cache[service]["per"] = 1
                elif remainder.endswith("_PER_DAY"):
                    service = remainder[: -len("_PER_DAY")].lower()
                    new_cache.setdefault(service, {})
                    new_cache[service]["rate"] = val
                    new_cache[service]["per"] = 86400

            self._limit_cache = new_cache
            if new_cache:
                logger.debug("[ApiRateLimiter] Loaded DB overrides: %s", new_cache)
        except Exception as exc:
            logger.warning("[ApiRateLimiter] Could not load DB overrides: %s", exc)

    @staticmethod
    def _window_key(service: str, per: int) -> str:
        """Redis key for the current fixed window."""
        window = int(time.time() / per)
        return f"rate_limit:api:{service}:{window}"

    def _try_increment(self, service: str, rate: int, per: int) -> bool:
        """
        Atomically increment the counter for the current window.
        Returns True if the counter is within *rate*, False if exceeded.
        Uses a pipeline for atomicity.
        """
        if not self._redis:
            return True  # No Redis → fail-open

        key = self._window_key(service, per)
        # Expire after 2× the window to ensure cleanup without early eviction
        expire = per * 2

        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, expire)
        results = pipe.execute()

        count = results[0]
        return count <= rate


def get_api_rate_limiter() -> ApiRateLimiter:
    """Return (or lazily create) the process-level ApiRateLimiter singleton."""
    global _api_rate_limiter
    with _api_rate_limiter_lock:
        if _api_rate_limiter is None:
            _api_rate_limiter = ApiRateLimiter()
        return _api_rate_limiter
