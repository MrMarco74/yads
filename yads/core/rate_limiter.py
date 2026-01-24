import time
import random
import logging
import threading
from typing import Optional
import redis
from datetime import datetime

from yads.config import settings
from yads.models import SystemConfig
from yads.database import engine, redis_client
from sqlmodel import Session

logger = logging.getLogger(__name__)

# Global bandwidth limiter instance
_bandwidth_limiter = None
_bandwidth_lock = threading.Lock()

class RateLimiter:
    """
    Centralized Rate Limiter using Redis.
    Enforces a delay between requests to the same domain.
    """
    
    KEY_PREFIX = "rate_limit:domain:"
    CONFIG_KEY = "WEB_RATE_LIMIT_DELAY"
    DEFAULT_DELAY = 2.0
    CACHE_TTL = 60 # How long to cache the DB config in memory
    
    def __init__(self):
        self.redis = redis_client
        self._config_cache = {}
        self._last_cache_update = 0
        logger.info("RateLimiter initialized.")

    def _get_configured_delay(self) -> float:
        """
        Fetches the delay configuration from DB (cached).
        """
        now = time.time()
        if now - self._last_cache_update < self.CACHE_TTL and self.CONFIG_KEY in self._config_cache:
            return self._config_cache[self.CONFIG_KEY]
            
        try:
            with Session(engine) as session:
                conf = session.get(SystemConfig, self.CONFIG_KEY)
                val = float(conf.value) if conf else self.DEFAULT_DELAY
                self._config_cache[self.CONFIG_KEY] = val
                self._last_cache_update = now
                return val
        except Exception as e:
            logger.error(f"Error fetching rate limit config: {e}")
            return self.DEFAULT_DELAY

    def wait(self, domain: str):
        """
        Blocks until the rate limit for the domain allows a new request.
        """
        if not self.redis:
            return

        delay = self._get_configured_delay()
        if delay <= 0:
            return

        key = f"{self.KEY_PREFIX}{domain}"
        
        try:
            last_access = self.redis.get(key)
            if last_access:
                last_time = float(last_access)
                now = time.time()
                elapsed = now - last_time
                
                if elapsed < delay:
                    # Calculate sleep time
                    sleep_needed = delay - elapsed
                    # Add Jitter (0-20% of delay)
                    jitter = random.uniform(0, delay * 0.2)
                    total_sleep = sleep_needed + jitter
                    
                    logger.info(f"Rate limiting {domain}: sleeping {total_sleep:.2f}s")
                    time.sleep(total_sleep)
            
            # Update last access
            self.redis.set(key, time.time(), ex=3600) # Expire after 1 hour to clean up
            
        except Exception as e:
            logger.warning(f"Rate limiter error for {domain}: {e}")


class BandwidthLimiter:
    """
    Global bandwidth limiter using Redis token bucket algorithm.
    Limits total outgoing bandwidth across all workers.
    """

    BUCKET_KEY = "bandwidth:tokens"
    LAST_UPDATE_KEY = "bandwidth:last_update"
    CONFIG_KEY = "NETWORK_RATE_LIMIT"
    CACHE_TTL = 30  # Refresh config every 30 seconds

    def __init__(self):
        self.redis = redis_client
        self._config_cache = None
        self._last_cache_update = 0
        self._local_lock = threading.Lock()
        logger.info("BandwidthLimiter initialized.")

    def _get_limit_mbps(self) -> float:
        """Get configured bandwidth limit in Mbit/s from DB (cached)."""
        now = time.time()
        if now - self._last_cache_update < self.CACHE_TTL and self._config_cache is not None:
            return self._config_cache

        try:
            with Session(engine) as session:
                conf = session.get(SystemConfig, self.CONFIG_KEY)
                val = float(conf.value) if conf and conf.value else 0.0
                self._config_cache = val
                self._last_cache_update = now
                return val
        except Exception as e:
            logger.error(f"Error fetching bandwidth limit config: {e}")
            return 0.0  # 0 = unlimited

    def _get_limit_bytes_per_sec(self) -> float:
        """Convert Mbit/s to bytes/second."""
        mbps = self._get_limit_mbps()
        if mbps <= 0:
            return 0  # Unlimited
        return (mbps * 1_000_000) / 8  # Mbit to bytes

    def consume(self, bytes_count: int):
        """
        Consume bandwidth tokens. Blocks if limit would be exceeded.
        Uses Redis for coordination across workers.

        Args:
            bytes_count: Number of bytes to consume
        """
        limit_bps = self._get_limit_bytes_per_sec()
        if limit_bps <= 0:
            return  # No limit configured

        if not self.redis:
            return

        with self._local_lock:
            try:
                now = time.time()

                # Get current bucket state from Redis
                pipe = self.redis.pipeline()
                pipe.get(self.BUCKET_KEY)
                pipe.get(self.LAST_UPDATE_KEY)
                results = pipe.execute()

                tokens = float(results[0]) if results[0] else limit_bps
                last_update = float(results[1]) if results[1] else now

                # Refill tokens based on time elapsed
                elapsed = now - last_update
                tokens = min(limit_bps, tokens + (elapsed * limit_bps))

                # Check if we need to wait
                if bytes_count > tokens:
                    # Calculate wait time
                    needed = bytes_count - tokens
                    wait_time = needed / limit_bps

                    if wait_time > 0.01:  # Only log significant waits
                        logger.debug(f"Bandwidth throttle: waiting {wait_time:.2f}s for {bytes_count} bytes")

                    time.sleep(wait_time)
                    tokens = bytes_count  # After waiting, we have enough

                # Consume tokens
                tokens -= bytes_count

                # Update Redis
                pipe = self.redis.pipeline()
                pipe.set(self.BUCKET_KEY, tokens, ex=60)
                pipe.set(self.LAST_UPDATE_KEY, now, ex=60)
                pipe.execute()

            except Exception as e:
                logger.warning(f"Bandwidth limiter error: {e}")

    def track_response(self, response_bytes: int):
        """Track bytes received (for accurate bandwidth accounting)."""
        self.consume(response_bytes)


def get_bandwidth_limiter() -> BandwidthLimiter:
    """Get or create the global bandwidth limiter instance."""
    global _bandwidth_limiter
    with _bandwidth_lock:
        if _bandwidth_limiter is None:
            _bandwidth_limiter = BandwidthLimiter()
        return _bandwidth_limiter
