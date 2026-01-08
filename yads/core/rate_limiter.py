import time
import random
import logging
from typing import Optional
import redis
from datetime import datetime

from yads.config import settings
from yads.models import SystemConfig
from yads.database import SessionLocal

logger = logging.getLogger(__name__)

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
        try:
            self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
            self._config_cache = {}
            self._last_cache_update = 0
            logger.info("RateLimiter initialized.")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis = None

    def _get_configured_delay(self) -> float:
        """
        Fetches the delay configuration from DB (cached).
        """
        now = time.time()
        if now - self._last_cache_update < self.CACHE_TTL and self.CONFIG_KEY in self._config_cache:
            return self._config_cache[self.CONFIG_KEY]
            
        try:
            with SessionLocal() as session:
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
