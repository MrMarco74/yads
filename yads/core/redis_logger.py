import logging
import redis
import json
from datetime import datetime
import os

from yads.config import settings

class RedisLogHandler(logging.Handler):
    """
    Logging Handler that publishes logs to a Redis list.
    Also updates a 'status' key with the latest message for quick access.
    """
    def __init__(self, target_id: int, ttl: int = 3600):
        super().__init__()
        self.target_id = target_id
        self.ttl = ttl
        try:
            self.redis = redis.from_url(settings.REDIS_URL)
        except Exception:
            self.redis = None
        
        self.list_key = f"scan:logs:{target_id}"
        self.status_key = f"scan:status:{target_id}"

    def emit(self, record):
        # 1. Prevent infinite recursion from self-generated logs (e.g. redis connection errors)
        if record.name.startswith(("redis", "urllib3", "requests", "httpcore")):
            return

        # 2. Re-entry guard (safety)
        if getattr(self, '_emitting', False):
            return
            
        if not self.redis:
            return

        self._emitting = True
        try:
            msg = self.format(record)
            
            entry = {
                "ts": datetime.utcnow().isoformat(),
                "level": record.levelname,
                "msg": msg
            }
            
            # Push to List
            self.redis.rpush(self.list_key, json.dumps(entry))
            # Trim to keep last 200 lines to avoid memory explosion
            self.redis.ltrim(self.list_key, -200, -1)
            
            # Update Status Key
            status_update = msg
            if hasattr(record, 'name') and record.name:
                short_name = record.name.split('.')[-1]
                status_update = f"[{short_name}] {msg}"
            
            self.redis.set(self.status_key, status_update)
            
            # Set Expiry
            self.redis.expire(self.list_key, self.ttl)
            self.redis.expire(self.status_key, self.ttl)
            
        except Exception:
            # If we fail here, we MUST NOT log, or we loop.
            # Just handleError which writes to stderr usually
            self.handleError(record)
        finally:
            self._emitting = False
