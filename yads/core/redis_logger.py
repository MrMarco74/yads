import logging
import redis
import json
from datetime import datetime
import os
from typing import Optional

from yads.config import settings
from yads.database import redis_client


class RedisLogHandler(logging.Handler):
    """
    Logging Handler that publishes logs to a Redis list.
    Also updates a 'status' key with the latest message for quick access.
    """
    def __init__(self, target_id: int, ttl: int = 3600):
        super().__init__()
        self.target_id = target_id
        self.ttl = ttl
        self.redis = redis_client

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


class DistributedRedisLogHandler(logging.Handler):
    """
    Enhanced Logging Handler for distributed workers.

    Publishes logs to multiple Redis keys:
    1. scan:logs:{target_id} - Per-target logs (backward compatible)
    2. scan:logs:tenant:{tenant_id} - Tenant aggregate logs (ZSET for time ordering)
    3. scan:logs:worker:{node_id} - Worker-specific logs for debugging

    Each log entry includes tenant and worker metadata for filtering.
    """

    def __init__(self, target_id: int, tenant_id: Optional[int] = None,
                 worker_node_id: Optional[str] = None, ttl: int = 3600):
        super().__init__()
        self.target_id = target_id
        self.tenant_id = tenant_id
        self.worker_node_id = worker_node_id
        self.ttl = ttl
        self.redis = redis_client

        # Key definitions
        self.list_key = f"scan:logs:{target_id}"
        self.status_key = f"scan:status:{target_id}"
        self.tenant_key = f"scan:logs:tenant:{tenant_id}" if tenant_id else None
        self.worker_key = f"scan:logs:worker:{worker_node_id}" if worker_node_id else None

        # Unified log stream key (for aggregated view)
        self.unified_key = "scan:logs:unified"

    def emit(self, record):
        # 1. Prevent infinite recursion from self-generated logs
        if record.name.startswith(("redis", "urllib3", "requests", "httpcore", "psutil")):
            return

        # 2. Re-entry guard
        if getattr(self, '_emitting', False):
            return

        if not self.redis:
            return

        self._emitting = True
        try:
            msg = self.format(record)
            now = datetime.utcnow()
            timestamp = now.timestamp()

            # Build log entry with metadata
            entry = {
                "ts": now.isoformat(),
                "level": record.levelname,
                "msg": msg,
                "target_id": self.target_id,
                "tenant_id": self.tenant_id,
                "worker_node_id": self.worker_node_id,
                "module": record.name.split('.')[-1] if record.name else None
            }
            entry_json = json.dumps(entry)

            # Pipeline for efficiency
            pipe = self.redis.pipeline()

            # 1. Per-target logs (backward compatible)
            pipe.rpush(self.list_key, entry_json)
            pipe.ltrim(self.list_key, -200, -1)
            pipe.expire(self.list_key, self.ttl)

            # Update status key
            status_update = msg
            if record.name:
                short_name = record.name.split('.')[-1]
                status_update = f"[{short_name}] {msg}"
            pipe.set(self.status_key, status_update)
            pipe.expire(self.status_key, self.ttl)

            # 2. Tenant aggregate logs (ZSET for time-ordered retrieval)
            if self.tenant_key:
                pipe.zadd(self.tenant_key, {entry_json: timestamp})
                # Keep last 1000 entries per tenant
                pipe.zremrangebyrank(self.tenant_key, 0, -1001)
                pipe.expire(self.tenant_key, self.ttl * 2)  # Longer TTL for aggregates

            # 3. Worker-specific logs
            if self.worker_key:
                pipe.rpush(self.worker_key, entry_json)
                pipe.ltrim(self.worker_key, -500, -1)  # Keep more for debugging
                pipe.expire(self.worker_key, self.ttl)

            # 4. Unified log stream (capped at 5000 entries)
            pipe.zadd(self.unified_key, {entry_json: timestamp})
            pipe.zremrangebyrank(self.unified_key, 0, -5001)
            pipe.expire(self.unified_key, self.ttl)

            pipe.execute()

        except Exception:
            self.handleError(record)
        finally:
            self._emitting = False


def get_target_logs(target_id: int, limit: int = 200) -> list:
    """
    Retrieve logs for a specific target.

    Args:
        target_id: Target ID to get logs for
        limit: Maximum number of log entries to return

    Returns:
        List of log entries (oldest first)
    """
    if not redis_client:
        return []

    try:
        key = f"scan:logs:{target_id}"
        entries = redis_client.lrange(key, -limit, -1)
        return [json.loads(e) for e in entries]
    except Exception:
        return []


def get_tenant_logs(tenant_id: int, limit: int = 500,
                    since_timestamp: float = None) -> list:
    """
    Retrieve aggregated logs for a tenant.

    Args:
        tenant_id: Tenant ID to get logs for
        limit: Maximum number of log entries to return
        since_timestamp: Only return logs after this timestamp

    Returns:
        List of log entries (newest first)
    """
    if not redis_client:
        return []

    try:
        key = f"scan:logs:tenant:{tenant_id}"

        if since_timestamp:
            # Get entries after timestamp
            entries = redis_client.zrangebyscore(
                key, since_timestamp, "+inf",
                start=0, num=limit,
                withscores=True
            )
        else:
            # Get latest entries
            entries = redis_client.zrevrange(key, 0, limit - 1, withscores=True)

        result = []
        for entry_json, score in entries:
            try:
                entry = json.loads(entry_json)
                entry["score"] = score
                result.append(entry)
            except:
                pass

        return result
    except Exception:
        return []


def get_worker_logs(worker_node_id: str, limit: int = 500) -> list:
    """
    Retrieve logs for a specific worker.

    Args:
        worker_node_id: Worker node ID to get logs for
        limit: Maximum number of log entries to return

    Returns:
        List of log entries (oldest first)
    """
    if not redis_client:
        return []

    try:
        key = f"scan:logs:worker:{worker_node_id}"
        entries = redis_client.lrange(key, -limit, -1)
        return [json.loads(e) for e in entries]
    except Exception:
        return []


def get_unified_logs(limit: int = 500, since_timestamp: float = None,
                     tenant_id: int = None, worker_node_id: str = None,
                     level: str = None) -> list:
    """
    Retrieve unified logs with optional filtering.

    Args:
        limit: Maximum number of log entries to return
        since_timestamp: Only return logs after this timestamp
        tenant_id: Filter by tenant ID
        worker_node_id: Filter by worker node ID
        level: Filter by log level (INFO, WARNING, ERROR)

    Returns:
        List of log entries (newest first)
    """
    if not redis_client:
        return []

    try:
        key = "scan:logs:unified"

        if since_timestamp:
            entries = redis_client.zrangebyscore(
                key, since_timestamp, "+inf",
                start=0, num=limit * 2,  # Fetch more for filtering
                withscores=True
            )
        else:
            entries = redis_client.zrevrange(key, 0, limit * 2 - 1, withscores=True)

        result = []
        for entry_json, score in entries:
            try:
                entry = json.loads(entry_json)

                # Apply filters
                if tenant_id and entry.get("tenant_id") != tenant_id:
                    continue
                if worker_node_id and entry.get("worker_node_id") != worker_node_id:
                    continue
                if level and entry.get("level") != level:
                    continue

                entry["score"] = score
                result.append(entry)

                if len(result) >= limit:
                    break
            except:
                pass

        return result
    except Exception:
        return []


def get_target_status(target_id: int) -> Optional[str]:
    """Get the current status message for a target."""
    if not redis_client:
        return None

    try:
        key = f"scan:status:{target_id}"
        return redis_client.get(key)
    except Exception:
        return None


def clear_target_logs(target_id: int):
    """Clear all logs for a target."""
    if not redis_client:
        return

    try:
        redis_client.delete(f"scan:logs:{target_id}")
        redis_client.delete(f"scan:status:{target_id}")
    except Exception:
        pass
