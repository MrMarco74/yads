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
