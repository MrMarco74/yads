"""Helper to inspect live Celery worker nodes."""
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


def get_celery_worker_nodes() -> List[Dict[str, Any]]:
    """
    Return a list of online Celery worker node dicts for UI display.
    Each dict: {full_name, display, concurrency, active, reserved}
    Returns [] on any error (Redis down, no workers, etc.)
    """
    try:
        from celery import Celery
        from yads.config import settings

        celery_app = Celery("yads_inspector", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
        i = celery_app.control.inspect(timeout=3.0)
        if i is None:
            return []

        active_raw  = i.active()  or {}
        reserved_raw = i.reserved() or {}
        stats_raw   = i.stats()   or {}

        all_names = set(active_raw) | set(reserved_raw) | set(stats_raw)
        nodes = []
        for wname in sorted(all_names):
            pool = stats_raw.get(wname, {}).get("pool", {})
            concurrency = pool.get("max-concurrency") or len(pool.get("processes", ["?"]))
            active_count   = len(active_raw.get(wname, []))
            reserved_count = len(reserved_raw.get(wname, []))
            display = wname.split("@", 1)[-1] if "@" in wname else wname
            nodes.append({
                "full_name":   wname,
                "display":     display,
                "concurrency": concurrency,
                "active":      active_count,
                "reserved":    reserved_count,
            })
        return nodes
    except Exception as e:
        logger.debug(f"Celery inspect failed: {e}")
        return []
