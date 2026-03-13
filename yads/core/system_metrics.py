"""
System Metrics Collector

Polls CPU, RAM and network throughput via psutil every 2 seconds
and stores the result in Redis (TTL 10s) so all API workers share
a single reading without each spawning their own psutil calls.
"""

import threading
import time
import json
import logging

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

logger = logging.getLogger("yads.system_metrics")

_thread: threading.Thread | None = None
_stop_event = threading.Event()

_REDIS_KEY = "yads:metrics:system"
_INTERVAL = 2  # seconds between samples


def _collect_loop(redis_client) -> None:
    """Background loop: sample psutil every _INTERVAL seconds."""
    if not _PSUTIL_AVAILABLE:
        logger.warning("psutil not available — system metrics collection disabled.")
        return
    prev_net = psutil.net_io_counters()
    prev_time = time.monotonic()

    # Prime cpu_percent (first call always returns 0.0)
    psutil.cpu_percent(interval=None)

    while not _stop_event.is_set():
        time.sleep(_INTERVAL)
        try:
            now = time.monotonic()
            elapsed = now - prev_time

            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            net = psutil.net_io_counters()

            # Delta-based throughput in MBit/s
            mbps_out = (net.bytes_sent - prev_net.bytes_sent) * 8 / (elapsed * 1_000_000) if elapsed > 0 else 0.0
            mbps_in  = (net.bytes_recv - prev_net.bytes_recv) * 8 / (elapsed * 1_000_000) if elapsed > 0 else 0.0

            prev_net = net
            prev_time = now

            payload = json.dumps({
                "cpu_percent":  round(cpu, 1),
                "mem_used_gb":  round(mem.used  / 1_073_741_824, 1),
                "mem_total_gb": round(mem.total / 1_073_741_824, 1),
                "mem_percent":  round(mem.percent, 1),
                "net_in_mbps":  round(mbps_in,  1),
                "net_out_mbps": round(mbps_out, 1),
            })
            redis_client.setex(_REDIS_KEY, 10, payload)

        except Exception as exc:
            logger.debug(f"system_metrics sample error: {exc}")


def start(redis_url: str) -> None:
    """Start the background metrics collector thread (idempotent)."""
    global _thread
    if _thread and _thread.is_alive():
        return

    import redis as redis_lib
    client = redis_lib.from_url(redis_url, socket_connect_timeout=2)

    _stop_event.clear()
    _thread = threading.Thread(
        target=_collect_loop,
        args=(client,),
        name="system-metrics",
        daemon=True,
    )
    _thread.start()
    logger.info("System metrics collector started.")


def stop() -> None:
    """Signal the background thread to stop."""
    _stop_event.set()


def get(redis_client) -> dict | None:
    """Read the latest metrics snapshot from Redis. Returns None if unavailable."""
    try:
        raw = redis_client.get(_REDIS_KEY)
        return json.loads(raw) if raw else None
    except Exception:
        return None
