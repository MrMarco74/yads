"""
worker_core.py — Celery app setup, signals, global state, and helpers.

Re-exported via yads/worker.py for backwards compatibility.
"""
from celery import Celery
from sqlmodel import Session, select

from yads.config import settings
from yads.core.logging_config import configure_logging
from yads.core.worker_client import get_worker_client, initialize_worker_client, WorkerMode
from yads.core.metrics import get_metrics
from yads.models import Target, SystemConfig

# Configure Logging
logger = configure_logging("yads-worker")

# Global worker client instance
_worker_client = None

# Initialize Celery
celery_app = Celery("yads_worker", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.conf.worker_hijack_root_logger = False
celery_app.conf.task_time_limit = 3600       # hard kill after 60 min
celery_app.conf.task_soft_time_limit = 3480  # soft signal after 58 min (allows graceful cleanup)
celery_app.conf.timezone = 'UTC'

# ── Queue routing ─────────────────────────────────────────────────────────────
# Tasks on the 'discovery' queue are only consumed by workers that explicitly
# listen to it (via -Q celery,discovery).  Standard scan tasks stay on 'celery'.
from kombu import Queue as _Queue
celery_app.conf.task_queues = (
    _Queue("celery"),
    _Queue("discovery"),
)
celery_app.conf.task_routes = {
    "yads.worker.run_discovery_scan":      {"queue": "discovery"},
    "yads.worker.start_discovery_session": {"queue": "discovery"},
}

# Beat schedule — tasks registered in worker_tasks.py
celery_app.conf.beat_schedule = {
    'daily-security-trends': {
        'task': 'yads.worker.calculate_security_trends',
        'schedule': 24 * 3600.0,
    },
    'daily-compliance-trends': {
        'task': 'yads.worker.calculate_compliance_trends',
        'schedule': 24 * 3600.0,
    },
    'daily-email-digests': {
        'task': 'yads.worker.send_daily_digests',
        'schedule': 24 * 3600.0,
    },
    'daily-data-retention': {
        'task': 'yads.worker.prune_old_scan_results',
        'schedule': 24 * 3600.0,
    },
}

from celery.signals import worker_ready, worker_process_init, task_failure, task_revoked


@worker_ready.connect
def on_worker_ready(sender=None, **kwargs):
    """
    On Startup: reset any targets stuck in 'running' (leftover from a crash/kill),
    then check DB and pause consumer if needed.
    """
    logger.info("[Worker] Signal: Worker Ready. Checking Queue State...")

    # ── Crash recovery: reset orphaned running targets ────────────────────
    try:
        from yads.database import engine
        with Session(engine) as session:
            stuck = session.exec(select(Target).where(Target.scan_status == "running")).all()
            if stuck:
                for t in stuck:
                    t.scan_status = "idle"
                    t.scan_progress = "Reset on worker startup (previous run was interrupted)"
                    session.add(t)
                session.commit()
                logger.warning(f"[Worker] startup: Reset {len(stuck)} stuck target(s) to idle")
    except Exception as e:
        logger.error(f"[Worker] Failed to reset stuck targets on startup: {e}")

    # ── Queue pause check ─────────────────────────────────────────────────
    try:
        from yads.database import engine
        with Session(engine) as session:
            conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
            if conf and conf.value.lower() == "false":
                logger.warning("[Worker] startup: Queue is PAUSED in DB. Cancelling consumer.")
                sender.app.control.cancel_consumer('celery', reply=False, destination=[sender.hostname])
            else:
                logger.info("[Worker] startup: Queue is ACTIVE.")
    except Exception as e:
        logger.error(f"[Worker] Failed to check queue state on startup: {e}")


def _reset_target_status(target_id: int, reason: str):
    """Helper: reset a target's scan_status to idle. Called from failure signals."""
    try:
        from yads.database import engine
        with Session(engine) as s:
            t = s.get(Target, target_id)
            if t and t.scan_status == "running":
                t.scan_status = "idle"
                t.scan_progress = reason
                s.add(t)
                s.commit()
                logger.warning(f"[Worker] Reset target {target_id} to idle: {reason}")
    except Exception as e:
        logger.error(f"[Worker] Failed to reset target {target_id} status: {e}")


@task_failure.connect(sender="yads.worker.run_all_scans")
def on_task_failure(task_id, exception, args, kwargs, traceback, einfo, **kw):
    """Reset target status when a task fails (incl. SoftTimeLimitExceeded)."""
    target_id = args[0] if args else kwargs.get("target_id")
    if target_id:
        from celery.exceptions import SoftTimeLimitExceeded
        if isinstance(exception, SoftTimeLimitExceeded):
            reason = "Scan interrupted (soft time limit exceeded)"
        else:
            reason = f"Scan failed: {type(exception).__name__}"
        _reset_target_status(target_id, reason)


@task_revoked.connect(sender="yads.worker.run_all_scans")
def on_task_revoked(request, terminated, signum, expired, **kw):
    """Reset target status when a task is revoked or killed by hard time limit."""
    target_id = request.args[0] if request.args else (request.kwargs or {}).get("target_id")
    if target_id:
        _reset_target_status(target_id, "Scan interrupted (task revoked or hard time limit)")


@worker_process_init.connect
def on_worker_process_init(**kwargs):
    """
    On Worker Process Start: Dispose existing DB engine connections.
    This ensures each forked worker process gets a fresh connection pool,
    preventing 'PGRES_TUPLES_OK' and other multiprocessing DB errors.
    """
    global _worker_client
    from yads.database import engine
    logger.info("[Worker] Signal: Process Init. Disposing DB engine to reset pool.")
    try:
        engine.dispose()
    except Exception as e:
        logger.error(f"[Worker] Failed to dispose engine on process init: {e}")

    # Initialize bandwidth limiter and patch requests module
    try:
        _patch_requests_with_throttling()
        logger.info("[Worker] Bandwidth throttling enabled for HTTP requests")
    except Exception as e:
        logger.warning(f"[Worker] Failed to initialize bandwidth throttling: {e}")

    # Initialize worker client for distributed mode
    try:
        _worker_client = initialize_worker_client()
        if _worker_client.is_distributed:
            logger.info(f"[Worker] Distributed mode: {_worker_client.state.mode.value}, node_id: {_worker_client.node_id}")
        else:
            logger.info("[Worker] Running in standalone mode (no distributed coordination)")
    except Exception as e:
        logger.warning(f"[Worker] Failed to initialize worker client: {e}")

    # Store worker network info in Redis for system-wide access
    try:
        from yads.core.redis_logger import get_external_ip, get_worker_hostname, store_worker_network_info
        external_ip = get_external_ip()
        hostname = get_worker_hostname()
        worker_id = _worker_client.node_id if _worker_client and _worker_client.is_distributed else f"standalone-{hostname}"
        store_worker_network_info(worker_id, external_ip, hostname, ttl=7200)  # 2 hour TTL
        logger.info(f"[Worker] Network info registered: {external_ip} ({hostname})")
    except Exception as e:
        logger.warning(f"[Worker] Failed to register network info: {e}")


def _patch_requests_with_throttling():
    """
    Monkey-patch the requests module to use bandwidth throttling.
    This ensures all HTTP requests respect the NETWORK_RATE_LIMIT setting.
    """
    import requests
    from yads.core.rate_limiter import get_bandwidth_limiter

    bandwidth_limiter = get_bandwidth_limiter()
    _original_request = requests.Session.request

    def throttled_request(self, method, url, **kwargs):
        """Wrapper that adds bandwidth throttling to requests."""
        response = _original_request(self, method, url, **kwargs)
        try:
            request_size = len(url) + 500  # Headers estimate
            response_size = 0
            if hasattr(response, 'content') and response.content:
                response_size = len(response.content)
            elif hasattr(response, 'headers'):
                content_length = response.headers.get('content-length')
                if content_length:
                    response_size = int(content_length)
            total_bytes = request_size + response_size
            if total_bytes > 0:
                bandwidth_limiter.consume(total_bytes)
        except Exception as e:
            logger.debug(f"Bandwidth tracking error: {e}")
        return response

    requests.Session.request = throttled_request
    logger.debug("Patched requests.Session.request with bandwidth throttling")
