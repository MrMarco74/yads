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
# broker=RabbitMQ (durable, ACK-based), backend=Valkey (result/log cache only)
celery_app = Celery("yads_worker", broker=settings.BROKER_URL, backend=settings.REDIS_URL)
celery_app.conf.worker_hijack_root_logger = False
celery_app.conf.task_time_limit = 3600       # hard kill after 60 min
celery_app.conf.task_soft_time_limit = 3480  # soft signal after 58 min (allows graceful cleanup)
celery_app.conf.timezone = 'UTC'
# Reliable delivery: tasks are ACK'd only after successful completion.
# If a worker dies mid-task, RabbitMQ re-queues the message automatically.
celery_app.conf.task_acks_late = True
celery_app.conf.task_reject_on_worker_lost = True

# ── Queue routing ─────────────────────────────────────────────────────────────
# Tasks on the 'discovery' queue are only consumed by workers that explicitly
# listen to it (via -Q celery,discovery).  Standard scan tasks stay on 'celery'.
#
# 'utility' is for admin-triggered utility tasks (tool availability checks,
# on-demand template updates) that must keep working even while the scan
# queue is paused. Pausing (queue.py/mobile.py/worker_core.py's
# on_worker_ready) cancels the 'celery' and 'discovery' consumers by literal
# name, never a wildcard/"cancel everything" call -- so a distinctly-named
# queue is naturally invisible to all of that pause/resume logic and needs
# no changes there. See scripts/start_worker.py for the matching -Q entry.
from kombu import Queue as _Queue, Exchange as _Exchange
_default_exchange = _Exchange("celery", type="direct", durable=True)
_discovery_exchange = _Exchange("discovery", type="direct", durable=True)
_utility_exchange = _Exchange("utility", type="direct", durable=True)
celery_app.conf.task_queues = (
    _Queue("celery",    _default_exchange,   routing_key="celery",    durable=True),
    _Queue("discovery", _discovery_exchange, routing_key="discovery", durable=True),
    _Queue("utility",   _utility_exchange,   routing_key="utility",   durable=True),
)
celery_app.conf.task_routes = {
    "yads.worker.run_discovery_scan":      {"queue": "discovery"},
    "yads.worker.start_discovery_session": {"queue": "discovery"},
    "yads.worker.check_nmap_available":    {"queue": "utility"},
    "yads.worker.check_nuclei_available":  {"queue": "utility"},
    "yads.worker.update_nuclei_templates": {"queue": "utility"},
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
    'stuck-job-cleaner': {
        'task': 'yads.worker.reset_stuck_targets',
        'schedule': 5 * 60.0,  # every 5 minutes
    },
    'external-integration-sync': {
        'task': 'yads.worker.sync_external_integrations',
        'schedule': 15 * 60.0, # every 15 minutes
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

    # ── Crash recovery: reset orphaned running/queued targets ─────────────
    try:
        from yads.database import engine
        with Session(engine) as session:
            stuck = session.exec(
                select(Target).where(Target.scan_status.in_(["running", "queued"]))
            ).all()
            if stuck:
                for t in stuck:
                    t.scan_status = "idle"
                    t.queued_at = None
                    t.scan_progress = "Reset on worker startup (previous run was interrupted)"
                    session.add(t)
                session.commit()
                logger.warning(f"[Worker] startup: Reset {len(stuck)} stuck target(s) to idle (running + queued)")
    except Exception as e:
        logger.error(f"[Worker] Failed to reset stuck targets on startup: {e}")

    # ── Load custom-installed modules into runtime registry ────────────────
    try:
        from yads.core.custom_modules_loader import load_installed_modules_from_db
        from yads.database import engine
        with Session(engine) as _s:
            load_installed_modules_from_db(_s)
    except Exception as e:
        logger.error(f"[Worker] Failed to load custom modules on startup: {e}")

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
