from celery import Celery
from sqlmodel import Session, create_engine, select
from yads.models import ScanResult, Target, SystemConfig, Tenant, SecurityTrend, ComplianceTrend, ComplianceTargetStatus
from datetime import datetime
import os
import dns.resolver

from yads.config import settings
from yads.core.logging_config import configure_logging
from yads.modules.dns_scanner import SubdomainScanner, DNSRecordScanner
from yads.modules.web_analyzer import WebAnalyzer
from yads.modules.visual_osint import VisualOSINT
from yads.modules.visual_osint import VisualOSINT
from yads.core.splunk_logger import splunk_logger
from yads.core.webhook_service import webhook_service
from yads.core.base import sanitize_null_bytes
from yads.core.worker_client import get_worker_client, initialize_worker_client, WorkerMode
from yads.core.metrics import get_metrics

# Configure Logging
logger = configure_logging("yads-worker")

# Global worker client instance
_worker_client = None

# Initialize Celery
celery_app = Celery("yads_worker", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.conf.worker_hijack_root_logger = False
celery_app.conf.task_time_limit = 3600       # hard kill after 60 min
celery_app.conf.task_soft_time_limit = 3480  # soft signal after 58 min (allows graceful cleanup)

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
        with Session(engine) as session:
            from yads.models import Target
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
        with Session(engine) as session:
            from yads.models import SystemConfig
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

    # Store original functions
    _original_request = requests.Session.request

    def throttled_request(self, method, url, **kwargs):
        """Wrapper that adds bandwidth throttling to requests."""
        # Make the request
        response = _original_request(self, method, url, **kwargs)

        # Track bandwidth usage
        try:
            # Estimate request size
            request_size = len(url) + 500  # Headers estimate

            # Track response size
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

    # Apply patch
    requests.Session.request = throttled_request
    logger.debug("Patched requests.Session.request with bandwidth throttling")


# Database access for worker

# Database access for worker
from yads.database import engine

@celery_app.task(name="yads.worker.auto_dns_cleanup")
def auto_dns_cleanup():
    """
    Periodic task to check DNS health for all active targets.
    """
    logger.info("[Worker] Starting periodic DNS cleanup scan for all active targets")
    try:
        with Session(engine) as session:
            # Query all non-archived targets
            targets = session.exec(select(Target).where(Target.is_archived == False)).all()
            
            for t in targets:
                # Dispatch a scan with only dns_cleanup module
                celery_app.send_task(
                    "yads.worker.run_all_scans", 
                    args=[t.id, t.domain, ["dns_cleanup"], t.tenant_id]
                )
            
            logger.info(f"[Worker] Dispatched DNS health checks for {len(targets)} targets.")
    except Exception as e:
        logger.error(f"[Worker] Failed to run auto_dns_cleanup: {e}")

# -- Periodic Schedule Configuration --
celery_app.conf.beat_schedule = {
    'periodic-dns-cleanup': {
        'task': 'yads.worker.auto_dns_cleanup',
        'schedule': 6 * 3600.0, # Run every 6 hours (in seconds)
    },
    'daily-security-trends': {
        'task': 'yads.worker.calculate_security_trends',
        'schedule': 24 * 3600.0, # Run every 24 hours
    },
    'daily-compliance-trends': {
        'task': 'yads.worker.calculate_compliance_trends',
        'schedule': 24 * 3600.0, # Run every 24 hours
    },
}
celery_app.conf.timezone = 'UTC'


@celery_app.task(name="yads.worker.calculate_security_trends")
def calculate_security_trends():
    """
    Calculates and stores daily security score averages for each tenant.
    """
    from yads.core.scoring import calculate_target_score
    from yads.database import engine
    from yads.models import Tenant, Target, ScanResult, SecurityTrend
    from sqlmodel import Session, select, text
    import logging

    logger = logging.getLogger("yads-worker")
    logger.info("[Worker] Starting daily security trend calculation...")

    try:
        with Session(engine) as session:
            # 1. Fetch all tenants
            tenants = session.exec(select(Tenant)).all()
            
            for tenant in tenants:
                # 2. Fetch all non-archived targets for this tenant
                targets = session.exec(select(Target).where(
                    Target.tenant_id == tenant.id,
                    Target.is_archived == False
                )).all()
                
                if not targets:
                    continue
                
                total_target_score = 0
                count = 0
                
                for t in targets:
                    # 3. Get latest results for this target
                    # Using similar logic to compliance/dashboard
                    query = f"""
                        SELECT DISTINCT ON (module_name) 
                            module_name, data 
                        FROM scanresult 
                        WHERE target_id = {t.id}
                          AND module_name IN ('ssl_scanner', 'web_analyzer', 'port_scanner')
                        ORDER BY module_name, scanned_at DESC
                    """
                    latest_rows = session.exec(text(query)).all()
                    
                    # Convert to dict for scoring function
                    class MockRes:
                        def __init__(self, data): self.data = data
                    
                    latest_results = {row[0]: MockRes(row[1]) for row in latest_rows}
                    
                    # 4. Calculate Score
                    score, grade, factors = calculate_target_score(t, latest_results)
                    total_target_score += score
                    count += 1
                
                if count > 0:
                    avg_score = total_target_score / count
                    
                    # 5. Store in SecurityTrend
                    trend = SecurityTrend(
                        tenant_id=tenant.id,
                        score=round(avg_score),
                        grade=calculate_target_score(None, {})[1], # Default grade logic reuse or just pass avg?
                        # actually get_grade is a better helper
                    )
                    # Use get_grade from scoring
                    from yads.core.scoring import get_grade
                    trend.grade = get_grade(round(avg_score))
                    
                    session.add(trend)
                    logger.info(f"[Worker] Recorded trend for tenant {tenant.name}: {avg_score:.1f} ({trend.grade})")
            
            session.commit()
            logger.info("[Worker] Security trend calculation finished.")
    except Exception as e:
        logger.error(f"[Worker] Failed to calculate security trends: {e}")


@celery_app.task(name="yads.worker.calculate_compliance_trends")
def calculate_compliance_trends():
    """
    Calculates and stores daily compliance scores for each tenant and framework.
    """
    from yads.modules.compliance_frameworks import FRAMEWORKS, get_framework_scorer
    from yads.database import engine
    from yads.models import Tenant, Target, ComplianceTrend
    from sqlmodel import Session, select, text
    import logging

    logger = logging.getLogger("yads-worker")
    logger.info("[Worker] Starting daily compliance trend calculation...")

    try:
        with Session(engine) as session:
            # Fetch all tenants
            tenants = session.exec(select(Tenant)).all()

            for tenant in tenants:
                # Fetch all non-archived targets for this tenant
                targets = session.exec(select(Target).where(
                    Target.tenant_id == tenant.id,
                    Target.is_archived == False
                )).all()

                if not targets:
                    continue

                # Get latest scan results for all targets
                target_ids = [t.id for t in targets]
                target_ids_str = ",".join(str(tid) for tid in target_ids)

                query = f"""
                    SELECT DISTINCT ON (target_id, module_name)
                        target_id, module_name, data
                    FROM scanresult
                    WHERE target_id IN ({target_ids_str})
                    ORDER BY target_id, module_name, scanned_at DESC
                """
                results = session.exec(text(query)).all()

                # Build target data structure
                target_data = {t.id: {} for t in targets}
                target_map = {t.id: t.domain for t in targets}

                for tid, mod, data in results:
                    if tid in target_data:
                        target_data[tid][mod] = data

                # Calculate score for each framework
                for framework_id in FRAMEWORKS.keys():
                    try:
                        scorer = get_framework_scorer(framework_id)
                        stats = scorer.calculate_score(target_data, target_map)

                        # Store trend record
                        trend = ComplianceTrend(
                            tenant_id=tenant.id,
                            framework=framework_id,
                            score=stats.get('score', 100),
                            grade=stats.get('grade', 'A'),
                            passing_controls=stats.get('passing_controls', 0),
                            failing_controls=stats.get('failing_controls', 0)
                        )
                        session.add(trend)
                        logger.info(f"[Worker] Recorded {framework_id} trend for tenant {tenant.name}: {stats.get('score')}%")

                    except Exception as fw_e:
                        logger.warning(f"[Worker] Failed to calculate {framework_id} trend: {fw_e}")

            session.commit()
            logger.info("[Worker] Compliance trend calculation finished.")
    except Exception as e:
        logger.error(f"[Worker] Failed to calculate compliance trends: {e}")


import io


import logging

class LogCapture:
    """
    Context manager to capture logs to a string.
    """
    def __init__(self):
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s"))
    
    def __enter__(self):
        # Attach to root logger to capture everything
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.getLogger().removeHandler(self.handler)
        self.handler.close()

    def get_logs(self):
        return self.log_stream.getvalue()


import socket
from concurrent.futures import ThreadPoolExecutor, wait as _futures_wait, ALL_COMPLETED


def _run_parallel_module(module_cls, target_id: int, domain: str):
    """
    Run a scanner module in its own DB session (thread-safe parallel execution).
    Each parallel module gets an isolated session; results are committed independently.
    LogCapture is intentionally skipped to avoid root-logger thread-safety issues —
    logs still flow via the Redis handler attached by the parent task.
    """
    from yads.utils.sanitize import sanitize_null_bytes
    try:
        with Session(engine) as session:
            mod = module_cls(db_session=session)
            result = mod.process(target_id, domain)
            if result and hasattr(result, 'log_content'):
                session.add(result)
                session.commit()
            logger.info(f"[Worker] Parallel: {mod.module_name} finished.")
    except Exception as e:
        logger.error(f"[Worker] Parallel module {module_cls.__name__} error: {e}")


def _run_simple_module(module_cls, target_id: int, domain: str, session, progress_msg: str = None):
    """
    DRY helper for simple scanner modules.
    Updates scan_progress, runs module, saves log_content.
    Returns True on success, False on error.
    """
    if progress_msg:
        t = session.get(Target, target_id)
        if t:
            t.scan_progress = progress_msg
            session.add(t)
            session.commit()
    try:
        scanner = module_cls(db_session=session)
        logger.info(f"[Worker] Running {scanner.module_name}...")
        with LogCapture() as logs:
            logger.info(f"Starting {scanner.module_name} for {domain}")
            result = scanner.process(target_id, domain)
            captured_logs = logs.get_logs()
        if result and hasattr(result, 'log_content'):
            result.log_content = sanitize_null_bytes(captured_logs)
            session.add(result)
            session.commit()
        print(f"[Worker] {scanner.module_name} finished.")
        return True
    except Exception as e:
        logger.error(f"[Worker] Error in {module_cls.__name__}: {e}")
        session.rollback()
        return False


@celery_app.task(name="yads.worker.run_all_scans", bind=True)
def run_all_scans(self, target_id: int, domain: str, scan_types: list[str] = None, tenant_id: int = None, ignore_queue_pause: bool = False):
    """
    Main orchestration task.
    Runs configured scanners for the given target.
    If scan_types is None, runs all available scanners.
    tenant_id is passed for queue filtering purposes (actual tenant is derived from target in DB).
    """
    bind = True # Required for self.retry to work? No, need to change decorator

    if scan_types is None:
        # Default now only includes DNS reconnaissance as per user request.
        scan_types = ["dns_cleanup", "subdomain_scanner", "dns_scanner"]
        
    logger.info(f"[Worker] Starting scan for {domain} (ID: {target_id}) with types: {scan_types}")

    # --- License Enforcement ---
    from yads.core.license import license_manager
    try:
        with Session(engine) as session:
            from yads.models import SystemConfig
            lc = session.exec(select(SystemConfig).where(SystemConfig.key == "license_key")).first()
            valid_license = False
            if lc and lc.value:
                if license_manager.verify(lc.value):
                    valid_license = True
            
            if not valid_license:
                logger.warning(f"[Worker] License Invalid or Missing. Discarding task for {domain}.")
                return
    except Exception as e:
        logger.error(f"[Worker] License check failed: {e}")
        # Fail safe? Or Fail closed? Fail closed for enforcement.
        return
    # ---------------------------

    def check_port(host, port, timeout=2):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except:
            return False

    # Setup Redis Logging (with distributed support)
    from yads.core.redis_logger import (
        DistributedRedisLogHandler, RedisLogHandler,
        get_external_ip, get_worker_hostname, resolve_target_ips,
        store_worker_network_info
    )

    # Use distributed handler if worker client is available
    global _worker_client
    worker_node_id = _worker_client.node_id if _worker_client and _worker_client.is_distributed else None

    # Get external IP for logging (cached, won't delay scans)
    external_ip = get_external_ip()
    worker_hostname = get_worker_hostname()

    # Store worker network info in Redis for system-wide access
    effective_worker_id = worker_node_id or f"standalone-{worker_hostname}"
    store_worker_network_info(effective_worker_id, external_ip, worker_hostname)

    if worker_node_id:
        redis_handler = DistributedRedisLogHandler(
            target_id=target_id,
            tenant_id=tenant_id,
            worker_node_id=worker_node_id,
            external_ip=external_ip
        )
    else:
        redis_handler = RedisLogHandler(target_id, external_ip=external_ip)

    # Be more specific with logger format for UI
    redis_handler.setFormatter(logging.Formatter("%(message)s"))

    # Attach to root logger to capture everything during this task
    # We use a try/finally block around the entire scan logic to ensure removal
    root_logger = logging.getLogger()
    root_logger.addHandler(redis_handler)

    # Log network information at scan start (for debugging and audit)
    target_ips = resolve_target_ips(domain)
    logger.info(f"[Network] Scan initiated from {external_ip or 'unknown'} ({worker_hostname})")
    if target_ips:
        logger.info(f"[Network] Target {domain} resolves to: {', '.join(target_ips)}")
    else:
        logger.info(f"[Network] Target {domain} - DNS resolution pending")

    # Report task started to worker manager
    celery_task_id = self.request.id if hasattr(self, 'request') and self.request else None
    if _worker_client and _worker_client.is_distributed and celery_task_id:
        _worker_client.report_task_started(celery_task_id)

    try:
        with Session(engine) as session:
            # 0. Check for Global Stop (Panic Button)
            from yads.models import SystemConfig
            conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
            
            # DEBUG LOGGING FOR STATE
            conf_val = conf.value if conf else "None"
            logger.info(f"[Worker] Checking QUEUE_ACTIVE for {domain}. DB Value: '{conf_val}', IgnorePause: {ignore_queue_pause}")
            
            # DEFAULT TO PAUSED IF CONFIG IS MISSING (Safety First)
            is_paused = True 
            if conf and conf.value.lower() == "true":
                is_paused = False
            
            if ignore_queue_pause:
                is_paused = False

            if is_paused:
                logger.warning(f"[Worker] Queue is PAUSED. Re-queuing scan for {domain} (ID: {target_id}).")
                # Instead of aborting (which drops the task), we retry it later.
                # This keeps it in the system but delays it.
                # Max retries? If unlimited, it will loop. 
                # Better: Ensure consumer is cancelled, then retry ONCE to put it back in queue?
                # Or just raise Retry?
                
                # Check if we should actually cancel the consumer here too?
                # on_worker_ready handles startup, but if it was missed:
                # Just retry. Do NOT cancel consumer here, as it risks the worker becoming "deaf" 
                # if it misses the resume signal.
                # A 60s retry loop is acceptable overhead.
                logger.warning(f"[Worker] Queue is PAUSED. Re-queuing scan for {domain} (ID: {target_id}).")
                
                # Retry in 60 seconds
                raise self.retry(countdown=60, max_retries=None)


            # Update Status to Running
            try:
                target = session.get(Target, target_id)
                if not target:
                    logger.warning(f"[Worker] Target {domain} (ID: {target_id}) not found in DB. Aborting scan.")
                    return
                
                target.scan_status = "running"
                target.scan_progress = "Initializing scan..."
                # Capture tenant_id for inheritance
                parent_tenant_id = target.tenant_id
                session.add(target)
                session.commit()
                
                # Splunk Event: Scan Start
                splunk_logger.send_security_event(
                    action="scan_start",
                    user="system:worker",
                    mitre_id="TA0007", # Discovery
                    details={
                        "target_id": target_id,
                        "domain": domain,
                        "scan_types": scan_types
                    },
                    tenant_id=parent_tenant_id
                )

                # Prometheus Metrics: Scan Start
                prom_metrics = get_metrics()
                prom_metrics.record_scan_started(
                    tenant_id=parent_tenant_id,
                    scan_types=scan_types
                )
                scan_start_time = datetime.utcnow()
            except Exception as e:
                logger.error(f"[Worker] Failed to update start status: {e}")
                session.rollback()
                return

            # Pre-check web availability to skip heavy web scans if offline
            has_http = False
            has_https = False
            
            # Only perform checks if web modules are requested
            web_modules = ["web_analyzer", "visual_osint", "ssl_scanner", "nuclei_scanner", "crawler", "content_discovery"]
            if any(x in scan_types for x in web_modules):
                logger.info(f"[Worker] Pre-checking web ports for {domain}...")
                has_http = check_port(domain, 80)
                has_https = check_port(domain, 443)
                logger.info(f"[Worker] Web Pre-check: HTTP={has_http}, HTTPS={has_https}")

            # 1. Run Subdomain Scanner (Heavy)
            # Replaces old "dns_scanner" logic for full enumeration
            if "subdomain_scanner" in scan_types:
                module_start = datetime.utcnow()
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Subdomain Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.dns_scanner import SubdomainScanner
                    # Only use crt.sh if SSL Scanner is also selected (per user request)
                    use_ct = "ssl_scanner" in scan_types
                    sub_scan = SubdomainScanner(db_session=session, use_ct_logs=use_ct)
                    logger.info(f"[Worker] Running {sub_scan.module_name} (CRT.sh: {use_ct})...")

                    with LogCapture() as logs:
                        logger.info(f"Starting {sub_scan.module_name} for {domain}")
                        result = sub_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()

                    if result:
                        print(f"[Worker] {sub_scan.module_name} found changes/new data.")
                        if isinstance(result, object) and hasattr(result, 'log_content'):
                             result.log_content = sanitize_null_bytes(captured_logs)
                             session.add(result)
                             session.commit()
                    else:
                         print(f"[Worker] {sub_scan.module_name} no change.")

                    # Prometheus Metrics: Module Completed
                    module_duration = (datetime.utcnow() - module_start).total_seconds()
                    get_metrics().record_scan_completed(
                        tenant_id=parent_tenant_id,
                        module_name="subdomain_scanner",
                        duration_seconds=module_duration,
                        status="success"
                    )
                except Exception as e:
                    logger.error(f"[Worker] Error in Subdomain Scanner: {e}")
                    session.rollback()
                    # Prometheus Metrics: Module Error
                    get_metrics().record_scan_error(
                        tenant_id=parent_tenant_id if 'parent_tenant_id' in locals() else None,
                        module_name="subdomain_scanner",
                        error_type=type(e).__name__
                    )

            # 1b. Run DNS Record Scanner (Light)
            if "dns_scanner" in scan_types:
                module_start = datetime.utcnow()
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running DNS Record Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.dns_scanner import DNSRecordScanner
                    dns_scan = DNSRecordScanner(db_session=session)
                    logger.info(f"[Worker] Running {dns_scan.module_name}...")

                    with LogCapture() as logs:
                        logger.info(f"Starting {dns_scan.module_name} for {domain}")
                        result = dns_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()

                    if result and hasattr(result, 'log_content'):
                         result.log_content = sanitize_null_bytes(captured_logs)
                         session.add(result)
                         session.commit()

                    # Prometheus Metrics: Module Completed
                    module_duration = (datetime.utcnow() - module_start).total_seconds()
                    get_metrics().record_scan_completed(
                        tenant_id=parent_tenant_id,
                        module_name="dns_scanner",
                        duration_seconds=module_duration,
                        status="success"
                    )
                except Exception as e:
                    logger.error(f"[Worker] Error in DNS Record Scanner: {e}")
                    session.rollback()
                    get_metrics().record_scan_error(
                        tenant_id=parent_tenant_id if 'parent_tenant_id' in locals() else None,
                        module_name="dns_scanner",
                        error_type=type(e).__name__
                    )

            # 1c. Run DNS Cleanup Scanner (Archive dead targets)
            if "dns_cleanup" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Checking DNS health..."
                        session.add(t)
                        session.commit()

                    from yads.modules.dns_cleanup_scanner import DNSCleanupScanner
                    cleanup_scan = DNSCleanupScanner(session)
                    logger.info(f"[Worker] Running {cleanup_scan.module_name}...")
                    
                    with LogCapture() as logs:
                        logger.info(f"Starting {cleanup_scan.module_name} for {domain}")
                        result = cleanup_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result and hasattr(result, 'log_content'):
                         result.log_content = sanitize_null_bytes(captured_logs)
                         session.add(result)
                         session.commit()
                         
                except Exception as e:
                    logger.error(f"[Worker] Error in DNS Cleanup Scanner: {e}")
                    session.rollback()

            # Group A: launch independent modules in background while web_analyzer runs
            _group_a_futures = []
            _group_a_modules = []
            _group_a_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan-a")
            # ssl_scanner and infrastructure_scanner run sequentially after web_analyzer.
            # Parallel execution via ThreadPoolExecutor was unreliable in Celery worker
            # context — silent failures with no logs or DB writes.
            # deception_detector is independent when port_scanner is not requested
            # (it falls back to default ports; no dependency on port_scanner results)
            # deception_detector runs sequentially later (ThreadPoolExecutor unreliable in Celery)
            _group_a_executor.shutdown(wait=False)
            if _group_a_modules:
                logger.info(f"[Worker] Group A started in background: {_group_a_modules}")

            # 2. Run Web Scanner
            # Dependency: CVE Scanner requires Web Analyzer
            if "cve_scanner" in scan_types and "web_analyzer" not in scan_types:
                 logger.info("[Worker] Auto-enabling Web Analyzer for CVE Scanner dependency.")
                 scan_types.append("web_analyzer")

            if "web_analyzer" in scan_types:
                if not (has_http or has_https):
                    logger.info("[Worker] Skipping Web Analyzer: Port 80/443 closed (Optimization).")
                else:
                    module_start = datetime.utcnow()
                    try:
                        t = session.get(Target, target_id)
                        if t:
                            t.scan_progress = "Running Web Analyzer..."
                            session.add(t)
                            session.commit()

                        enable_cves = "cve_scanner" in scan_types
                        web = WebAnalyzer(db_session=session, enable_cves=enable_cves)
                        logger.info(f"[Worker] Step 2: Running {web.module_name}...")
                        with LogCapture() as logs:
                            logger.info(f"Starting {web.module_name} for {domain}")
                            result = web.process(target_id, domain)
                            captured_logs = logs.get_logs()

                        if result and hasattr(result, 'log_content'):
                            result.log_content = sanitize_null_bytes(captured_logs)
                            session.add(result)
                            session.commit()
                            print(f"[Worker] {web.module_name} found changes/new data.")
                        else:
                            print(f"[Worker] {web.module_name} no change.")

                        # Prometheus Metrics: Module Completed
                        module_duration = (datetime.utcnow() - module_start).total_seconds()
                        get_metrics().record_scan_completed(
                            tenant_id=parent_tenant_id,
                            module_name="web_analyzer",
                            duration_seconds=module_duration,
                            status="success"
                        )
                    except Exception as e:
                        logger.error(f"[Worker] Error in Web Analyzer: {e}")
                        session.rollback()
                        get_metrics().record_scan_error(
                            tenant_id=parent_tenant_id if 'parent_tenant_id' in locals() else None,
                            module_name="web_analyzer",
                            error_type=type(e).__name__
                        )

            # 2b. Run Infrastructure Scanner (sequential, runs after web_analyzer)
            if "infrastructure_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Infrastructure Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.infrastructure_scanner import InfrastructureScanner
                    infra = InfrastructureScanner(db_session=session)
                    logger.info(f"[Worker] Step 2b: Running {infra.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {infra.module_name} for {domain}")
                        result = infra.process(target_id, domain)
                        captured_logs = logs.get_logs()

                    if result and hasattr(result, 'log_content'):
                        result.log_content = sanitize_null_bytes(captured_logs)
                        session.add(result)
                        session.commit()
                        print(f"[Worker] {infra.module_name} found changes/new data.")
                    else:
                        print(f"[Worker] {infra.module_name} no change.")
                except Exception as e:
                    logger.error(f"[Worker] Error in Infrastructure Scanner: {e}")
                    session.rollback()

            # 2c. Run Nuclei Vulnerability Scanner (Active)
            # (New in v1.5.0)
            if "nuclei_scanner" in scan_types:
                # Removed optimization check (has_http/https) to allow scan on non-standard ports/internal IPs
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Nuclei Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.nuclei_scanner import NucleiScanner
                    nu = NucleiScanner(db_session=session)
                    logger.info(f"[Worker] Step 2b: Running {nu.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {nu.module_name} for {domain}")
                        result = nu.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result and hasattr(result, 'log_content'):
                        result.log_content = sanitize_null_bytes(captured_logs)
                        session.add(result)
                        session.commit()
                        print(f"[Worker] {nu.module_name} finished.")
                except Exception as e:
                    logger.error(f"[Worker] Error in Nuclei Scanner: {e}")
                    session.rollback()

            # 3. Run Typosquat Scanner (Independent of Web)
            if "typosquat_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Typosquat Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.typosquat_scanner import TyposquatScanner
                    ts = TyposquatScanner(db_session=session)
                    logger.info(f"[Worker] Step 3: Running {ts.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {ts.module_name} for {domain}")
                        result = ts.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result and hasattr(result, 'log_content'):
                         result.log_content = sanitize_null_bytes(captured_logs)
                         session.add(result)
                         session.commit()
                         print(f"[Worker] {ts.module_name} found changes/new data.")
                    else:
                         print(f"[Worker] {ts.module_name} no change.")
                except Exception as e:
                    logger.error(f"[Worker] Error in Typosquat Scanner: {e}")
                    session.rollback()

            # 4. Infrastructure Scanner runs in Group A (background thread, see above)

            # 5. Run Analytics Correlator
            if "analytics_correlator" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Analytics Correlator..."
                        session.add(t)
                        session.commit()

                    from yads.modules.analytics_correlator import AnalyticsCorrelator
                    ac = AnalyticsCorrelator(db_session=session)
                    logger.info(f"[Worker] Step 5: Running {ac.module_name}...")
                    
                    with LogCapture() as logs:
                        logger.info(f"Starting {ac.module_name} for {domain}")
                        result = ac.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result and hasattr(result, 'log_content'):
                         result.log_content = sanitize_null_bytes(captured_logs)
                         session.add(result)
                         session.commit()
                         print(f"[Worker] {ac.module_name} found changes/new data.")
                    else:
                         print(f"[Worker] {ac.module_name} no change.")
                         
                except Exception as e:
                    logger.error(f"[Worker] Error in Analytics Correlator: {e}")
                    session.rollback()

            # 4b. Run Port Scanner / Quick Web Probe
            if "quick_web_probe" in scan_types or "port_scanner" in scan_types:
                is_quick = "quick_web_probe" in scan_types and "port_scanner" not in scan_types
                logger.info(f"[Worker] PortScanner requested for {domain} (quick={is_quick})")
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Quick Web Probe..." if is_quick else "Running Port Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.port_scanner import PortScanner
                    ps = PortScanner(db_session=session)
                    ps.quick_mode = is_quick
                    logger.info(f"[Worker] Step 4b: Running {ps.module_name} (quick={ps.quick_mode})...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {ps.module_name} for {domain}")
                        result = ps.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    
                    if result:
                         logger.info(f"[Worker] PortScanner result found: {result.data}")
                         if hasattr(result, 'log_content'):
                            result.log_content = sanitize_null_bytes(captured_logs)
                            session.add(result)
                            session.commit()
                         print(f"[Worker] {ps.module_name} finished.")
                    else:
                         logger.info("[Worker] PortScanner result is Empty/None")

                except Exception as e:
                    logger.error(f"[Worker] Error in Port Scanner: {e}", exc_info=True)
                    session.rollback()

            # 4c. Nmap — dispatched via registry loop below

            # 5. Run Visual OSINT
            if "visual_osint" in scan_types:
                if not (has_http or has_https):
                    logger.info("[Worker] Skipping Visual OSINT: Port 80/443 closed (Optimization).")
                else:
                    try:
                        t = session.get(Target, target_id)
                        if t:
                            t.scan_progress = "Running Visual OSINT..."
                            session.add(t)
                            session.commit()

                        from yads.modules.visual_osint import VisualOSINT
                        vis = VisualOSINT(db_session=session)
                        logger.info(f"[Worker] Step 5: Running {vis.module_name}...")
                        with LogCapture() as logs:
                            logger.info(f"Starting {vis.module_name} for {domain}")
                            result = vis.process(target_id, domain)
                            captured_logs = logs.get_logs()
                        
                        if result and hasattr(result, 'log_content'):
                            result.log_content = sanitize_null_bytes(captured_logs)
                            session.add(result)
                            session.commit()
                            print(f"[Worker] {vis.module_name} found changes/new data.")
                        else:
                            print(f"[Worker] {vis.module_name} no change.")
                    except Exception as e:
                        logger.error(f"[Worker] Error in Visual OSINT: {e}")
                        session.rollback()

            # 5b. Wayback Scanner — dispatched via registry loop below
        
            # 6. Wait for remaining Group A (deception_detector only now)
            if _group_a_futures:
                logger.info(f"[Worker] Waiting for Group A background modules: {_group_a_modules}...")
                _futures_wait(_group_a_futures, return_when=ALL_COMPLETED)
                logger.info("[Worker] Group A completed.")

            # 6b. Run SSL Scanner sequentially
            if "ssl_scanner" in scan_types and has_https:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running SSL Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.ssl_scanner import SSLScanner
                    ssl = SSLScanner(db_session=session)
                    logger.info(f"[Worker] Step 6b: Running {ssl.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {ssl.module_name} for {domain}")
                        result = ssl.process(target_id, domain)
                        captured_logs = logs.get_logs()

                    if result and hasattr(result, 'log_content'):
                        result.log_content = sanitize_null_bytes(captured_logs)
                        session.add(result)
                        session.commit()
                        print(f"[Worker] {ssl.module_name} found changes/new data.")
                    else:
                        print(f"[Worker] {ssl.module_name} no change.")
                except Exception as e:
                    logger.error(f"[Worker] Error in SSL Scanner: {e}")
                    session.rollback()
            elif "ssl_scanner" in scan_types and not has_https:
                logger.info("[Worker] Skipping SSL Scanner: Port 443 closed (Optimization).")

            if "ssl_scanner" in scan_types and has_https:
                # Post-process: auto-queue extracted domains from SSL cert (read from DB)
                try:
                    import dns.resolver
                    ssl_result = session.exec(
                        select(ScanResult).where(
                            ScanResult.target_id == target_id,
                            ScanResult.module_name == "ssl_scanner"
                        ).order_by(ScanResult.scanned_at.desc())
                    ).first()
                    if ssl_result and ssl_result.data and "extracted_domains" in ssl_result.data:
                        extracted = ssl_result.data["extracted_domains"]
                        new_found = 0
                        for edomain in extracted:
                            edomain = edomain.strip().lower()
                            if not edomain:
                                continue
                            resolves = False
                            try:
                                dns.resolver.resolve(edomain, 'A')
                                resolves = True
                            except Exception:
                                try:
                                    dns.resolver.resolve(edomain, 'AAAA')
                                    resolves = True
                                except Exception:
                                    resolves = False
                            if resolves:
                                existing_t = session.exec(select(Target).where(Target.domain == edomain)).first()
                                if not existing_t:
                                    new_target = Target(domain=edomain, tenant_id=parent_tenant_id)
                                    session.add(new_target)
                                    session.commit()
                                    session.refresh(new_target)
                                    new_found += 1
                                    print(f"[Worker] Discovered and added new target from SSL: {edomain}")
                                    webhook_service.trigger_event(parent_tenant_id, "new_asset", {
                                        "domain": edomain, "source": "ssl_scanner", "parent": domain
                                    })
                        if new_found > 0:
                            print(f"[Worker] SSL Discovery added {new_found} new targets.")
                except Exception as e:
                    logger.error(f"[Worker] SSL domain extraction error: {e}")
            # 7. Crawler queued for parallel execution with content_discovery (see step 9 below)

            # 7+9. Run Crawler and Content Discovery in parallel (Group B)
            _group_b_classes = []
            if "crawler" in scan_types and (has_http or has_https):
                from yads.modules.crawler import Crawler
                _group_b_classes.append(Crawler)
            elif "crawler" in scan_types:
                logger.info("[Worker] Skipping Crawler: Port 80/443 closed (Optimization).")

            if "content_discovery" in scan_types and (has_http or has_https):
                from yads.modules.content_discovery import ContentDiscoveryScanner
                _group_b_classes.append(ContentDiscoveryScanner)
            elif "content_discovery" in scan_types:
                logger.info("[Worker] Skipping Content Discovery: Port 80/443 closed.")

            for _cls in _group_b_classes:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = f"Running {_cls.__name__}..."
                        session.add(t)
                        session.commit()
                    _mod = _cls(db_session=session)
                    logger.info(f"[Worker] Running {_mod.module_name}...")
                    with LogCapture() as logs:
                        logger.info(f"Starting {_mod.module_name} for {domain}")
                        result = _mod.process(target_id, domain)
                        captured_logs = logs.get_logs()
                    if result and hasattr(result, 'log_content'):
                        result.log_content = sanitize_null_bytes(captured_logs)
                        session.add(result)
                        session.commit()
                    print(f"[Worker] {_mod.module_name} finished.")
                except Exception as e:
                    logger.error(f"[Worker] Error in {_cls.__name__}: {e}")
                    session.rollback()

            # Deception detector (sequential, was previously in broken ThreadPoolExecutor)
            if "deception_detector" in scan_types and "port_scanner" not in scan_types:
                try:
                    import hashlib, json as _json
                    from yads.modules.deception_detector import DeceptionDetector
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Deception Detector..."
                        session.add(t)
                        session.commit()
                    dd = DeceptionDetector(timeout=30)
                    logger.info(f"[Worker] Running {dd.module_name}...")
                    scan_data = dd.run_scan(domain, ports=[22, 23, 21, 25, 80, 443, 8080])
                    if scan_data:
                        scan_data = sanitize_null_bytes(scan_data)
                        data_hash = hashlib.sha256(_json.dumps(scan_data, sort_keys=True).encode()).hexdigest()
                        session.add(ScanResult(target_id=target_id, module_name=dd.module_name, data=scan_data, result_hash=data_hash))
                        session.commit()
                    print(f"[Worker] {dd.module_name} finished.")
                except Exception as e:
                    logger.error(f"[Worker] Error in Deception Detector: {e}")
                    session.rollback()

            # Steps 10-16 (tld_scanner, cloud_scanner, api_discovery, form_discovery,
            # brand_intelligence, email_intelligence, social_media_scanner) are now
            # dispatched via the registry loop below.

            # 17. Deception Detector: runs in Group A if port_scanner not requested,
            # otherwise runs sequentially here (uses port_scanner results from DB).
            if "deception_detector" in scan_types and "port_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Deception Detector..."
                        session.add(t)
                        session.commit()

                    from yads.modules.deception_detector import DeceptionDetector
                    dd_scan = DeceptionDetector(timeout=30)
                    logger.info(f"[Worker] Step 17: Running {dd_scan.module_name} (sequential, uses port results)...")

                    ports_to_check = [22, 23, 21, 25, 80, 443, 8080]
                    try:
                        port_result = session.exec(select(ScanResult).where(
                            ScanResult.target_id == target_id,
                            ScanResult.module_name == "port_scanner"
                        ).order_by(ScanResult.scanned_at.desc())).first()
                        if port_result and port_result.data and "open_ports" in port_result.data:
                            ports_to_check = [p["port"] for p in port_result.data["open_ports"]]
                            logger.info(f"Using discovered open ports: {ports_to_check}")
                    except Exception:
                        pass

                    scan_data = dd_scan.run_scan(domain, ports=ports_to_check)
                    if scan_data:
                        import hashlib, json as _json2
                        scan_data = sanitize_null_bytes(scan_data)
                        data_hash = hashlib.sha256(_json2.dumps(scan_data, sort_keys=True).encode()).hexdigest()
                        session.add(ScanResult(
                            target_id=target_id, module_name=dd_scan.module_name,
                            data=scan_data, result_hash=data_hash))
                        session.commit()
                        summary = scan_data.get("summary", {})
                        logger.info(f"[Worker] {dd_scan.module_name} finished: "
                                    f"{summary.get('total_detections', 0)} detections, "
                                    f"risk: {summary.get('overall_risk', 'none')}")
                except Exception as e:
                    logger.error(f"[Worker] Error in Deception Detector: {e}")
                    session.rollback()

            # Steps 18-19 (seed_files_scanner, csp_scanner) dispatched via registry loop below.

            # ── Registry-driven parallel module dispatch ──────────────────
            # Modules with custom_dispatch=True are handled above; everything
            # else is submitted concurrently via ThreadPoolExecutor.
            # Each thread gets its own DB session via _run_parallel_module.
            from yads.core.module_registry import get_simple_dispatch_modules
            from concurrent.futures import as_completed as _as_completed

            _parallel_mods = []
            for _mod_def in get_simple_dispatch_modules():
                if _mod_def.name not in scan_types:
                    continue
                if _mod_def.requires_https and not has_https:
                    logger.info(f"[Worker] Skipping {_mod_def.name}: no HTTPS")
                    continue
                if _mod_def.requires_http and not (has_http or has_https):
                    logger.info(f"[Worker] Skipping {_mod_def.name}: no HTTP")
                    continue
                try:
                    _parallel_mods.append((_mod_def.name, _mod_def.load_class()))
                except Exception as _e:
                    logger.error(f"[Worker] Failed to load {_mod_def.name}: {_e}")

            if _parallel_mods:
                _pmod_names = [n for n, _ in _parallel_mods]
                logger.info(f"[Worker] Running {len(_parallel_mods)} modules in parallel: {_pmod_names}")
                _pt = session.get(Target, target_id)
                if _pt:
                    _pt.scan_progress = f"Running {len(_parallel_mods)} modules in parallel..."
                    session.add(_pt)
                    session.commit()

                with ThreadPoolExecutor(
                    max_workers=min(len(_parallel_mods), 6),
                    thread_name_prefix="scan-p",
                ) as _pex:
                    _pfutures = {
                        _pex.submit(_run_parallel_module, _cls, target_id, domain): name
                        for name, _cls in _parallel_mods
                    }
                    for _pf in _as_completed(_pfutures):
                        _pmod_name = _pfutures[_pf]
                        try:
                            _pf.result()
                            logger.info(f"[Worker] Parallel done: {_pmod_name}")
                        except Exception as _pfe:
                            logger.error(f"[Worker] Parallel error in {_pmod_name}: {_pfe}")
                logger.info("[Worker] All parallel modules completed.")

            # Subdomain Discovery & Auto-Queue Logic
            # Updated to check 'subdomain_scanner' result as the primary source of subdomains
            
            auto_queue_enabled = settings.AUTO_QUEUE_SUBDOMAINS
            try:
                from yads.models import SystemConfig
                aq_conf = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
                if aq_conf:
                    auto_queue_enabled = aq_conf.value.lower() == 'true'
            except Exception:
                pass

            try:
                 # Check for Subdomain Scanner results first
                 # Prioritize 'subdomain_scanner' if present
                 sub_res = session.exec(select(ScanResult).where(
                     ScanResult.target_id == target_id,
                     ScanResult.module_name == "subdomain_scanner"
                 ).order_by(ScanResult.scanned_at.desc())).first()
                 
                 # Fallback to legacy 'dns_scanner' if subdomain_scanner didn't run effectively
                 if not sub_res:
                     sub_res = session.exec(select(ScanResult).where(
                         ScanResult.target_id == target_id,
                         ScanResult.module_name == "dns_scanner"
                     ).order_by(ScanResult.scanned_at.desc())).first()

                 if sub_res and sub_res.data and "subdomains" in sub_res.data:
                     subs = sub_res.data["subdomains"]
                     
                     new_targets_count = 0
                     queued_count = 0
                     
                     for entry in subs:
                         sub_domain = entry.get("subdomain")
                         if sub_domain and sub_domain != domain: # Avoid self-loop

                             # Only add subdomains that actually resolved to an IP
                             ips = entry.get("ips") or []
                             if not ips:
                                 logger.debug(f"[Worker] Skipping unresolved subdomain (no IP): {sub_domain}")
                                 continue

                             # Check existence
                             existing = session.exec(select(Target).where(Target.domain == sub_domain)).first()
                             if not existing:
                                 # Create New Target (Always)
                                 # Inherit Tenant ID from parent
                                 new_target = Target(domain=sub_domain, tenant_id=parent_tenant_id)
                                 session.add(new_target)
                                 session.commit()
                                 session.refresh(new_target)
                                 new_targets_count += 1
                                 
                                 # Queue Scan (Conditional)
                                 if auto_queue_enabled:
                                     # FIX: Only queue new subdomains with dns_scanner to prevent recursive explosion
                                     # User request: "new targets, which have been added during the subdomain scan, 
                                     # should only conduct the scan type DNS Records (Simple)"
                                     subdomain_scan_types = ['dns_scanner']
                                     celery_app.send_task("yads.worker.run_all_scans", args=[new_target.id, new_target.domain, subdomain_scan_types, parent_tenant_id])
                                     queued_count += 1
                                     logger.info(f"[Worker] Auto-queued new subdomain: {sub_domain} with types: {subdomain_scan_types}")
                                 else:
                                     logger.info(f"[Worker] Discovered new subdomain: {sub_domain} (Auto-queue disabled)")
                                 
                                     # Webhook: New Asset
                                     webhook_service.trigger_event(parent_tenant_id, "new_asset", {
                                         "domain": sub_domain,
                                         "source": "subdomain_discovery",
                                         "parent": domain
                                     })
                     
                     if new_targets_count > 0:
                         logger.info(f"[Worker] Subdomain Discovery: Added {new_targets_count} new targets. Queued: {queued_count}.")

            except Exception as e:
                logger.error(f"[Worker] Error in Subdomain Discovery logic: {e}")
                session.rollback()

            # Post-Scan Compliance Recalculation
            try:
                from yads.modules.compliance_frameworks import FRAMEWORKS, get_framework_scorer
                from yads.models import ComplianceTargetStatus, ComplianceTrend
                from sqlmodel import text as sql_text

                logger.info(f"[Worker] Recalculating compliance status for {domain}...")

                # Get latest scan results for this target
                query = """
                    SELECT DISTINCT ON (module_name)
                        module_name, data
                    FROM scanresult
                    WHERE target_id = :target_id
                    ORDER BY module_name, scanned_at DESC
                """
                results = session.exec(sql_text(query), params={"target_id": target_id}).all()

                target_data = {target_id: {}}
                for mod, data in results:
                    target_data[target_id][mod] = data

                target_map = {target_id: domain}

                # Calculate and store status for each framework
                for framework_id in FRAMEWORKS.keys():
                    try:
                        scorer = get_framework_scorer(framework_id)
                        stats = scorer.calculate_score(target_data, target_map)

                        # Upsert ComplianceTargetStatus
                        existing = session.exec(
                            select(ComplianceTargetStatus).where(
                                ComplianceTargetStatus.target_id == target_id,
                                ComplianceTargetStatus.framework == framework_id
                            )
                        ).first()

                        if existing:
                            existing.score = stats.get('score', 100)
                            existing.grade = stats.get('grade', 'A')
                            existing.passing_controls = stats.get('passing_controls', 0)
                            existing.failing_controls = stats.get('failing_controls', 0)
                            existing.findings = stats.get('findings', [])
                            existing.last_assessed_at = datetime.utcnow()
                            session.add(existing)
                        else:
                            new_status = ComplianceTargetStatus(
                                target_id=target_id,
                                framework=framework_id,
                                score=stats.get('score', 100),
                                grade=stats.get('grade', 'A'),
                                passing_controls=stats.get('passing_controls', 0),
                                failing_controls=stats.get('failing_controls', 0),
                                findings=stats.get('findings', [])
                            )
                            session.add(new_status)

                    except Exception as fw_e:
                        logger.warning(f"[Worker] Failed to calculate {framework_id} compliance: {fw_e}")

                session.commit()
                logger.info(f"[Worker] Compliance status updated for {domain}")

            except Exception as e:
                logger.error(f"[Worker] Error in compliance recalculation: {e}")
                session.rollback()

            # Reset status
            try:
                 t = session.get(Target, target_id)
                 if t:
                     t.scan_status = "idle"
                     t.scan_progress = f"Last scan completed at {datetime.utcnow().strftime('%H:%M:%S')}"
                     session.add(t)
                     session.commit()
            except Exception as e:
                 logger.error(f"[Worker] Failed to update finish status: {e}")
                 session.rollback()

        if 'parent_tenant_id' in locals():
            webhook_service.trigger_event(parent_tenant_id, "scan_finished", {
                "target_id": target_id,
                "domain": domain,
                "status": "completed",
                "modules": scan_types
            })

            # Prometheus Metrics: Scan Finished
            try:
                prom_metrics = get_metrics()
                prom_metrics.record_scan_finished(tenant_id=parent_tenant_id)
            except Exception as e:
                logger.debug(f"[Worker] Failed to record scan_finished metric: {e}")


        logger.info(f"[Worker] Finished scan for {domain}")

        # Report task completed to worker manager
        if _worker_client and _worker_client.is_distributed and celery_task_id:
            _worker_client.report_task_completed(celery_task_id, success=True)

    finally:
        # Cleanup Handler
        if 'root_logger' in locals() and 'redis_handler' in locals():
            root_logger.removeHandler(redis_handler)
