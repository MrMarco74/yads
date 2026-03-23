"""
worker_tasks.py — Celery task definitions.

Contains: auto_dns_cleanup, calculate_security_trends,
          calculate_compliance_trends, run_all_scans.

Re-exported via yads/worker.py for backwards compatibility.
"""
import os
import socket
import logging
import requests
import hashlib
import json as _json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait as _futures_wait, ALL_COMPLETED, as_completed as _as_completed

from sqlmodel import Session, select
from sqlalchemy import func

from yads.worker_core import celery_app, _reset_target_status, logger as _core_logger
from yads.worker_modules import LogCapture, _run_parallel_module, _run_simple_module
from yads.database import engine
from yads.models import (
    ScanResult, Target, SystemConfig, Tenant,
    SecurityTrend, ComplianceTrend, ComplianceTargetStatus,
    SecurityAuditLog, SystemAlertLog, HTTPTraffic, IntegrationConfig, SecurityFinding
)
from yads.config import settings
from yads.core.splunk_logger import splunk_logger
from yads.core.webhook_service import webhook_service
from yads.core.base import sanitize_null_bytes
from yads.core.metrics import get_metrics

logger = logging.getLogger("yads-worker")


# ── Periodic Tasks ────────────────────────────────────────────────────────────

@celery_app.task(name="yads.worker.auto_dns_cleanup")
def auto_dns_cleanup():
    """
    Periodic task to check DNS health for all active targets.
    Respects GLOBAL_MAX_CONCURRENT_SCANS — queues in batches, never floods.
    """
    from yads.core.scheduler import get_active_scan_count, get_max_concurrent_scans

    logger.info("[Worker] Starting periodic DNS cleanup scan for all active targets")
    try:
        with Session(engine) as session:
            max_concurrent = get_max_concurrent_scans(session)
            targets = session.exec(select(Target).where(Target.is_archived == False)).all()

            queued = 0
            skipped = 0
            active_count = get_active_scan_count(session)

            for t in targets:
                if active_count >= max_concurrent:
                    skipped += 1
                    continue
                celery_app.send_task(
                    "yads.worker.run_all_scans",
                    args=[t.id, t.domain, ["dns_cleanup"], t.tenant_id]
                )
                queued += 1
                active_count += 1

            logger.info(
                f"[Worker] DNS cleanup: queued {queued}, skipped {skipped} "
                f"(limit {max_concurrent})."
            )
    except Exception as e:
        logger.error(f"[Worker] Failed to run auto_dns_cleanup: {e}")


@celery_app.task(name="yads.worker.calculate_security_trends")
def calculate_security_trends():
    """Calculates and stores daily security score averages for each tenant."""
    from yads.core.scoring import calculate_target_score, get_grade
    from sqlmodel import text

    logger.info("[Worker] Starting daily security trend calculation...")
    try:
        with Session(engine) as session:
            tenants = session.exec(select(Tenant)).all()

            for tenant in tenants:
                targets = session.exec(select(Target).where(
                    Target.tenant_id == tenant.id,
                    Target.is_archived == False
                )).all()

                if not targets:
                    continue

                total_target_score = 0
                count = 0

                for t in targets:
                    query = text("""
                        SELECT DISTINCT ON (module_name)
                            module_name, data
                        FROM scanresult
                        WHERE target_id = :target_id
                          AND module_name IN ('ssl_scanner', 'web_analyzer', 'port_scanner')
                        ORDER BY module_name, scanned_at DESC
                    """)
                    latest_rows = session.execute(query, {"target_id": t.id}).all()

                    class MockRes:
                        def __init__(self, data): self.data = data

                    latest_results = {row[0]: MockRes(row[1]) for row in latest_rows}
                    score, grade, factors = calculate_target_score(t, latest_results)
                    total_target_score += score
                    count += 1

                if count > 0:
                    avg_score = total_target_score / count
                    trend = SecurityTrend(
                        tenant_id=tenant.id,
                        score=round(avg_score),
                        grade=get_grade(round(avg_score)),
                    )
                    session.add(trend)
                    logger.info(f"[Worker] Recorded trend for tenant {tenant.name}: {avg_score:.1f} ({trend.grade})")

            session.commit()
            logger.info("[Worker] Security trend calculation finished.")
    except Exception as e:
        logger.error(f"[Worker] Failed to calculate security trends: {e}")


@celery_app.task(name="yads.worker.calculate_compliance_trends")
def calculate_compliance_trends():
    """Calculates and stores daily compliance scores for each tenant and framework."""
    try:
        try:
            from yads.modules.compliance_frameworks import FRAMEWORKS, get_framework_scorer
        except ImportError:
            from yads.modules.custom.compliance_frameworks import FRAMEWORKS, get_framework_scorer
    except ImportError:
        logger.warning("[Worker] Optional module compliance_frameworks not found. Skipping trend calculation.")
        return
    from sqlmodel import text

    logger.info("[Worker] Starting daily compliance trend calculation...")
    try:
        with Session(engine) as session:
            tenants = session.exec(select(Tenant)).all()

            for tenant in tenants:
                targets = session.exec(select(Target).where(
                    Target.tenant_id == tenant.id,
                    Target.is_archived == False
                )).all()

                if not targets:
                    continue

                target_ids = [t.id for t in targets]
                if not target_ids:
                    continue

                from sqlalchemy import bindparam
                query = text("""
                    SELECT DISTINCT ON (target_id, module_name)
                        target_id, module_name, data
                    FROM scanresult
                    WHERE target_id = ANY(:target_ids)
                    ORDER BY target_id, module_name, scanned_at DESC
                """)
                results = session.execute(query, {"target_ids": target_ids}).all()

                target_data = {t.id: {} for t in targets}
                target_map = {t.id: t.domain for t in targets}

                for tid, mod, data in results:
                    if tid in target_data:
                        target_data[tid][mod] = data

                for framework_id in FRAMEWORKS.keys():
                    try:
                        scorer = get_framework_scorer(framework_id)
                        stats = scorer.calculate_score(target_data, target_map)

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


@celery_app.task(name="yads.worker.send_daily_digests")
def send_daily_digests():
    """Send daily security digest to all tenants with email configured."""
    from datetime import timedelta
    logger.info("[Worker] Starting daily email digest task...")
    try:
        with Session(engine) as session:
            email_enabled = session.get(SystemConfig, "EMAIL_NOTIFICATIONS_ENABLED")
            if not email_enabled or email_enabled.value.lower() != "true":
                return
            addr_conf = session.get(SystemConfig, "EMAIL_NOTIFICATION_ADDRESS")
            global_addr = addr_conf.value.strip() if addr_conf and addr_conf.value else ""
            if not global_addr:
                return
            base_url_conf = session.get(SystemConfig, "BASE_URL")
            base_url = base_url_conf.value if base_url_conf else ""
            tenants = session.exec(select(Tenant)).all()
            yesterday = datetime.utcnow() - timedelta(days=1)
            from yads.models import ChangeEvent
            from yads.core.email_service import EmailService
            for tenant in tenants:
                targets = session.exec(
                    select(Target).where(Target.tenant_id == tenant.id, Target.is_archived == False)
                ).all()
                targets_data = []
                for t in targets:
                    last_result = session.exec(
                        select(ScanResult).where(ScanResult.target_id == t.id)
                        .order_by(ScanResult.scanned_at.desc())
                    ).first()
                    last_scan = last_result.scanned_at.strftime("%Y-%m-%d %H:%M") if last_result else "-"
                    recent_ids = [
                        r.id for r in session.exec(
                            select(ScanResult).where(
                                ScanResult.target_id == t.id,
                                ScanResult.scanned_at >= yesterday
                            )
                        ).all()
                    ]
                    changes_count = 0
                    if recent_ids:
                        changes_count = session.exec(
                            select(func.count()).where(ChangeEvent.scan_result_id.in_(recent_ids))
                        ).one()
                    targets_data.append({
                        "domain": t.domain, "target_id": t.id,
                        "last_scan": last_scan, "changes_count": changes_count,
                    })
                lang = getattr(tenant, "language", "en") or "en"
                EmailService.send_daily_digest(
                    tenant_name=tenant.name,
                    targets_with_scores=targets_data,
                    to_address=global_addr,
                    lang=lang,
                    base_url=base_url,
                )
                logger.info(f"[Worker] Daily digest queued for tenant {tenant.name}")
    except Exception as e:
        logger.error(f"[Worker] send_daily_digests failed: {e}")


# ── Stuck Job Cleaner ─────────────────────────────────────────────────────────

@celery_app.task(name="yads.worker.reset_stuck_targets")
def reset_stuck_targets():
    """
    Reset only genuinely stuck 'running' targets — i.e. scans that started more
    than 45 minutes ago and never finished (worker crash).

    We intentionally do NOT reset 'queued' targets here because:
    - Queued targets legitimately sit in the Redis queue waiting for a worker slot.
    - Mass-resetting them causes the header widget to show 0/0 even when the queue
      is full, and re-scanning them would create duplicate Celery tasks.

    Startup seeding resets ALL queued/running once on boot (safe because Redis is
    just starting too). This periodic task only handles post-crash hangers.
    """
    from sqlmodel import text as sql_text
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=45)
    # Use ISO-8601 string — works for both TEXT and TIMESTAMP columns
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S")

    with Session(engine) as db:
        # Only reset 'running' targets whose last_scan timestamp predates the cutoff.
        # 'queued' targets are legitimately waiting in Celery — leave them alone.
        result = db.execute(sql_text(
            "UPDATE target SET scan_status='idle' "
            "WHERE scan_status = 'running' "
            "AND created_at < :cutoff"
        ), {"cutoff": cutoff_str})
        db.commit()
        stuck = result.rowcount
        if stuck:
            logger.warning(f"[StuckCleaner] Reset {stuck} stuck running target(s) → idle (> 45 min)")
        else:
            logger.debug("[StuckCleaner] No stuck running targets found")


# ── Data Retention ────────────────────────────────────────────────────────────

@celery_app.task(name="yads.worker.prune_old_scan_results")
def prune_old_scan_results():
    """
    Periodic data retention task (DORA/DSGVO compliance).
    - Deletes ScanResult rows older than DATA_RETENTION_DAYS (default 5 years).
    - Deletes HTTPTraffic and SystemAlertLog older than LOG_RETENTION_DAYS (default 30 days).
    - Deletes SecurityAuditLog older than 5 years (DORA requirement).
    - Triggers anonymization in Support Portal.
    """
    from datetime import timedelta, timezone
    from sqlalchemy import text
    from yads.models import ChangeEvent

    now = datetime.now(timezone.utc)
    logger.info("[Worker] Starting comprehensive data retention pruning...")
    
    try:
        with Session(engine) as session:
            # 1. Scan Results (Default: 5 years / 1825 days)
            days = settings.DATA_RETENTION_DAYS
            if days > 0:
                cutoff = now - timedelta(days=days)
                # Delete old change events first (FK dependency)
                # We use a subquery/join to delete efficiently
                old_events_stmt = text("""
                    DELETE FROM changeevent 
                    WHERE scan_result_id IN (
                        SELECT id FROM scanresult WHERE scanned_at < :cutoff
                    )
                """)
                res_events = session.execute(old_events_stmt, {"cutoff": cutoff})
                
                # Delete results
                old_results_stmt = text("DELETE FROM scanresult WHERE scanned_at < :cutoff")
                res_results = session.execute(old_results_stmt, {"cutoff": cutoff})
                
                logger.info(f"[Worker] Pruned {res_results.rowcount} ScanResults and {res_events.rowcount} ChangeEvents (> {days} days)")

            # 2. HTTP Traffic & System Alerts (Default: 30 days)
            log_days = settings.LOG_RETENTION_DAYS
            if log_days > 0:
                log_cutoff = now - timedelta(days=log_days)
                
                res_traffic = session.execute(text("DELETE FROM httptraffic WHERE timestamp < :cutoff"), {"cutoff": log_cutoff})
                res_alerts = session.execute(text("DELETE FROM systemalertlog WHERE fired_at < :cutoff"), {"cutoff": log_cutoff})
                
                logger.info(f"[Worker] Pruned {res_traffic.rowcount} HTTPTraffic and {res_alerts.rowcount} SystemAlertLogs (> {log_days} days)")

            # 3. Security Audit Logs (Default: 1825 days / 5 years)
            # DORA Art. 12 requires 5 years for ICT logs.
            audit_cutoff = now - timedelta(days=1825)
            res_audit = session.execute(text("DELETE FROM securityauditlog WHERE timestamp < :cutoff"), {"cutoff": audit_cutoff})
            logger.info(f"[Worker] Pruned {res_audit.rowcount} SecurityAuditLogs (> 5 years)")

            session.commit()
            
            # 4. Trigger Support Portal Cleanup
            # We do this as a fire-and-forget background request
            _trigger_support_portal_cleanup()
            
            logger.info("[Worker] Data retention pruning completed successfully.")
    except Exception as e:
        logger.error(f"[Worker] Data retention pruning failed: {e}")

def _trigger_support_portal_cleanup():
    """Triggers the anonymization task on the Support Portal."""
    import requests
    try:
        url = f"{settings.SUPPORT_PORTAL_URL.rstrip('/')}/api/admin/cleanup"
        # The Support Portal likely needs an ADMIN_TOKEN for this
        token = os.getenv("SUPPORT_PORTAL_ADMIN_TOKEN")
        if not token:
            logger.warning("[Worker] SUPPORT_PORTAL_ADMIN_TOKEN not set, skipping remote cleanup.")
            return
            
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.post(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            logger.info("[Worker] Support Portal cleanup triggered successfully.")
        else:
            logger.warning(f"[Worker] Support Portal cleanup trigger failed (Status: {resp.status_code})")
    except Exception as e:
        logger.warning(f"[Worker] Failed to trigger Support Portal cleanup: {e}")


# ── Main Scan Task ────────────────────────────────────────────────────────────

@celery_app.task(name="yads.worker.run_all_scans", bind=True)
def run_all_scans(
    self,
    target_id: int,
    domain: str,
    scan_types: list[str] = None,
    tenant_id: int = None,
    ignore_queue_pause: bool = False
):
    """
    Main orchestration task.
    Runs configured scanners for the given target.
    If scan_types is None, runs all available scanners.
    tenant_id is passed for queue filtering purposes (actual tenant is derived from target in DB).
    """
    from yads.worker_core import _worker_client

    if scan_types is None:
        scan_types = ["dns_cleanup", "subdomain_scanner", "dns_scanner"]

    logger.info(f"[Worker] Starting scan for {domain} (ID: {target_id}) with types: {scan_types}")

    # --- License / CE Enforcement ---
    from yads.core.license import license_manager, activation_verifier
    from yads.core.community_edition import get_ce_state, check_can_scan as ce_check_scan
    try:
        with Session(engine) as session:
            ce_state = get_ce_state(session)
            if ce_state["edition"] == "community":
                allowed, reason = ce_check_scan(session)
                if not allowed:
                    logger.warning(f"[Worker] CE read-only — discarding task for {domain}: {reason}")
                    return
            else:
                lc = session.exec(select(SystemConfig).where(SystemConfig.key == "license_key")).first()
                lic_data = license_manager.verify(lc.value) if (lc and lc.value) else None
                if not lic_data:
                    logger.warning(f"[Worker] License Invalid or Missing. Discarding task for {domain}.")
                    return
                # --- Activation enforcement for business licenses ---
                if lic_data.get("customer_id"):
                    uuid_conf = session.exec(select(SystemConfig).where(SystemConfig.key == "INSTANCE_UUID")).first()
                    instance_uuid = uuid_conf.value if uuid_conf else None
                    act_conf = session.exec(select(SystemConfig).where(SystemConfig.key == "ACTIVATION_CODE")).first()
                    act_data = activation_verifier.verify(act_conf.value, instance_uuid) if (act_conf and act_conf.value) else None
                    if not act_data:
                        logger.warning(f"[Worker] Instanz nicht aktiviert — Scan für {domain} verworfen.")
                        return
    except Exception as e:
        logger.error(f"[Worker] License check failed: {e}")
        return

    def check_port(host, port, timeout=2):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except:
            return False

    def check_web(host):
        """More robust web availability check.
        Returns (has_http, has_https).
        TCP port check first (fast); HTTP HEAD request as fallback for each protocol.
        """
        has_https = check_port(host, 443, timeout=3)
        has_http = check_port(host, 80, timeout=3)
        # Fallback: actual HTTP request if TCP check was inconclusive
        if not has_https:
            try:
                import urllib.request, ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(f"https://{host}", method="HEAD")
                with urllib.request.urlopen(req, timeout=4, context=ctx):
                    has_https = True
            except Exception:
                pass
        if not has_http:
            try:
                import urllib.request
                req = urllib.request.Request(f"http://{host}", method="HEAD")
                with urllib.request.urlopen(req, timeout=4):
                    has_http = True
            except Exception:
                pass
        return has_http, has_https

    # Setup Redis Logging (with distributed support)
    from yads.core.redis_logger import (
        DistributedRedisLogHandler, RedisLogHandler,
        get_external_ip, get_worker_hostname, resolve_target_ips,
        store_worker_network_info
    )

    worker_node_id = _worker_client.node_id if _worker_client and _worker_client.is_distributed else None
    external_ip = get_external_ip()
    worker_hostname = get_worker_hostname()

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

    redis_handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(redis_handler)

    # Log network information at scan start
    target_ips = resolve_target_ips(domain)
    logger.info(f"[Network] Scan initiated from {external_ip or 'unknown'} ({worker_hostname})")
    if target_ips:
        logger.info(f"[Network] Target {domain} resolves to: {', '.join(target_ips)}")
    else:
        logger.info(f"[Network] Target {domain} - DNS resolution pending")

    celery_task_id = self.request.id if hasattr(self, 'request') and self.request else None
    if _worker_client and _worker_client.is_distributed and celery_task_id:
        _worker_client.report_task_started(celery_task_id)

    try:
        with Session(engine) as session:
            # 0. Check for Global Stop (Panic Button)
            conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()

            conf_val = conf.value if conf else "None"
            logger.info(f"[Worker] Checking QUEUE_ACTIVE for {domain}. DB Value: '{conf_val}', IgnorePause: {ignore_queue_pause}")

            # Default: active. Only pause if QUEUE_ACTIVE is explicitly "false".
            # Missing key (fresh DB after wipe) = treat as active.
            is_paused = conf is not None and conf.value.lower() == "false"

            if ignore_queue_pause:
                is_paused = False

            if is_paused:
                logger.warning(f"[Worker] Queue is PAUSED. Re-queuing scan for {domain} (ID: {target_id}).")
                raise self.retry(countdown=60, max_retries=None)

            # Update Status to Running
            try:
                target = session.get(Target, target_id)
                if not target:
                    logger.warning(f"[Worker] Target {domain} (ID: {target_id}) not found in DB. Aborting scan.")
                    return
                if target.is_archived:
                    logger.info(f"[Worker] Target {domain} (ID: {target_id}) is archived — skipping scan.")
                    return

                target.scan_status = "running"
                target.scan_progress = "Initializing scan..."
                parent_tenant_id = target.tenant_id
                session.add(target)
                session.commit()

                splunk_logger.send_security_event(
                    action="scan_start",
                    user="system:worker",
                    mitre_id="TA0007",
                    details={"target_id": target_id, "domain": domain, "scan_types": scan_types},
                    tenant_id=parent_tenant_id
                )

                prom_metrics = get_metrics()
                prom_metrics.record_scan_started(tenant_id=parent_tenant_id, scan_types=scan_types)
                scan_start_time = datetime.utcnow()
            except Exception as e:
                logger.error(f"[Worker] Failed to update start status: {e}")
                session.rollback()
                return

            # Pre-check web availability
            has_http = False
            has_https = False
            from yads.core.module_registry import get_simple_dispatch_modules as _get_sdm
            _needs_web = (
                any(x in scan_types for x in ["web_analyzer", "visual_osint", "ssl_scanner", "nuclei_scanner", "crawler", "content_discovery"])
                or any(m.requires_http or m.requires_https for m in _get_sdm() if m.name in scan_types)
            )
            if _needs_web:
                logger.info(f"[Worker] Pre-checking web availability for {domain}...")
                has_http, has_https = check_web(domain)
                logger.info(f"[Worker] Web Pre-check: HTTP={has_http}, HTTPS={has_https}")

            # 1. Subdomain Scanner
            if "subdomain_scanner" in scan_types:
                module_start = datetime.utcnow()
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Subdomain Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.dns_scanner import SubdomainScanner
                    use_ct = "ssl_scanner" in scan_types
                    sub_scan = SubdomainScanner(db_session=session, use_ct_logs=use_ct)
                    logger.info(f"[Worker] Running {sub_scan.module_name} (CRT.sh: {use_ct})...")

                    with LogCapture() as logs:
                        logger.info(f"Starting {sub_scan.module_name} for {domain}")
                        result = sub_scan.process(target_id, domain)
                        captured_logs = logs.get_logs()

                    if result:
                        print(f"[Worker] {sub_scan.module_name} found changes/new data.")
                        if hasattr(result, 'log_content'):
                            result.log_content = sanitize_null_bytes(captured_logs)
                            session.add(result)
                            session.commit()
                    else:
                        print(f"[Worker] {sub_scan.module_name} no change.")

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
                    get_metrics().record_scan_error(
                        tenant_id=parent_tenant_id if 'parent_tenant_id' in locals() else None,
                        module_name="subdomain_scanner",
                        error_type=type(e).__name__
                    )

            # 1c. DNS Cleanup Scanner
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

            # Group A: dns_scanner + ssl_scanner in background while web_analyzer runs
            _group_a_futures: dict = {}
            _group_a_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan-a")

            if "dns_scanner" in scan_types:
                from yads.modules.dns_scanner import DNSRecordScanner
                _group_a_futures["dns_scanner"] = _group_a_executor.submit(
                    _run_parallel_module, DNSRecordScanner, target_id, domain
                )
                logger.info("[Worker] [Group A] dns_scanner started in background.")

            if "ssl_scanner" in scan_types and has_https:
                from yads.modules.ssl_scanner import SSLScanner
                _group_a_futures["ssl_scanner"] = _group_a_executor.submit(
                    _run_parallel_module, SSLScanner, target_id, domain
                )
                logger.info("[Worker] [Group A] ssl_scanner started in background.")
            elif "ssl_scanner" in scan_types and not has_https:
                logger.info("[Worker] [Group A] ssl_scanner skipped: no HTTPS.")

            if _group_a_futures:
                logger.info(f"[Worker] Group A running in background: {list(_group_a_futures.keys())}")

            # 2. Web Analyzer
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

                        from yads.modules.web_analyzer import WebAnalyzer
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

            # Collect Group A (dns_scanner + ssl_scanner)
            if _group_a_futures:
                logger.info("[Worker] Collecting Group A results (dns + ssl)...")
                for _ga_name, _ga_fut in _group_a_futures.items():
                    try:
                        _ga_fut.result(timeout=120)
                        logger.info(f"[Worker] [Group A] {_ga_name} completed.")
                    except Exception as _ga_err:
                        logger.error(f"[Worker] [Group A] {_ga_name} error: {_ga_err}")
                _group_a_executor.shutdown(wait=False)

            # 2b. Infrastructure Scanner
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

            # 2c. Nuclei Scanner
            if "nuclei_scanner" in scan_types:
                try:
                    t = session.get(Target, target_id)
                    if t:
                        t.scan_progress = "Running Nuclei Scanner..."
                        session.add(t)
                        session.commit()

                    from yads.modules.nuclei_scanner import NucleiScanner
                    nu = NucleiScanner(db_session=session)
                    logger.info(f"[Worker] Step 2c: Running {nu.module_name}...")
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

            # 3. Typosquat Scanner
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

            # 5. Analytics Correlator
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

            # 4b. Port Scanner
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

            # 5. Visual OSINT
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

            # Collect remaining Group A
            if _group_a_futures:
                logger.info(f"[Worker] Waiting for Group A background modules: {list(_group_a_futures.keys())}...")
                _futures_wait(list(_group_a_futures.values()), return_when=ALL_COMPLETED)
                logger.info("[Worker] Group A completed.")

            # SSL post-processing: auto-queue extracted domains
            if "ssl_scanner" in scan_types and has_https:
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

            # 7+9. Crawler + Content Discovery (Group B, sequential)
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

            # Deception Detector (without port_scanner)
            if "deception_detector" in scan_types and "port_scanner" not in scan_types:
                try:
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

            # Deception Detector (with port_scanner results)
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
                        scan_data = sanitize_null_bytes(scan_data)
                        data_hash = hashlib.sha256(_json.dumps(scan_data, sort_keys=True).encode()).hexdigest()
                        session.add(ScanResult(
                            target_id=target_id, module_name=dd_scan.module_name,
                            data=scan_data, result_hash=data_hash))
                        session.commit()
                        summary = scan_data.get("summary", {})
                        logger.info(
                            f"[Worker] {dd_scan.module_name} finished: "
                            f"{summary.get('total_detections', 0)} detections, "
                            f"risk: {summary.get('overall_risk', 'none')}"
                        )
                except Exception as e:
                    logger.error(f"[Worker] Error in Deception Detector: {e}")
                    session.rollback()

            # Registry-driven parallel module dispatch
            from yads.core.module_registry import get_simple_dispatch_modules

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
                    for _pf in _as_completed(_pfutures, timeout=180):
                        _pmod_name = _pfutures[_pf]
                        try:
                            _pf.result(timeout=120)
                            logger.info(f"[Worker] Parallel done: {_pmod_name}")
                        except Exception as _pfe:
                            logger.error(f"[Worker] Parallel error in {_pmod_name}: {_pfe}")
                logger.info("[Worker] All parallel modules completed.")

            # Subdomain Discovery & Auto-Queue Logic
            subdomain_modules_ran = bool(set(scan_types) & {'subdomain_scanner', 'dns_scanner'})
            if not subdomain_modules_ran:
                logger.debug("[Worker] Skipping auto-queue: subdomain_scanner/dns_scanner not in current scan_types.")
            else:
                auto_queue_enabled = settings.AUTO_QUEUE_SUBDOMAINS
                try:
                    aq_conf = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
                    if aq_conf:
                        auto_queue_enabled = aq_conf.value.lower() == 'true'
                except Exception:
                    pass

                try:
                    sub_res = session.exec(select(ScanResult).where(
                        ScanResult.target_id == target_id,
                        ScanResult.module_name == "subdomain_scanner"
                    ).order_by(ScanResult.scanned_at.desc())).first()

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
                            if sub_domain and sub_domain != domain:
                                ips = entry.get("ips") or []
                                if not ips:
                                    logger.debug(f"[Worker] Skipping unresolved subdomain (no IP): {sub_domain}")
                                    continue

                                existing = session.exec(select(Target).where(Target.domain == sub_domain)).first()
                                if not existing:
                                    new_target = Target(domain=sub_domain, tenant_id=parent_tenant_id)
                                    session.add(new_target)
                                    session.commit()
                                    session.refresh(new_target)
                                    new_targets_count += 1

                                    if auto_queue_enabled:
                                        subdomain_scan_types = ['dns_scanner']
                                        celery_app.send_task(
                                            "yads.worker.run_all_scans",
                                            args=[new_target.id, new_target.domain, subdomain_scan_types, parent_tenant_id]
                                        )
                                        queued_count += 1
                                        logger.info(f"[Worker] Auto-queued new subdomain: {sub_domain} with types: {subdomain_scan_types}")
                                    else:
                                        logger.info(f"[Worker] Discovered new subdomain: {sub_domain} (Auto-queue disabled)")
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
                try:
                    from yads.modules.compliance_frameworks import FRAMEWORKS, get_framework_scorer
                except ImportError:
                    from yads.modules.custom.compliance_frameworks import FRAMEWORKS, get_framework_scorer
                from sqlmodel import text as sql_text

                logger.info(f"[Worker] Recalculating compliance status for {domain}...")

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

                for framework_id in FRAMEWORKS.keys():
                    try:
                        scorer = get_framework_scorer(framework_id)
                        stats = scorer.calculate_score(target_data, target_map)

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

            try:
                prom_metrics = get_metrics()
                prom_metrics.record_scan_finished(tenant_id=parent_tenant_id)
            except Exception as e:
                logger.debug(f"[Worker] Failed to record scan_finished metric: {e}")

            # Email notification: send if changes were detected
            try:
                with Session(engine) as _email_session:
                    email_enabled = _email_session.get(SystemConfig, "EMAIL_NOTIFICATIONS_ENABLED")
                    if email_enabled and email_enabled.value.lower() == "true":
                        from yads.models import ChangeEvent
                        from sqlmodel import text as _sql_text
                        from datetime import timedelta
                        cutoff = datetime.utcnow() - timedelta(minutes=15)
                        recent_results = _email_session.exec(
                            select(ScanResult).where(
                                ScanResult.target_id == target_id,
                                ScanResult.scanned_at >= cutoff
                            )
                        ).all()
                        result_ids = [r.id for r in recent_results]
                        changes = []
                        if result_ids:
                            ce_rows = _email_session.exec(
                                select(ChangeEvent).where(ChangeEvent.scan_result_id.in_(result_ids))
                            ).all()
                            for ce in ce_rows:
                                mod = next((r.module_name for r in recent_results if r.id == ce.scan_result_id), "")
                                changes.append({
                                    "description": getattr(ce, "description", str(ce)),
                                    "module_name": mod,
                                    "severity": getattr(ce, "severity", "medium"),
                                })
                        if changes:
                            addr_conf = _email_session.get(SystemConfig, "EMAIL_NOTIFICATION_ADDRESS")
                            notify_addr = addr_conf.value.strip() if addr_conf and addr_conf.value else ""
                            if notify_addr:
                                tenant_obj = _email_session.get(Tenant, parent_tenant_id) if parent_tenant_id else None
                                lang = getattr(tenant_obj, "language", "en") or "en"
                                base_url_conf = _email_session.get(SystemConfig, "BASE_URL")
                                base_url = base_url_conf.value if base_url_conf else ""
                                from yads.core.email_service import EmailService
                                EmailService.send_scan_finished(
                                    target_domain=domain,
                                    target_id=target_id,
                                    changes=changes,
                                    to_address=notify_addr,
                                    lang=lang,
                                    base_url=base_url,
                                )
            except Exception as _email_exc:
                logger.warning(f"[Worker] Email notification failed (non-fatal): {_email_exc}")

        logger.info(f"[Worker] Finished scan for {domain}")

        if _worker_client and _worker_client.is_distributed and celery_task_id:
            _worker_client.report_task_completed(celery_task_id, success=True)

    finally:
        if 'root_logger' in locals() and 'redis_handler' in locals():
            root_logger.removeHandler(redis_handler)


# ── Discovery Tasks ────────────────────────────────────────────────────────────

@celery_app.task(name="yads.worker.run_discovery_scan", queue="discovery")
def run_discovery_scan(session_id: int, target_id: int, domain: str, depth: int):
    """
    Run a discovery-scoped scan on a single target as part of a DiscoverySession.

    Phase 1 — structured scans (DNS, SSL, CT logs):
      Re-uses existing scanner modules and extracts candidates via DiscoveryScannerAdapter.

    Phase 2 — passive hunters (SPF traversal, Wayback CDX, VirusTotal passive DNS,
      SRV enumeration, CORS/CSP headers, Robots/Sitemap, Favicon/Shodan):
      Safe, zero-impact techniques that consult public data sources only.

    All candidates are written to DiscoveryCandidate and scored by the orchestrator.
    """
    from yads.core.discovery_scanner_adapter import DiscoveryScannerAdapter
    from yads.core.discovery_orchestrator import DiscoveryOrchestrator
    from yads.core.discovery_passive_hunters import run_all_passive_hunters
    from yads.models import DiscoverySession, DiscoveryCandidate, DiscoveryDomainBlocklist, ScanResult, Tenant

    logger.info(f"[Discovery] run_discovery_scan session={session_id} target={domain} depth={depth}")

    DISCOVERY_SCAN_TYPES = ["dns_scanner", "ssl_scanner", "ct_monitor", "asn_scanner", "subdomain_scanner",
                            "cert_mismatch_scanner", "dns_history_scanner", "tld_scanner"]

    try:
        with Session(engine) as db:
            sess = db.get(DiscoverySession, session_id)
            if not sess or sess.status in ("stopped", "failed"):
                return
            include_typosquats = sess.include_typosquats
            passive_hunting = sess.passive_hunting
            web_scraping = sess.web_scraping
            tenant = db.get(Tenant, sess.tenant_id)
            vt_key = (tenant.virustotal_api_key or "") if tenant else ""
            shodan_key = (tenant.shodan_api_key or "") if tenant else ""
            # Load blocklist once for the entire scan
            blocklist_entries = db.exec(
                select(DiscoveryDomainBlocklist).where(
                    DiscoveryDomainBlocklist.tenant_id == sess.tenant_id
                )
            ).all()
            blocked_patterns = [e.pattern for e in blocklist_entries]

        # ── Phase 1: structured scanner modules ───────────────────────────────
        run_all_scans(target_id, domain, DISCOVERY_SCAN_TYPES, None)

        adapter = DiscoveryScannerAdapter(include_typosquats=include_typosquats)

        with Session(engine) as db:
            for scanner_name in DISCOVERY_SCAN_TYPES:
                result = db.exec(
                    select(ScanResult).where(
                        ScanResult.target_id == target_id,
                        ScanResult.module_name == scanner_name,
                    ).order_by(ScanResult.scanned_at.desc())
                ).first()

                if not result or not result.data:
                    continue

                for cand_domain, source_scanner, signals in adapter.extract(scanner_name, result.data):
                    _upsert_candidate(db, session_id, target_id, cand_domain, domain, source_scanner, signals, depth, blocked_patterns)

            db.commit()

        # ── Phase 2: passive hunters (opt-in per session) ─────────────────────
        if passive_hunting:
            logger.info(f"[Discovery] Running passive hunters for {domain}")
            passive = run_all_passive_hunters(domain, vt_key, shodan_key)

            with Session(engine) as db:
                for cand_domain, signal in passive:
                    _upsert_candidate(db, session_id, target_id, cand_domain, domain, "passive_hunter", [signal], depth, blocked_patterns)
                db.commit()

            logger.info(f"[Discovery] Passive hunters complete for {domain}: {len(passive)} candidates")
        else:
            logger.info(f"[Discovery] Passive hunting disabled for session {session_id} — skipping Phase 2")

        # ── Phase 3: web scraping (opt-in, heavy) ─────────────────────────────
        if web_scraping:
            WEB_SCRAPING_TYPES = ["external_resources", "crawler"]
            logger.info(f"[Discovery] Running web scraping phase for {domain}")
            run_all_scans(target_id, domain, WEB_SCRAPING_TYPES, None)

            with Session(engine) as db:
                for scanner_name in WEB_SCRAPING_TYPES:
                    result = db.exec(
                        select(ScanResult).where(
                            ScanResult.target_id == target_id,
                            ScanResult.module_name == scanner_name,
                        ).order_by(ScanResult.scanned_at.desc())
                    ).first()
                    if not result or not result.data:
                        continue
                    for cand_domain, source_scanner, signals in adapter.extract(scanner_name, result.data):
                        _upsert_candidate(db, session_id, target_id, cand_domain, domain, source_scanner, signals, depth, blocked_patterns)
                db.commit()

            logger.info(f"[Discovery] Web scraping phase complete for {domain}")
        else:
            logger.info(f"[Discovery] Web scraping disabled for session {session_id} — skipping Phase 3")

    except Exception as e:
        logger.error(f"[Discovery] run_discovery_scan error for {domain}: {e}")
    finally:
        # Always signal orchestrator, even on error
        try:
            orchestrator = DiscoveryOrchestrator(session_id)
            orchestrator.on_target_complete(depth)
        except Exception as e2:
            logger.error(f"[Discovery] orchestrator signal failed: {e2}")


def _upsert_candidate(
    db: Session,
    session_id: int,
    target_id: int,
    cand_domain: str,
    source_domain: str,
    source_scanner: str,
    signals: list,
    depth: int,
    blocked_patterns: list = [],
):
    """
    Insert a new DiscoveryCandidate or merge signals into an existing one.
    Skips the source domain itself, already-accepted targets, and blocked domains.
    """
    from yads.models import DiscoveryCandidate
    from yads.core.discovery_orchestrator import _matches_blocklist

    cand_domain = cand_domain.strip().lower()
    if not cand_domain or cand_domain == source_domain:
        return
    if "." not in cand_domain or " " in cand_domain:
        return

    # Skip blocked domains immediately — don't even insert them
    if blocked_patterns and _matches_blocklist(cand_domain, blocked_patterns):
        return

    existing = db.exec(
        select(DiscoveryCandidate).where(
            DiscoveryCandidate.session_id == session_id,
            DiscoveryCandidate.domain == cand_domain,
        )
    ).first()

    if existing:
        # Merge any new signals into the existing candidate
        merged = list(existing.matching_signals)
        changed = False
        for sig in signals:
            if sig not in merged:
                merged.append(sig)
                changed = True
        if changed:
            existing.matching_signals = merged
            db.add(existing)
        return

    # Skip if already an accepted target in this session
    if db.exec(
        select(Target).where(
            Target.domain == cand_domain,
            Target.discovery_session_id == session_id,
        )
    ).first():
        return

    db.add(DiscoveryCandidate(
        session_id=session_id,
        source_target_id=target_id,
        domain=cand_domain,
        source_scanner=source_scanner,
        depth=depth,
        relevance_score=0.0,
        matching_signals=signals,
        status="pending",
    ))


@celery_app.task(name="yads.worker.start_discovery_session", queue="discovery")
def start_discovery_session(session_id: int):
    """Entry-point task that starts a DiscoveryOrchestrator session."""
    from yads.core.discovery_orchestrator import DiscoveryOrchestrator
    orchestrator = DiscoveryOrchestrator(session_id)
    orchestrator.start()


@celery_app.task(name="yads.worker.run_osint_enrichment", bind=True)
def run_osint_enrichment(self, target_id: int, target_domain: str, tenant_id: int):
    """
    High-priority dedicated task for refreshing all OSINT modules for a single Target.
    """
    logger.info(f"[OSINT Worker] Starting enrichment for {target_domain} (ID: {target_id})")
    
    modules_to_run = [
        ("yads.modules.leaked_credentials", "LeakedCredentialsScanner"),
        ("yads.modules.dns_history_scanner", "DNSHistoryScanner"),
        ("yads.modules.whois_history_scanner", "WhoisHistoryScanner"),
        ("yads.modules.social_media_scanner", "SocialMediaScanner"),
        ("yads.modules.tech_stack_analyzer", "TechStackAnalyzer"),
        ("yads.modules.cloud_scanner", "CloudScanner"),
        ("yads.modules.subdomain_takeover_scanner", "SubdomainTakeoverScanner"),
        ("yads.modules.threat_intel_scanner", "ThreatIntelScanner"),
        ("yads.modules.shodan_censys_scanner", "ShodanCensysScanner"),
    ]
    
    with Session(engine) as session:
        for mod_path, class_name in modules_to_run:
            try:
                mod = __import__(mod_path, fromlist=[class_name])
                ScannerClass = getattr(mod, class_name)
                scanner = ScannerClass(db_session=session)
                logger.info(f"[OSINT Worker] Running {class_name} against {target_domain}")
                # Modules expecting (target_id, domain, tenant_id) or (target_id, target.domain)
                # Signature varies, so we catch TypeErrors and fall back
                try:
                    scanner.run_scan(target_id, target_domain, tenant_id)
                except TypeError:
                    # Fallback for base module signature
                    scanner.run_scan(target_id, target_domain)
            except Exception as e:
                logger.error(f"[OSINT Worker] {class_name} failed for {target_domain}: {e}")
                
        # Send Webhook Alert upon successful completion
        try:
            from yads.core.webhook_service import webhook_service
            webhook_service.trigger_osint_alert({
                "target_id": target_id,
                "target_domain": target_domain,
                "status": "completed",
                "message": "OSINT Enrichment Scan Completed"
            })
        except Exception as webhook_e:
            logger.error(f"[OSINT Worker] Failed to send webhook: {webhook_e}")
            
    logger.info(f"[OSINT Worker] Finished enrichment for {target_domain}")

@celery_app.task(name="yads.worker.sync_external_integrations")
def sync_external_integrations():
    """
    Periodic task to sync findings with external ticketing systems (Jira, GitHub).
    Focuses on closed/fixed findings that have a ticket_ref but may not have been updated.
    """
    from yads.api.routers.integrations import _push_to_jira, _push_to_github, _push_to_siem_syslog, _push_to_siem_http, _finding_to_cef, _finding_to_ecs
    
    with Session(engine) as session:
        # We look for all SecurityFindings with a ticket_ref and a closed status
        findings = session.exec(
            select(SecurityFinding).where(
                SecurityFinding.ticket_ref != None,
                SecurityFinding.status.in_(["fixed", "false_positive"])
            )
        ).all()
        
        if not findings:
            return
            
        for sf in findings:
            ic_configs = session.exec(
                select(IntegrationConfig).where(
                    IntegrationConfig.tenant_id == sf.tenant_id,
                    IntegrationConfig.is_active == True
                )
            ).all()
            
            for ic in ic_configs:
                config = ic.config or {}
                finding_stub = {"title": sf.issue, "description": sf.issue, "severity": sf.severity}
                
                if ic.integration_type == "jira":
                    _push_to_jira(config, finding_stub, sf.domain, status=sf.status, ticket_ref=sf.ticket_ref)
                elif ic.integration_type == "github":
                    _push_to_github(config, finding_stub, sf.domain, status=sf.status, ticket_ref=sf.ticket_ref)
                elif ic.integration_type == "siem_syslog":
                    cef = _finding_to_cef(finding_stub, sf.domain, status=sf.status)
                    _push_to_siem_syslog(config, cef)
                elif ic.integration_type == "siem_http":
                    ecs = _finding_to_ecs(finding_stub, sf.domain, status=sf.status)
                    _push_to_siem_http(config, ecs)

        logger.info(f"[Sync Worker] Processed {len(findings)} findings for external sync.")
