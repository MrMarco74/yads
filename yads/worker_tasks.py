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
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, wait as _futures_wait, ALL_COMPLETED, as_completed as _as_completed
import dns.resolver

from sqlmodel import Session, select
from sqlalchemy import func

from yads.worker_core import celery_app, _reset_target_status, logger as _core_logger
from yads.worker_modules import LogCapture, _run_parallel_module, _run_simple_module
from yads.database import engine
from yads.models import (
    ScanResult, Target, SystemConfig, Tenant,
    SecurityTrend, ComplianceTrend, ComplianceTargetStatus,
    SecurityAuditLog, SystemAlertLog, HTTPTraffic, IntegrationConfig, SecurityFinding,
    BrandWatch, ShadowDomainCandidate
)
from yads.config import settings
from yads.core.splunk_logger import splunk_logger
from yads.core.webhook_service import webhook_service
from yads.core.base import sanitize_null_bytes
from yads.core.metrics import get_metrics
from urllib.parse import quote
from yads.modules._shared_osint_utils import RateLimitedClient
from yads.modules.tld_scanner import get_tld_list

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
    from yads.core.scoring import calculate_target_score, get_grade, SCORED_MODULE_NAMES
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
                          AND module_name = ANY(:module_names)
                        ORDER BY module_name, scanned_at DESC
                    """)
                    latest_rows = session.execute(query, {"target_id": t.id, "module_names": SCORED_MODULE_NAMES}).all()

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

                        # Per-control gap tracking (#13): ComplianceTrend only
                        # ever stored the aggregate score — this diffs which
                        # *specific* controls flipped PASS<->FAIL since the
                        # last run, so "what changed since last report" is a
                        # real answer instead of just a score delta.
                        try:
                            from yads.core.baseline_diff import diff_against_last
                            breakdown = stats.get("detailed_breakdown") or {}
                            passing_ids = [cid for cid, c in breakdown.items() if c.get("status") == "PASS"]
                            diff = diff_against_last(
                                session, f"compliance_passing_controls:{framework_id}",
                                passing_ids, tenant_id=tenant.id,
                            )
                            if not diff["is_first"]:
                                newly_closed = diff["added"]       # now passing, wasn't before
                                newly_failing = diff["removed"]    # was passing, now failing
                                if newly_closed or newly_failing:
                                    logger.info(
                                        f"[Worker] Compliance gap change for {tenant.name}/{framework_id}: "
                                        f"closed={newly_closed} reopened={newly_failing}"
                                    )
                                    if newly_failing:
                                        webhook_service.trigger_event(tenant.id, "security_alert", {
                                            "module": "compliance",
                                            "severity": "medium",
                                            "title": f"{len(newly_failing)} {framework_id.upper()} control(s) newly failing",
                                            "detail": f"Controls: {', '.join(newly_failing)}",
                                        })
                        except Exception as ce:
                            logger.warning(f"[Worker] Compliance control-gap diff failed (non-fatal): {ce}")

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


@celery_app.task(name="yads.worker.send_recurring_reports")
def send_recurring_reports():
    """
    Recurring report delivery (#45): checks all active ReportSubscriptions
    and emails the ones due today (weekly on their configured weekday,
    monthly on their configured day-of-month), independent of ScanSchedule
    and the fixed daily digest.
    """
    from yads.models import ReportSubscription
    from yads.core.email_service import EmailService
    logger.info("[Worker] Checking recurring report subscriptions...")
    try:
        today = datetime.utcnow().date()
        with Session(engine) as session:
            subs = session.exec(select(ReportSubscription).where(ReportSubscription.is_active == True)).all()
            for sub in subs:
                if not sub.recipients:
                    continue
                due = False
                if sub.frequency == "weekly" and today.weekday() == sub.day_of_week:
                    due = True
                elif sub.frequency == "monthly" and today.day == sub.day_of_month:
                    due = True
                # Don't re-send twice on the same calendar day (e.g. beat retries).
                if due and sub.last_sent_at and sub.last_sent_at.date() == today:
                    due = False
                if not due:
                    continue

                tenant = session.get(Tenant, sub.tenant_id)
                base_url_conf = session.get(SystemConfig, "BASE_URL")
                base_url = base_url_conf.value if base_url_conf else ""
                report_url = f"{base_url}/security-findings/" if sub.report_type == "findings_csv" else f"{base_url}/executive-report"

                try:
                    EmailService().send_mail(
                        to_addr=sub.recipients,
                        subject=f"YADS Recurring Report: {sub.name} ({tenant.name if tenant else sub.tenant_id})",
                        body_text=f"Your scheduled '{sub.name}' report is ready: {report_url}",
                        body_html=f"<p>Your scheduled report <strong>{sub.name}</strong> is ready.</p><p><a href='{report_url}'>View report</a></p>",
                    )
                    sub.last_sent_at = datetime.utcnow()
                    session.add(sub)
                    logger.info(f"[Worker] Sent recurring report '{sub.name}' to {len(sub.recipients)} recipient(s)")
                except Exception as se:
                    logger.warning(f"[Worker] Failed to send recurring report '{sub.name}': {se}")
            session.commit()
    except Exception as e:
        logger.error(f"[Worker] send_recurring_reports failed: {e}")


@celery_app.task(name="yads.worker.check_archived_target_reactivation")
def check_archived_target_reactivation():
    """
    Reactivation suggestion for archived targets (#65). dns_cleanup_scanner
    archives domains that stop resolving, but never rechecks them — a
    reactivated domain (renewed after expiry, service moved back) stays
    silently archived forever. Periodically re-resolve DNS-dead-archived
    targets and flag the ones that respond again, via the same webhook
    channel other modules use — doesn't auto-unarchive (a human should
    confirm this wasn't a squatter/different owner before resuming scans).
    """
    import dns.resolver
    logger.info("[Worker] Checking archived (dns_dead) targets for reactivation...")
    try:
        with Session(engine) as session:
            archived = session.exec(
                select(Target).where(Target.is_archived == True, Target.archived_reason == "dns_dead")
            ).all()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 5.0
            reactivation_candidates = 0
            for t in archived:
                try:
                    resolver.resolve(t.domain, "A")
                    resolves = True
                except Exception:
                    resolves = False
                if resolves:
                    reactivation_candidates += 1
                    logger.info(f"[Worker] Archived target {t.domain} resolves again — suggesting reactivation")
                    webhook_service.trigger_event(t.tenant_id, "new_asset", {
                        "domain": t.domain,
                        "source": "archived_target_reactivation",
                        "detail": f"{t.domain} was archived as DNS-dead but now resolves again — review and reactivate if legitimate.",
                    })
            if reactivation_candidates:
                logger.info(f"[Worker] {reactivation_candidates} archived target(s) flagged for reactivation review")
    except Exception as e:
        logger.error(f"[Worker] check_archived_target_reactivation failed: {e}")


@celery_app.task(name="yads.worker.check_cert_expiry_alerts")
def check_cert_expiry_alerts():
    """
    Proactive cert-expiry alerting (#22). `cert_timeline.py` already computes
    days-until-expiry, but only when a user happens to open that page — there
    was no active alert. Walks every target's latest ssl_scanner result and
    fires a webhook the first time a cert crosses the 30-day-to-expiry window
    (dedup via baseline_diff keyed on the cert's own notAfter date, so a
    renewed cert re-arms the alert instead of going permanently silent).
    """
    from yads.core.baseline_diff import diff_against_last
    logger.info("[Worker] Starting cert-expiry alert sweep...")
    try:
        with Session(engine) as session:
            targets = session.exec(select(Target).where(Target.is_archived == False)).all()
            for t in targets:
                latest = session.exec(
                    select(ScanResult).where(
                        ScanResult.target_id == t.id,
                        ScanResult.module_name == "ssl_scanner",
                    ).order_by(ScanResult.scanned_at.desc())
                ).first()
                if not latest or not latest.data:
                    continue
                not_after = latest.data.get("notAfter")
                if not not_after:
                    continue
                try:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                except Exception:
                    continue
                days_left = (expiry_dt - datetime.utcnow()).days
                if days_left > 30:
                    continue

                diff = diff_against_last(session, "cert_expiry_alerted", [not_after], target_id=t.id)
                if not_after in diff["added"]:
                    webhook_service.trigger_event(t.tenant_id, "security_alert", {
                        "domain": t.domain,
                        "module": "ssl_scanner",
                        "severity": "critical" if days_left <= 0 else "medium",
                        "title": (
                            f"Certificate expired {abs(days_left)} day(s) ago" if days_left <= 0
                            else f"Certificate expires in {days_left} day(s)"
                        ),
                        "detail": f"{t.domain} — expires {not_after}",
                    })
                    logger.info(f"[Worker] Cert-expiry alert fired for {t.domain} ({days_left} days left)")
    except Exception as e:
        logger.error(f"[Worker] check_cert_expiry_alerts failed: {e}")


# ── Scan Heartbeat ────────────────────────────────────────────────────────────

def _run_scan_heartbeat(target_id: int, stop_event: threading.Event) -> None:
    """Daemon thread: updates scan_heartbeat_at every 2 min while scan is running."""
    while not stop_event.wait(120):
        try:
            with Session(engine) as s:
                t = s.get(Target, target_id)
                if t and t.scan_status == "running":
                    t.scan_heartbeat_at = datetime.now(timezone.utc)
                    s.add(t)
                    s.commit()
        except Exception:
            pass


# ── Stuck Job Cleaner ─────────────────────────────────────────────────────────

@celery_app.task(name="yads.worker.reset_stuck_targets")
def reset_stuck_targets():
    """
    Reset genuinely stuck targets back to 'idle':
    - 'running' targets whose heartbeat is stale (> 10 min without update → worker crash/hang)
    - 'running' targets with no heartbeat and started > 45 min ago (pre-heartbeat entries)
    - 'queued' targets with queued_at > 60 min ago (task lost from broker)
    """
    from sqlmodel import text as sql_text
    from datetime import datetime, timedelta, timezone

    heartbeat_cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    running_cutoff   = datetime.now(timezone.utc) - timedelta(minutes=45)
    queued_cutoff    = datetime.now(timezone.utc) - timedelta(minutes=60)
    heartbeat_cutoff_str = heartbeat_cutoff.strftime("%Y-%m-%dT%H:%M:%S")
    running_cutoff_str   = running_cutoff.strftime("%Y-%m-%dT%H:%M:%S")
    queued_cutoff_str    = queued_cutoff.strftime("%Y-%m-%dT%H:%M:%S")

    with Session(engine) as db:
        # Reset stuck 'running' targets:
        # - Has heartbeat but it's stale (> 10 min) → worker crashed mid-scan
        # - No heartbeat and queued_at old (> 45 min) → pre-heartbeat era, truly stuck
        # - No heartbeat and queued_at NULL → very old stuck entry
        r1 = db.execute(sql_text("""
            UPDATE target SET scan_status='idle', queued_at=NULL, scan_heartbeat_at=NULL
            WHERE scan_status = 'running' AND (
                (scan_heartbeat_at IS NOT NULL AND scan_heartbeat_at < :hb_cutoff)
                OR (scan_heartbeat_at IS NULL AND (queued_at IS NULL OR queued_at < :run_cutoff))
            )
        """), {"hb_cutoff": heartbeat_cutoff_str, "run_cutoff": running_cutoff_str})

        # Reset orphaned 'queued' targets (task lost from broker)
        r2 = db.execute(sql_text(
            "UPDATE target SET scan_status='idle', queued_at=NULL "
            "WHERE scan_status = 'queued' "
            "AND queued_at IS NOT NULL "
            "AND queued_at < :cutoff"
        ), {"cutoff": queued_cutoff_str})

        db.commit()

        if r1.rowcount:
            logger.warning(f"[StuckCleaner] Reset {r1.rowcount} stuck running target(s) → idle (stale heartbeat / no heartbeat > 45 min)")
        if r2.rowcount:
            logger.warning(f"[StuckCleaner] Reset {r2.rowcount} orphaned queued target(s) → idle (queued_at > 60 min)")
        if not r1.rowcount and not r2.rowcount:
            logger.debug("[StuckCleaner] No stuck targets found")


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

            logger.info("[Worker] Data retention pruning completed successfully.")
    except Exception as e:
        logger.error(f"[Worker] Data retention pruning failed: {e}")


def _resolve_nuclei_binary() -> str:
    """Admin-configured nuclei path (Settings -> Scanner Resources), falling
    back to a bare 'nuclei' resolved via PATH."""
    with Session(engine) as session:
        conf = session.get(SystemConfig, "NUCLEI_BINARY_PATH")
    return (conf.value.strip() if conf and conf.value else "") or "nuclei"


@celery_app.task(name="yads.worker.update_nuclei_templates")
def update_nuclei_templates():
    """
    Runs 'nuclei -ut' to update vulnerability templates. Must run on a worker
    node -- the nuclei binary and the nuclei_templates volume are only
    present in the worker image (see Dockerfile's base-scanner stage), not
    the API image.
    """
    import subprocess
    nuclei_bin = _resolve_nuclei_binary()
    logger.info(f"[Worker] Running Nuclei template update ({nuclei_bin}).")
    try:
        proc = subprocess.run(  # nosec B603 B607 - path from admin-only Settings, no user input
            [nuclei_bin, "-ut"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600
        )
        if proc.returncode == 0:
            last_line = proc.stdout.splitlines()[-1] if proc.stdout.strip() else "Templates are up to date."
            return {"ok": True, "message": last_line}
        return {"ok": False, "message": f"Update failed ({proc.returncode}): {proc.stderr[:100]}"}
    except Exception as e:
        logger.error(f"[Worker] Nuclei template update failed: {e}")
        return {"ok": False, "message": str(e)}


@celery_app.task(name="yads.worker.check_nuclei_available")
def check_nuclei_available():
    """Resolve availability of the (optionally admin-configured) nuclei binary on this worker."""
    import shutil
    nuclei_bin = _resolve_nuclei_binary()
    resolved = shutil.which(nuclei_bin)
    if not resolved and os.path.isfile(nuclei_bin) and os.access(nuclei_bin, os.X_OK):
        resolved = nuclei_bin
    return {"available": bool(resolved), "path": resolved}


@celery_app.task(name="yads.worker.check_nmap_available")
def check_nmap_available():
    """
    Resolve nmap availability on this worker. nmap is baked into the
    worker image at build time (Dockerfile's base-scanner stage), so this
    is normally always True -- unlike the API container, where an
    apt-get-installed nmap only lives in that container's writable layer
    and disappears on every restart/redeploy.
    """
    import shutil
    resolved = shutil.which("nmap")
    return {"available": bool(resolved), "path": resolved}


# ── Main Scan Task ────────────────────────────────────────────────────────────

@celery_app.task(name="yads.worker.run_all_scans", bind=True, acks_late=True, reject_on_worker_lost=True)
def run_all_scans(
    self,
    target_id: int,
    domain: str,
    scan_types: list[str] = None,
    tenant_id: int = None,
    ignore_queue_pause: bool = False,
    light_subdomain_scan: bool = False,
):
    """
    Main orchestration task.
    Runs configured scanners for the given target.
    If scan_types is None, runs all available scanners.
    tenant_id is passed for queue filtering purposes (actual tenant is derived from target in DB).
    light_subdomain_scan caps subdomain_scanner's wordlist brute-force to a small
    sample (CT logs still run in full) — used by run_discovery_scan, where this
    task is dispatched once per candidate per depth and an unbounded wordlist
    scan per candidate is the main cost driver on large discovery sessions.
    """
    from yads.worker_core import _worker_client

    if scan_types is None:
        scan_types = ["dns_cleanup", "dns_scanner"]

    logger.info(f"[Worker] Starting scan for {domain} (ID: {target_id}) with types: {scan_types}")

    # Cancellation check independent of Celery's in-memory revoke state.
    # This task uses acks_late+reject_on_worker_lost, so a SIGTERM'd
    # (Stop/Purge/Cancel) task is redelivered by the broker; if the
    # redelivery lands on an autoscaled worker child that never saw the
    # revoke broadcast, it would otherwise silently re-run. queue.py's
    # mark_task_cancelled() writes here before revoking, so we can catch
    # it up front regardless of which process picks up the redelivery.
    _celery_task_id = self.request.id if hasattr(self, 'request') and self.request else None
    if _celery_task_id:
        try:
            from yads.database import redis_client as _redis_client
            if _redis_client.exists(f"yads:cancelled_task:{_celery_task_id}"):
                logger.info(f"[Worker] Task {_celery_task_id} for {domain} was cancelled — skipping redelivered execution.")
                return
        except Exception as e:
            logger.warning(f"[Worker] Cancellation check failed for task {_celery_task_id}: {e}")

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
                target.queued_at = datetime.now(timezone.utc)  # track when worker started — used by StuckCleaner
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

            # Start heartbeat thread — updates scan_heartbeat_at every 2 min
            _hb_stop = threading.Event()
            _hb_thread = threading.Thread(
                target=_run_scan_heartbeat, args=(target_id, _hb_stop), daemon=True
            )
            _hb_thread.start()

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
                    wordlist_limit = 100 if light_subdomain_scan else None
                    sub_scan = SubdomainScanner(db_session=session, use_ct_logs=use_ct, wordlist_limit=wordlist_limit)
                    logger.info(f"[Worker] Running {sub_scan.module_name} (CRT.sh: {use_ct}, wordlist_limit: {wordlist_limit})...")

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
                    # as_completed(timeout=...) raises TimeoutError if even ONE of
                    # the submitted futures is still running when the window
                    # elapses -- with up to 26 modules sharing 6 threads and some
                    # (nuclei/crawler/visual_osint) legitimately taking minutes,
                    # 3 total minutes for the whole batch was far too tight. That
                    # TimeoutError was uncaught, crashing the entire run_all_scans
                    # task and skipping everything after this block (status
                    # finalization, webhooks, auto-queue) -- not just the slow
                    # module. Catch it, log which modules are still outstanding,
                    # and keep waiting for the rest individually instead of
                    # abandoning the whole task. (Exiting the `with` block still
                    # blocks until every submitted future finishes either way --
                    # ThreadPoolExecutor can't forcibly kill a running thread --
                    # so this doesn't shorten a genuinely hung module, it just
                    # stops one slow module from taking the whole scan down.)
                    try:
                        _pf_iter = _as_completed(_pfutures, timeout=1800)
                        while True:
                            try:
                                _pf = next(_pf_iter)
                            except StopIteration:
                                break
                            _pmod_name = _pfutures[_pf]
                            try:
                                _pf.result(timeout=120)
                                logger.info(f"[Worker] Parallel done: {_pmod_name}")
                            except Exception as _pfe:
                                logger.error(f"[Worker] Parallel error in {_pmod_name}: {_pfe}")
                    except TimeoutError:
                        _still_running = [n for f, n in _pfutures.items() if not f.done()]
                        logger.error(
                            f"[Worker] Parallel module batch exceeded 30min timeout — "
                            f"still running: {_still_running}. Continuing scan; the "
                            f"`with` block below will still wait for these threads to "
                            f"finish before the task can complete."
                        )
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
                        review_count = 0

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

                                    # Pre-scoring: only auto-queue a real scan when the
                                    # subdomain was independently surfaced by >=2 signals
                                    # (e.g. CT logs AND wordlist match). A single-signal
                                    # candidate (typically a plain wordlist guess) is kept
                                    # as a Target but only proposed for manual review —
                                    # this is what kept the queue-explosion incident from
                                    # recurring (see #9 in TODO_VIBE_SESSIONS.md).
                                    signal_count = len(entry.get("sources") or [])
                                    high_confidence = signal_count >= 2

                                    if auto_queue_enabled and high_confidence:
                                        subdomain_scan_types = ['dns_scanner']
                                        celery_app.send_task(
                                            "yads.worker.run_all_scans",
                                            args=[new_target.id, new_target.domain, subdomain_scan_types, parent_tenant_id]
                                        )
                                        queued_count += 1
                                        logger.info(
                                            f"[Worker] Auto-queued new subdomain: {sub_domain} "
                                            f"(signals={signal_count}) with types: {subdomain_scan_types}"
                                        )
                                    else:
                                        reason = "Auto-queue disabled" if not auto_queue_enabled else f"only {signal_count} signal(s), needs manual review"
                                        review_count += 1
                                        logger.info(f"[Worker] Discovered new subdomain: {sub_domain} ({reason})")
                                        webhook_service.trigger_event(parent_tenant_id, "new_asset", {
                                            "domain": sub_domain,
                                            "source": "subdomain_discovery",
                                            "parent": domain,
                                            "signal_count": signal_count,
                                            "needs_review": not high_confidence,
                                        })

                        if new_targets_count > 0:
                            logger.info(
                                f"[Worker] Subdomain Discovery: Added {new_targets_count} new targets. "
                                f"Auto-queued: {queued_count}. Pending manual review: {review_count}."
                            )

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

            # Stop heartbeat thread
            if '_hb_stop' in locals():
                _hb_stop.set()

            # Reset status
            try:
                t = session.get(Target, target_id)
                if t:
                    t.scan_status = "idle"
                    t.scan_progress = f"Last scan completed at {datetime.utcnow().strftime('%H:%M:%S')}"
                    t.scan_heartbeat_at = None
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
                if 'scan_start_time' in locals():
                    scan_duration = (datetime.utcnow() - scan_start_time).total_seconds()
                else:
                    scan_duration = 0.0
                splunk_logger.send_ops_event(
                    category="scan_completed",
                    message=f"Scan completed for {domain}",
                    details={
                        "target_id": target_id,
                        "domain": domain,
                        "duration_seconds": round(scan_duration, 2),
                        "scan_types": scan_types
                    },
                    tenant_id=parent_tenant_id
                )
            except Exception:
                pass

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

@celery_app.task(name="yads.worker.run_discovery_scan", queue="discovery", acks_late=True, reject_on_worker_lost=True)
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
        run_all_scans(target_id, domain, DISCOVERY_SCAN_TYPES, None, light_subdomain_scan=True)

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

            # CT-log SANs behave incrementally rather than as a flat snapshot:
            # diff against the last-seen set for this target so repeated/scheduled
            # discovery runs only surface newly-issued certs (see baseline_diff.py),
            # closer to live CT-log streaming than a one-off crt.sh query.
            ct_signals = {"ct_log", "ct_san_cohost"}
            ct_hosts = [d for d, sig in passive if sig in ct_signals]
            other = [(d, sig) for d, sig in passive if sig not in ct_signals]

            if ct_hosts:
                from yads.core.baseline_diff import diff_against_last
                with Session(engine) as db:
                    ct_diff = diff_against_last(
                        db, "ct_log_sans", ct_hosts,
                        tenant_id=sess.tenant_id, target_id=target_id,
                    )
                new_ct_hosts = set(ct_diff["added"])
                passive = other + [(d, sig) for d, sig in passive if sig in ct_signals and d in new_ct_hosts]
                logger.info(
                    f"[Discovery] CT-log SANs for {domain}: {len(ct_hosts)} total, "
                    f"{len(new_ct_hosts)} new since last check"
                )
            else:
                passive = other

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


@celery_app.task(name="yads.worker.start_discovery_session", queue="discovery", acks_late=True, reject_on_worker_lost=True)
def start_discovery_session(session_id: int):
    """Entry-point task that starts a DiscoveryOrchestrator session."""
    from yads.core.discovery_orchestrator import DiscoveryOrchestrator
    orchestrator = DiscoveryOrchestrator(session_id)
    orchestrator.start()


@celery_app.task(name="yads.worker.run_osint_enrichment", bind=True, acks_late=True, reject_on_worker_lost=True)
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
        logger.info(f"[Sync Worker] Processed {len(findings)} findings for external sync.")


_CRTSH_KEYWORD_URL = "https://crt.sh/?q={keyword}&output=json"

# Module-level singleton: RateLimitedClient tracks last-request timestamps
# on the INSTANCE, so a fresh client per call (as this used to do) never
# actually throttles anything -- every call starts with no last-request
# history. One shared client across the whole process is what makes the
# registered 1 req/s limit real when multiple BrandWatch rows are processed
# in the same run_brand_watch_scan tick.
_brand_watch_ct_client = RateLimitedClient()
_brand_watch_ct_client.register_service("crtsh", requests_per_second=1.0)


def _ct_search_keyword(keyword: str) -> list:
    """Substring-search crt.sh for a brand keyword across all issued certs
    (NOT scoped to a known domain, unlike ct_monitor.py's _fetch_certs)."""
    domains = set()
    try:
        url = _CRTSH_KEYWORD_URL.format(keyword=quote(keyword, safe=""))
        resp = _brand_watch_ct_client.get("crtsh", url, timeout=20)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if keyword.lower() in name:
                        domains.add(name)
    except Exception as e:
        logger.warning(f"[BrandWatch] crt.sh search failed for '{keyword}': {e}")

    return sorted(domains)


def _probe_keyword_across_tlds(keyword: str) -> list:
    """Check whether <keyword>.<tld> resolves, for every TLD in the shared
    tld_scanner TLD list. Modeled on tld_scanner.py's threaded check_tld
    closure, but against a bare keyword rather than a known domain's SLD."""
    found = []

    def check(tld):
        candidate = f"{keyword}.{tld}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.resolve(candidate, "A")
            return candidate
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(check, tld) for tld in get_tld_list()]
        for future in _as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found)


@celery_app.task(name="yads.worker.run_brand_watch_scan")
def run_brand_watch_scan():
    """Daily beat task: for every active BrandWatch, search CT logs and
    probe TLDs for the brand keyword, diff against known Targets, and
    upsert new ShadowDomainCandidate rows for triage."""
    with Session(engine) as session:
        watches = session.exec(select(BrandWatch).where(BrandWatch.active == True)).all()

        for watch in watches:
            try:
                ct_domains = _ct_search_keyword(watch.keyword)
                tld_domains = _probe_keyword_across_tlds(watch.keyword)

                known_domains = set(
                    d.lower() for d in session.exec(
                        select(Target.domain).where(Target.tenant_id == watch.tenant_id)
                    ).all()
                )
                existing_candidates = {
                    c.discovered_domain: c
                    for c in session.exec(
                        select(ShadowDomainCandidate)
                        .where(ShadowDomainCandidate.brand_watch_id == watch.id)
                    ).all()
                }

                new_count = 0
                now = datetime.utcnow()
                for domain, source in [(d, "ct_log") for d in ct_domains] + [(d, "tld_enum") for d in tld_domains]:
                    if domain in known_domains:
                        continue
                    existing = existing_candidates.get(domain)
                    if existing is not None:
                        # Re-discovered an already-known candidate (any status:
                        # new/confirmed/dismissed) -- update last_seen_at so a
                        # human can judge the re-appearance against the
                        # original dismissal reasoning, rather than silently
                        # ignoring it.
                        existing.last_seen_at = now
                        session.add(existing)
                        continue
                    new_candidate = ShadowDomainCandidate(
                        brand_watch_id=watch.id,
                        tenant_id=watch.tenant_id,
                        discovered_domain=domain,
                        source=source,
                    )
                    session.add(new_candidate)
                    existing_candidates[domain] = new_candidate
                    new_count += 1

                watch.last_run_at = now
                session.add(watch)

                try:
                    entry = SecurityAuditLog(
                        event_type="brand_watch_scan",
                        tenant_id=watch.tenant_id,
                        success=True,
                        details={
                            "keyword": watch.keyword,
                            "ct_domains_found": len(ct_domains),
                            "tld_domains_found": len(tld_domains),
                            "new_candidates": new_count,
                        },
                    )
                    session.add(entry)
                except Exception as e:
                    logger.warning(f"[BrandWatch] Failed to write audit log: {e}")

                session.commit()
            except Exception:
                # Don't let one watch's failure (e.g. a race causing an
                # IntegrityError) abort the whole daily task -- every other
                # tenant's watch, including their last_run_at update, must
                # still be processed.
                session.rollback()
                logger.exception(f"[BrandWatch] Failed to process watch id={watch.id} keyword={watch.keyword!r}")
                continue


@celery_app.task(name="yads.worker.check_splunk_hec_health")
def check_splunk_hec_health():
    """
    Periodic task to check Splunk HEC health & report telemetry stats.
    """
    from yads.core.splunk_logger import splunk_logger
    stats = splunk_logger.get_stats()
    if stats["enabled"]:
        logger.info(f"[Splunk Health] HEC Queue depth: {stats['queue_depth']}/{stats['max_queue_size']}, Sent: {stats['sent_count']}, Errors: {stats['error_count']}")
        if stats["error_count"] > 10 and stats["sent_count"] == 0:
            logger.warning("[Splunk Health] High error count detected on Splunk HEC logger!")
