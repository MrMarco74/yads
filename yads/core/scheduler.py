import time
import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Session, select, func
from yads.database import engine
from yads.models import ScanSchedule, Target, ScanResult, SystemConfig, TenantScanConfig


logger = logging.getLogger("yads.scheduler")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_active_scan_count(session: Session) -> int:
    """Return the number of targets currently running (global).
    'queued' targets sit in Celery and do not consume worker concurrency."""
    result = session.exec(
        select(func.count(Target.id)).where(
            Target.scan_status == "running"
        )
    ).first()
    return result or 0


def get_tenant_active_scan_count(session: Session, tenant_id: int) -> int:
    """Return the number of targets currently running for one tenant."""
    result = session.exec(
        select(func.count(Target.id)).where(
            Target.tenant_id == tenant_id,
            Target.scan_status == "running"
        )
    ).first()
    return result or 0


def get_max_concurrent_scans(session: Session) -> int:
    """Read GLOBAL_MAX_CONCURRENT_SCANS from SystemConfig. Default: 5."""
    conf = session.exec(
        select(SystemConfig).where(SystemConfig.key == "GLOBAL_MAX_CONCURRENT_SCANS")
    ).first()
    if conf and conf.value:
        try:
            return int(conf.value)
        except ValueError:
            pass
    return 5


def is_within_scan_window(config: TenantScanConfig, now: datetime) -> bool:
    """Return True if current UTC time is within the configured scan window."""
    if not config.scan_window_start or not config.scan_window_end:
        return True  # No window configured = always allowed
    try:
        start_h, start_m = map(int, config.scan_window_start.split(":"))
        end_h, end_m = map(int, config.scan_window_end.split(":"))
        current_minutes = now.hour * 60 + now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        if start_minutes <= end_minutes:
            return start_minutes <= current_minutes < end_minutes
        else:
            # Overnight window e.g. 22:00 → 04:00
            return current_minutes >= start_minutes or current_minutes < end_minutes
    except (ValueError, AttributeError):
        return True  # Malformed config — don't block scans


def compute_next_auto_run(
    frequency: str,
    cron_expression: Optional[str],
    from_dt: datetime
) -> datetime:
    """Compute next_auto_run_at based on cron_expression or frequency."""
    if cron_expression:
        try:
            from croniter import croniter
            return croniter(cron_expression, from_dt).get_next(datetime)
        except Exception:
            pass
    if frequency == "daily":
        return from_dt + timedelta(days=1)
    elif frequency == "monthly":
        return from_dt + timedelta(days=30)
    else:  # weekly (default)
        return from_dt + timedelta(weeks=1)


# ---------------------------------------------------------------------------
# Main scheduler loop
# ---------------------------------------------------------------------------

def run_scheduler_loop(celery_app):
    """
    Main scheduler loop — runs in a background thread (60s tick).

    Pass 1: Fire due per-target ScanSchedule entries.
    Pass 2: Fire per-tenant TenantScanConfig auto-sweeps.

    Both passes respect GLOBAL_MAX_CONCURRENT_SCANS and per-tenant limits.
    """
    logger.info("Scheduler Service Started.")

    while True:
        try:
            with Session(engine) as session:
                now = datetime.utcnow()
                max_concurrent = get_max_concurrent_scans(session)
                active_count = get_active_scan_count(session)

                # ── Pass 1: Per-target ScanSchedule entries ──────────────
                due_schedules = session.exec(
                    select(ScanSchedule).where(
                        ScanSchedule.is_active == True,
                        ScanSchedule.next_run_at <= now
                    )
                ).all()

                if due_schedules:
                    logger.info(f"[Scheduler] Found {len(due_schedules)} due target schedules.")

                for schedule in due_schedules:
                    target = schedule.target
                    if not target:
                        logger.warning(f"Schedule {schedule.id} has no target. Removing.")
                        session.delete(schedule)
                        session.commit()
                        continue

                    if active_count >= max_concurrent:
                        logger.info(
                            f"[Scheduler] Global limit ({active_count}/{max_concurrent}). "
                            f"Stopping pass 1."
                        )
                        break

                    logger.info(f"[Scheduler] Triggering {target.domain} ({schedule.frequency})")
                    celery_app.send_task(
                        "yads.worker.run_all_scans",
                        args=[target.id, target.domain, ["dns_scanner", "web_analyzer", "ssl_scanner"]]
                    )
                    active_count += 1

                    schedule.last_run_at = now
                    if schedule.frequency == "daily":
                        schedule.next_run_at = now + timedelta(days=1)
                    elif schedule.frequency == "weekly":
                        schedule.next_run_at = now + timedelta(weeks=1)
                    else:
                        schedule.next_run_at = now + timedelta(days=1)
                    session.add(schedule)
                    session.commit()

                # ── Pass 2: Per-tenant TenantScanConfig auto-sweeps ──────
                due_configs = session.exec(
                    select(TenantScanConfig).where(
                        TenantScanConfig.auto_scan_enabled == True,
                        TenantScanConfig.next_auto_run_at != None,
                        TenantScanConfig.next_auto_run_at <= now,
                    )
                ).all()

                for config in due_configs:
                    if active_count >= max_concurrent:
                        logger.info("[AutoScan] Global limit reached, stopping pass 2.")
                        break

                    if not is_within_scan_window(config, now):
                        logger.debug(f"[AutoScan] Tenant {config.tenant_id}: outside scan window.")
                        continue

                    tenant_active = get_tenant_active_scan_count(session, config.tenant_id)
                    if tenant_active >= config.max_concurrent_scans:
                        logger.info(
                            f"[AutoScan] Tenant {config.tenant_id}: at tenant limit "
                            f"({tenant_active}/{config.max_concurrent_scans}), retry next tick."
                        )
                        # Don't advance next_auto_run_at — retry in 60s
                        continue

                    # Fetch idle targets, oldest first, up to max_targets_per_run
                    targets = session.exec(
                        select(Target).where(
                            Target.tenant_id == config.tenant_id,
                            Target.is_archived == False,
                            Target.scan_status == "idle",
                        ).order_by(Target.id).limit(config.max_targets_per_run)
                    ).all()

                    queued = 0
                    for target in targets:
                        if tenant_active + queued >= config.max_concurrent_scans:
                            break
                        if active_count >= max_concurrent:
                            break

                        celery_app.send_task(
                            "yads.worker.run_all_scans",
                            args=[target.id, target.domain, config.scan_types, config.tenant_id],
                        )
                        queued += 1
                        active_count += 1

                    config.last_auto_run_at = now
                    config.next_auto_run_at = compute_next_auto_run(
                        config.frequency, config.cron_expression, now
                    )
                    session.add(config)
                    session.commit()
                    logger.info(
                        f"[AutoScan] Tenant {config.tenant_id}: queued {queued} target(s). "
                        f"Next run: {config.next_auto_run_at}"
                    )

        except Exception as e:
            logger.error(f"Scheduler Loop Error: {e}")

        time.sleep(60)
