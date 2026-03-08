import time
import logging
from datetime import datetime, timedelta
from sqlmodel import Session, select, func
from yads.database import engine
from yads.models import ScanSchedule, Target, ScanResult, SystemConfig
from yads.config import settings


def get_active_scan_count(session: Session) -> int:
    """Return the number of targets currently running or queued."""
    result = session.exec(
        select(func.count(Target.id)).where(
            Target.scan_status.in_(["running", "queued"])
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

# Configure Scheduler Logger
logger = logging.getLogger("yads.scheduler")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def run_scheduler_loop(celery_app):
    """
    Main loop for the scheduler.
    Intended to be run in a separate thread/process.
    """
    logger.info("Scheduler Service Started.")
    
    while True:
        try:
            with Session(engine) as session:
                # 1. Fetch Due Schedules
                now = datetime.utcnow()
                statement = select(ScanSchedule).where(
                    ScanSchedule.is_active == True,
                    ScanSchedule.next_run_at <= now
                )
                due_schedules = session.exec(statement).all()
                
                if due_schedules:
                    logger.info(f"Checking schedules... Found {len(due_schedules)} due.")
                
                # Check global concurrent scan limit before queuing anything
                max_concurrent = get_max_concurrent_scans(session)
                active_count = get_active_scan_count(session)

                for schedule in due_schedules:
                    target = schedule.target
                    if not target:
                        logger.warning(f"Schedule {schedule.id} has no associated target. Removing.")
                        session.delete(schedule)
                        session.commit()
                        continue

                    # Respect global scan limit — pause scheduler if limit reached
                    if active_count >= max_concurrent:
                        logger.info(
                            f"[Scheduler] Limit reached ({active_count}/{max_concurrent} active). "
                            f"Pausing scheduler until next tick — {target.domain} and remaining skipped."
                        )
                        break

                    logger.info(f"Triggering scheduled scan for {target.domain} (Frequency: {schedule.frequency})")

                    # 2. Trigger Scan
                    # Defaulting to a standard set of scans for scheduled jobs.
                    # NOTE: subdomain_scanner intentionally excluded — it triggers
                    # auto-queuing of hundreds of subdomains per run.
                    scan_types = [
                        "dns_scanner", "web_analyzer", "ssl_scanner"
                    ]

                    # Send Task to Celery
                    celery_app.send_task(
                        "yads.worker.run_all_scans",
                        args=[target.id, target.domain, scan_types]
                    )
                    active_count += 1  # Track locally so we don't re-query per iteration
                    
                    # 3. Update Schedule
                    schedule.last_run_at = now
                    
                    # Calculate Next Run
                    if schedule.frequency == "daily":
                        schedule.next_run_at = now + timedelta(days=1)
                    elif schedule.frequency == "weekly":
                        schedule.next_run_at = now + timedelta(weeks=1)
                    else:
                        # Default fallback
                        schedule.next_run_at = now + timedelta(days=1)
                        
                    session.add(schedule)
                    session.commit()
                    logger.info(f"Rescheduled {target.domain} for {schedule.next_run_at}")
                    
        except Exception as e:
            logger.error(f"Scheduler Loop Error: {e}")
            
        # Sleep Check Interval (e.g. 60 seconds)
        time.sleep(60)
