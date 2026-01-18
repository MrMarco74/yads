import time
import logging
from datetime import datetime, timedelta
from sqlmodel import Session, select
from yads.database import engine
from yads.models import ScanSchedule, Target, ScanResult
from yads.config import settings

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
                
                for schedule in due_schedules:
                    target = schedule.target
                    if not target:
                        logger.warning(f"Schedule {schedule.id} has no associated target. Removing.")
                        session.delete(schedule)
                        session.commit()
                        continue
                        
                    logger.info(f"Triggering scheduled scan for {target.domain} (Frequency: {schedule.frequency})")
                    
                    # 2. Trigger Scan
                    # Defaulting to a standard set of scans for scheduled jobs
                    scan_types = [
                        "subdomain_scanner", "dns_scanner", "web_analyzer", 
                        "ssl_scanner", "nuclei_scanner", "port_scanner"
                    ]
                    
                    # Send Task to Celery
                    celery_app.send_task(
                        "yads.worker.run_all_scans", 
                        args=[target.id, target.domain, scan_types]
                    )
                    
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
