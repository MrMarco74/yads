import asyncio
import logging
from datetime import datetime, timedelta
from sqlmodel import Session, select, create_engine
from celery import Celery

from yads.config import settings
from yads.models import ScanSchedule, Target, SystemConfig
from yads.core.splunk_logger import splunk_logger

# Use existing DB engine from config
engine = create_engine(settings.DATABASE_URL)

# Connect to Celery for triggering tasks
# We use the same broker URL as defined in settings
celery_app = Celery("yads_scheduler", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

logger = logging.getLogger("yads.scheduler")

from yads.core.tenant_logger import TenantLogger

class ScanScheduler:
    def __init__(self):
        self.running = False

    async def start(self):
        self.running = True
        logger.info("[Scheduler] Service Started.")
        splunk_logger.send_event({"action": "SCHEDULER_STARTUP"}, sourcetype="yads:scheduler")
        
        while self.running:
            try:
                await self.tick()
            except Exception as e:
                logger.error(f"[Scheduler] Tick failed: {e}")
                splunk_logger.send_event({
                    "action": "SCHEDULER_ERROR",
                    "error": str(e)
                }, sourcetype="yads:scheduler:error")
            
            # Sleep for 60 seconds
            await asyncio.sleep(60)

    async def tick(self):
        """
        Main scheduler loop. Checks DB for due tasks.
        """
        now = datetime.utcnow()
        
        with Session(engine) as session:
            # Check Master Switch
            conf = session.get(SystemConfig, "SCHEDULER_ACTIVE")
            if conf and conf.value == "false":
                # Scheduler Paused
                return

            # Find Due Schedules
            # next_run_at <= NOW and is_active = True
            query = select(ScanSchedule).where(
                ScanSchedule.next_run_at <= now,
                ScanSchedule.is_active == True
            )
            due_schedules = session.exec(query).all()
            
            if not due_schedules:
                return

            logger.info(f"[Scheduler] Found {len(due_schedules)} due schedules.")
            
            for schedule in due_schedules:
                target = schedule.target
                session.refresh(target) # Ensure relationships loaded if needed
                
                if not target:
                    logger.warning(f"[Scheduler] Schedule {schedule.id} has no target.")
                    continue
                
                # Use Tenant Logger for Context
                t_logger = TenantLogger(logger, target.tenant_id)
                t_logger.info(f"[Scheduler] Triggering schedule {schedule.id} for {target.domain}")
                
                # 1. Trigger Task
                # Using send_task to decouple from worker code import if possible, 
                # but we know the task name: "yads.worker.run_all_scans"
                task_args = [target.id, target.domain, None] # None = All Scans
                
                task = celery_app.send_task("yads.worker.run_all_scans", args=task_args)
                
                # 2. Log Event (Splunk)
                splunk_logger.send_security_event(
                    action="scheduled_scan_triggered",
                    user="system:scheduler",
                    mitre_id="TA0000", # Automation
                    details={
                        "schedule_id": schedule.id,
                        "target_id": target.id,
                        "domain": target.domain,
                        "task_id": task.id
                    },
                    tenant_id=target.tenant_id
                )

                # 3. Calculate Next Run
                # Simple logic for MVP: Daily = +24h, Weekly = +7d
                # IMPORTANT: Base calculation on 'now' to avoid drift if server was down, 
                # OR base on 'next_run_at' to keep strict schedule?
                # User usually prefers 'now + interval' to avoid burst of catch-up jobs.
                
                if schedule.frequency == "daily":
                    schedule.next_run_at = now + timedelta(days=1)
                elif schedule.frequency == "weekly":
                    schedule.next_run_at = now + timedelta(weeks=1)
                else:
                    # Default backup
                    schedule.next_run_at = now + timedelta(days=1)
                
                schedule.last_run_at = now
                session.add(schedule)
            
            session.commit()
            logger.info("[Scheduler] Tick complete. Schedules updated.")
