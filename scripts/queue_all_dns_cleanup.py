"""
Script to queue ALL targets from ALL tenants for the DNS Cleanup Scanner.
Useful for performing a global "cleanup" as requested by the user.
"""

from sqlmodel import Session, select
from yads.database import engine
from yads.models import Target
from yads.worker import celery_app
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("queue_cleanup")

def queue_all():
    with Session(engine) as session:
        # Fetch all active (non-archived) targets across all tenants
        targets = session.exec(select(Target).where(Target.is_archived == False)).all()
        
        logger.info(f"Found {len(targets)} active targets to queue for dns_cleanup.")
        
        count = 0
        for t in targets:
            try:
                # Type: dns_cleanup
                # Note: run_all_scans(target_id, domain, scan_types, tenant_id)
                celery_app.send_task(
                    "yads.worker.run_all_scans", 
                    args=[t.id, t.domain, ["dns_cleanup"], t.tenant_id]
                )
                count += 1
                if count % 100 == 0:
                    logger.info(f"Queued {count} targets...")
            except Exception as e:
                logger.error(f"Failed to queue target {t.domain} (ID: {t.id}): {e}")

        logger.info(f"Successfully queued {count} targets for DNS Cleanup Scanner.")

if __name__ == "__main__":
    queue_all()
