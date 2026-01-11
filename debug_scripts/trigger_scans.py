from sqlmodel import Session, select, create_engine
from yads.worker import celery_app
from yads.models import Target
from yads.config import settings
import sys

# Create DB Engine (Worker config handles this usually, but we need it here to fetch targets)
engine = create_engine(settings.DATABASE_URL)

def trigger_scans():
    print("Fetching targets...")
    with Session(engine) as session:
        targets = session.exec(select(Target)).all()
        
    if not targets:
        print("No targets found.")
        return

    print(f"Found {len(targets)} targets. Queueing infrastructure_scanner...")
    
    for t in targets:
        # Enqueue infrastructure_scanner specifically
        print(f" -> Queueing {t.domain} (ID: {t.id})")
        celery_app.send_task(
            "yads.worker.run_all_scans", 
            args=[t.id, t.domain],
            kwargs={
                "scan_types": ["infrastructure_scanner"],
                "ignore_queue_pause": True # Force run even if queue paused, this is a manual fix
            }
        )
    
    print("\nDone! All tasks queued.")

if __name__ == "__main__":
    trigger_scans()
