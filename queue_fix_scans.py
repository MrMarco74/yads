import os
import json
from sqlmodel import Session, select, create_engine
from yads.models import ScanResult, Target
from yads.config import settings
from yads.worker import celery_app

def queue_fix_scans():
    # Prefer env var, then settings
    db_url = os.environ.get("DATABASE_URL") or settings.DATABASE_URL
    
    # If explicitly running locally with default settings that are wrong:
    if "user:password" in db_url and "localhost" in db_url:
         db_url = "postgresql://yads:yads@localhost:5432/yads"
    
    print(f"Connecting to DB: {db_url}")
    engine = create_engine(db_url)
    
    targets_to_scan = []

    with Session(engine) as session:
        targets = session.exec(select(Target)).all()
        print(f"Checking {len(targets)} targets...")
        
        for t in targets:
            # Check latest infra scan
            scan = session.exec(select(ScanResult).where(
                ScanResult.target_id == t.id,
                ScanResult.module_name == 'infrastructure_scanner'
            ).order_by(ScanResult.scanned_at.desc())).first()
            
            needs_scan = False
            if scan and scan.data:
                ip = scan.data.get("ip")
                if ip == "0.0.0.0":
                    needs_scan = True
                    print(f"Found Target with 0.0.0.0: {t.domain}")
            
            # Optional: Check if directory browsing fix is needed? 
            # User specifically asked for "domains with 0.0.0.0".
            # But we should apply both fixes (infra + web) to these.
            
            if needs_scan:
                targets_to_scan.append(t)
    
    print(f"\nQueueing scans for {len(targets_to_scan)} targets...")
    
    for t in targets_to_scan:
        scan_types = ["infrastructure_scanner", "web_analyzer"]
        print(f"  -> Queueing: {t.domain} (ID: {t.id})")
        celery_app.send_task(
            "yads.worker.run_all_scans", 
            args=[t.id, t.domain, scan_types]
        )
        
    print("Done.")

if __name__ == "__main__":
    queue_fix_scans()
