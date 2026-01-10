import os
import json
from sqlmodel import Session, select, create_engine
from yads.models import ScanResult, Target
from yads.config import settings
from yads.worker import celery_app

def queue_online_scans():
    # Prefer env, fallback to settings
    db_url = os.environ.get("DATABASE_URL") or settings.DATABASE_URL
    # Docker fix if running locally without env
    if "user:password" in db_url and "localhost" in db_url:
         db_url = "postgresql://yads:yads@localhost:5432/yads"
    
    print(f"Connecting to DB: {db_url}")
    engine = create_engine(db_url)
    
    online_targets = []

    with Session(engine) as session:
        targets = session.exec(select(Target)).all()
        print(f"Checking {len(targets)} targets for Online status...")
        
        for t in targets:
            is_online = False
            
            # 1. Check Web Analyzer (Most reliable for 'Directory Browsing' relevance)
            web = session.exec(select(ScanResult).where(
                ScanResult.target_id == t.id,
                ScanResult.module_name == 'web_analyzer'
            ).order_by(ScanResult.scanned_at.desc())).first()
            
            if web and web.data:
                if web.data.get("http_status", 0) > 0 or web.data.get("https_status", 0) > 0:
                    is_online = True
            
            # 2. Check Port Scanner (If web didn't run or failed, but ports open)
            if not is_online:
                port = session.exec(select(ScanResult).where(
                    ScanResult.target_id == t.id,
                    ScanResult.module_name == 'port_scanner'
                ).order_by(ScanResult.scanned_at.desc())).first()
                
                if port and port.data:
                    if port.data.get("open_ports") and len(port.data["open_ports"]) > 0:
                        is_online = True
            
            if is_online:
                online_targets.append(t)

    print(f"\nFound {len(online_targets)} Online targets.")
    print("Queueing 'web_analyzer' for all of them to check for Directory Browsing...")

    for t in online_targets:
        # We only need web_analyzer for directory browsing check
        scan_types = ["web_analyzer"]
        
        # print(f"  -> Queueing: {t.domain}")
        celery_app.send_task(
            "yads.worker.run_all_scans", 
            args=[t.id, t.domain, scan_types]
        )
        
    print(f"Successfully queued {len(online_targets)} scans.")

if __name__ == "__main__":
    queue_online_scans()
