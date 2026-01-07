from sqlmodel import Session, create_engine, select
from yads.models import ScanResult, Target
from yads.config import settings
import json

engine = create_engine(settings.DATABASE_URL)

with Session(engine) as session:
    # Find latest DNS scan
    scan = session.exec(select(ScanResult).where(ScanResult.module_name == "dns_scanner").order_by(ScanResult.scanned_at.desc())).first()
    
    if scan:
        print(f"Target ID: {scan.target_id}")
        data = scan.data
        if isinstance(data, str):
            data = json.loads(data)
            
        subs = data.get("subdomains")
        print(f"Subdomains found: {subs}")
        if subs:
            print("Count:", len(subs))
    else:
        print("No DNS scan found.")
