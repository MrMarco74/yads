from sqlmodel import Session, select, create_engine
from yads.models import ScanResult, Target
from yads.config import settings

engine = create_engine(settings.DATABASE_URL)

def debug_one():
    with Session(engine) as session:
        t = session.exec(select(Target).where(Target.domain == "example-client.de")).first()
        if not t:
            print("Target not found")
            return
            
        print(f"Target: {t.domain} (ID: {t.id})")
        
        res = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "infrastructure_scanner"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        if not res:
            print("No Infrastructure Result found.")
            return
            
        print("Data Keys:", res.data.keys())
        print("IP:", res.data.get("ip"))
        print("GeoIP:", res.data.get("geoip"))
        
        if res.data.get("ip") and not res.data.get("geoip"):
            print("CONDITION MET: Should Repair")
        else:
            print("CONDITION FAIL: Skip")

if __name__ == "__main__":
    debug_one()
