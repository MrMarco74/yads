from sqlmodel import Session, select, create_engine
from yads.models import Target, ScanResult
import json

DATABASE_URL = "postgresql://yads:yads@localhost:5432/yads"
engine = create_engine(DATABASE_URL)

def inspect_details(target_id):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        if not target: return
        
        results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc())).all()
        
        dns = next((r for r in results if r.module_name == 'dns_scanner'), None)
        web = next((r for r in results if r.module_name == 'web_analyzer'), None)
        
        print(f"=== DNS RESULT ({dns.scanned_at if dns else 'None'}) ===")
        if dns:
            print(json.dumps(dns.data, indent=2))
            
        print(f"\n=== WEB RESULT ({web.scanned_at if web else 'None'}) ===")
        if web:
            print(json.dumps(web.data, indent=2))

if __name__ == "__main__":
    inspect_details(22534)
