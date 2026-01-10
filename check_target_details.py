from sqlmodel import Session, select, create_engine
from yads.models import Target, ScanResult
# Direct connection string since we know it now
DATABASE_URL = "postgresql://yads:yads@localhost:5432/yads"

engine = create_engine(DATABASE_URL)

def check_target(target_id):
    try:
        with Session(engine) as session:
            target = session.get(Target, target_id)
            if not target:
                print(f"Target {target_id} NOT FOUND.")
                return

            print(f"Target: {target.domain} (ID: {target_id})")
            
            results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id)).all()
            print(f"Found {len(results)} scan results.")
            for r in results:
                print(f" - {r.module_name}: {r.scanned_at} (Data len: {len(str(r.data)) if r.data else 0})")
                if r.module_name == 'web_analyzer':
                     print(f"   Date keys: {r.data.keys() if r.data else 'None'}")
                     if r.data:
                         print(f"   Title: {r.data.get('title')}")
                         print(f"   Status: {r.data.get('status_code')}")
    except Exception as e:
        print(f"Error accessing DB: {e}")

if __name__ == "__main__":
    check_target(22534)
