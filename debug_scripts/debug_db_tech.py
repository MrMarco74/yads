from sqlmodel import Session, select, create_engine, text
from yads.models import ScanResult, Target
from yads.config import settings

engine = create_engine(settings.DATABASE_URL)

def check_db():
    print("Checking WebAnalyzer Results...")
    with Session(engine) as session:
        # Check total count
        count = session.exec(select(ScanResult).where(ScanResult.module_name=="web_analyzer")).all()
        print(f"Total WebAnalyzer Results: {len(count)}")
        
        # Check for ANY non-empty tech_stack
        valid = session.exec(text("SELECT count(*) FROM scanresult WHERE module_name='web_analyzer' AND jsonb_array_length(data->'tech_stack') > 0")).one()
        print(f"Results with Tech Stack > 0: {valid[0]}")
        
        # Sample one target to see history
        t = session.exec(select(Target).where(Target.domain == "example-client.de")).first()
        if t:
            print(f"\nHistory for {t.domain}:")
            res = session.exec(select(ScanResult).where(
                ScanResult.target_id == t.id, 
                ScanResult.module_name == "web_analyzer"
            ).order_by(ScanResult.scanned_at.desc())).all()
            
            for r in res:
                ts = r.data.get("tech_stack", [])
                print(f" - {r.scanned_at}: TechStack={len(ts)} Items: {ts}")

if __name__ == "__main__":
    check_db()
