from sqlmodel import Session, select, create_engine
from yads.models import Target, ScanResult
from yads.config import settings

engine = create_engine(settings.DATABASE_URL)

def check_osint():
    with Session(engine) as session:
        # Strict match first
        target = session.exec(select(Target).where(Target.domain == "example-client.de")).first()
        if not target:
            print("Target 'example-client.de' not found. Searching for similar...")
            target = session.exec(select(Target).where(Target.domain.contains("example-client.de"))).first()
            
        if not target:
            print("No target found for example-client.de")
            return

        print(f"Target Found: {target.domain} (ID: {target.id})")
        print(f"Status: {target.scan_status}")
        
        # Check Scan Results
        results = session.exec(select(ScanResult).where(ScanResult.target_id == target.id)).all()
        
        web_res = next((r for r in results if r.module_name == "web_analyzer"), None)
        vis_res = next((r for r in results if r.module_name == "visual_osint"), None)
        
        if web_res:
             print("\n[Web Analyzer Result]")
             print(f"Scanned At: {web_res.scanned_at}")
             data = web_res.data
             print(f"Keys: {data.keys()}")
             print(f"Emails: {data.get('emails')}")
             print(f"Socials: {data.get('socials')}")
             print(f"Screenshot Path: {data.get('screenshot_path')}")
             print(f"Log Content Len: {len(web_res.log_content) if web_res.log_content else 0}")
        else:
             print("\n[Web Analyzer Result] NOT FOUND")

        if vis_res:
             print("\n[Visual OSINT Result]")
             data = vis_res.data
             print(f"Logos: {data.get('logos')}")
        else:
             print("\n[Visual OSINT Result] NOT FOUND")

if __name__ == "__main__":
    check_osint()
