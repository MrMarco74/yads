import os
import sys

# Setup Path
sys.path.append(os.getcwd())

from sqlmodel import Session, create_engine
from yads.models import Target
from yads.modules.dns_scanner import SubdomainScanner

DATABASE_URL = "postgresql://yads:yads@localhost:5432/yads"
engine = create_engine(DATABASE_URL)

def test_subdomain_scanner(target_id):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        if not target:
            print(f"Target {target_id} not found")
            return

        domain = target.domain
        print(f"Running SubdomainScanner for {domain} (ID: {target_id})...")
        
        scanner = SubdomainScanner(db_session=session, use_ct_logs=True)
        try:
            # We call run_scan directly to see exceptions
            data = scanner.run_scan(domain)
            print("Scan completed successfully.")
            
            subs = data.get("subdomains", [])
            print(f"Found {len(subs)} subdomains.")
            if subs:
                print("Sample:", subs[:3])
                
        except Exception as e:
            print(f"SCAN FAILED: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_subdomain_scanner(22534)
