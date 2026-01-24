import sys
import os
from sqlmodel import Session, select, text

# Add project root to path
sys.path.append("/home/mrmarco/Documents/gitlab/yads")

from yads.worker import calculate_security_trends
from yads.database import engine
from yads.models import Tenant, Target, ScanResult, SecurityTrend

def run_trigger():
    print("Triggering security trend calculation...")
    try:
        # Step 1: Check if we have any data to aggregate
        with Session(engine) as session:
            targets = session.exec(select(Target)).all()
            print(f"Found {len(targets)} targets.")
            
            # Show existing trends
            trends = session.exec(select(SecurityTrend)).all()
            print(f"Existing trend records: {len(trends)}")

        # Step 2: Run the task
        calculate_security_trends()
        
        # Step 3: Verify creation
        with Session(engine) as session:
            trends = session.exec(select(SecurityTrend)).all()
            print(f"Trend records after trigger: {len(trends)}")
            for t in trends:
                print(f" - Tenant ID {t.tenant_id}: Score {t.score} ({t.grade}) at {t.recorded_at}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_trigger()
