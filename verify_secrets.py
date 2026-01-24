import sys
import os
from sqlmodel import Session, create_engine, select
import json
import time

# Add project root to path
sys.path.append("/home/mrmarco/Documents/gitlab/yads")

from yads.modules.web_analyzer import WebAnalyzer
from yads.database import engine

def test_scan():
    print("Initializing Scanner...")
    with Session(engine) as session:
        scanner = WebAnalyzer(db_session=session)
        # We use IP to bypass some DNS checks if any, or just localhost
        target = "localhost:8000/static/test_secret.html"
        print(f"Scanning {target}...")
        
        # Mock results dict as run_scan expects it to be populated 
        # Actually run_scan initializes it.
        # But we need to make sure Stage 1 succeeds.
        
        results = scanner.run_scan(target)
        
        print("\n--- SECRETS FOUND ---")
        if results.get("secrets"):
            for s in results["secrets"]:
                print(f"\n[!] Type: {s['type']}")
                print(f"    Source: {s['source']}")
                print(f"    Line: {s.get('line')}")
                print(f"    Value: {s['value']}")
                print(f"    Context Snippet:\n{'-'*40}\n{s.get('context')}\n{'-'*40}")
        else:
            print("No secrets found in the results.")
            if "headless_error" in results:
                print(f"Headless Error: {results['headless_error']}")
            if "error" in results:
                print(f"Error: {results['error']}")

if __name__ == "__main__":
    test_scan()
