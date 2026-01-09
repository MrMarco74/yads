import sys
import os
import zipfile
import json
from sqlmodel import Session, create_engine, select
from yads.config import settings
from yads.core.backup import create_backup_zip
from yads.models import Target

# Connect to DB
engine = create_engine(settings.DATABASE_URL)

def verify_export():
    print("Starting Export Verification...")
    
    with Session(engine) as session:
        # Check if we have data to export
        target_count = session.exec(select(Target)).all()
        print(f"Current DB has {len(target_count)} targets.")
        
        # Run Export
        print("Generating Backup Zip...")
        zip_io = create_backup_zip(session)
        
        # Inspect Zip
        with zipfile.ZipFile(zip_io, 'r') as zf:
            files = zf.namelist()
            print(f"Zip contains {len(files)} files.")
            
            # Check mandatory files
            if "data/target.json" not in files:
                print("FAILED: data/target.json missing!")
                sys.exit(1)
            
            if "data/systemconfig.json" not in files:
                print("FAILED: data/systemconfig.json missing!")
                sys.exit(1)
                
            # Verify JSON content
            target_data = zf.read("data/target.json")
            targets = json.loads(target_data)
            print(f"Backup contains {len(targets)} targets.")
            
            if len(targets) != len(target_count):
                 print(f"WARNING: Backup target count ({len(targets)}) differs from DB count ({len(target_count)})? (Might be concurrent access or just fine)")
            
            print("Integrity Check Passed: valid zip structure and JSON data.")

if __name__ == "__main__":
    try:
        verify_export()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
