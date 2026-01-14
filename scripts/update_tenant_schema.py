import sys
import os
sys.path.append(os.getcwd())

from sqlmodel import Session, text
from yads.database import engine

def add_columns():
    with Session(engine) as session:
        print("Checking Tenant table schema...")
        
        # Check if columns exist (Postgres specific)
        # We'll just try to add them and catch error, or check information_schema
        # Simple approach: ALTER TABLE IF NOT EXISTS... but Postgres doesn't support IF NOT EXISTS for ADD COLUMN easily in one line without blocks in older versions.
        # Let's use clean separate statements.
        
        commands = [
            "ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_enabled BOOLEAN DEFAULT FALSE",
            "ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_quota_max INTEGER DEFAULT 0",
            "ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_quota_used INTEGER DEFAULT 0",
            "ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_cost_per_search FLOAT DEFAULT 0.0"
        ]
        
        for cmd in commands:
            try:
                print(f"Executing: {cmd}")
                session.exec(text(cmd))
                session.commit()
            except Exception as e:
                print(f"Error (might be harmless if column exists): {e}")
                session.rollback()

        print("Schema update complete.")

if __name__ == "__main__":
    add_columns()
