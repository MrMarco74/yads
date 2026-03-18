"""
Database migration script to add archiving fields to Target table.
Run this to update existing database schema.
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

def run_migration():
    """Add archiving fields to target table"""
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise SystemExit("ERROR: DATABASE_URL environment variable is not set.")
    engine = create_engine(db_url)
    
    with Session(engine) as session:
        print("Adding archiving fields to target table...")
        
        # Add columns
        session.execute(text("""
            ALTER TABLE target 
            ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP,
            ADD COLUMN IF NOT EXISTS archived_reason VARCHAR(255);
        """))
        
        # Create index for performance
        session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_target_archived ON target(is_archived);
        """))
        
        session.commit()
        print("✓ Migration completed successfully")

if __name__ == "__main__":
    run_migration()
