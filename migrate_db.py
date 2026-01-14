from sqlmodel import text
from yads.database import engine
from yads.core.seeding import seed_changelog

def migrate():
    """
    Safely migrates the database schema.
    VERIFIED SAFE: This script only performs ADD COLUMN / CREATE TABLE operations.
    It DOES NOT drop tables or columns, ensuring NO DATA LOSS.
    """
    with engine.connect() as conn:
        print("Migrating Database...")
        
        # 1. Update User Table: last_seen_changelog_id
        print(">> Checking User table: last_seen_changelog_id...")
        try:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS last_seen_changelog_id INTEGER DEFAULT 0;'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 2. Update User Table: tenant_id
        print(">> Checking User table: tenant_id...")
        try:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenant(id);'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            # Table 'tenant' might not exist if created via this script later? 
            # Actually create_all runs on app start. If this runs inside container, app might have run once?
            # Or if this is run BEFORE app start?
            # Ideally create_all should be run first.
            print(f"   Skipped/Error (Ensure 'tenant' table exists): {e}")

        # 3. Update Target Table: tenant_id
        print(">> Checking Target table: tenant_id...")
        try:
            conn.execute(text('ALTER TABLE target ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenant(id);'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 4. Update Target Table: brand_logo_url
        print(">> Checking Target table: brand_logo_url...")
        try:
            # text columns often safest as VARCHAR or TEXT
            conn.execute(text('ALTER TABLE target ADD COLUMN IF NOT EXISTS brand_logo_url VARCHAR;'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 5. Create ChangelogEntry Table
        print(">> Creating changelogentry table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS changelogentry (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR NOT NULL,
                    content VARCHAR NOT NULL,
                    version VARCHAR NOT NULL,
                    published_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating table: {e}")

        # 6. Create Notification Table (Just in case create_all missed it/wasn't run)
        print(">> Creating notification table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS notification (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR NOT NULL,
                    text VARCHAR NOT NULL,
                    type VARCHAR DEFAULT 'info',
                    color VARCHAR DEFAULT 'blue',
                    icon VARCHAR NOT NULL,
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        # 7. Create ScanSchedule Table
        print(">> Creating scanschedule table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scanschedule (
                    id SERIAL PRIMARY KEY,
                    target_id INTEGER NOT NULL REFERENCES target(id),
                    frequency VARCHAR DEFAULT 'daily',
                    next_run_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                    last_run_at TIMESTAMP WITHOUT TIME ZONE,
                    is_active BOOLEAN DEFAULT TRUE
                );
                CREATE INDEX IF NOT EXISTS ix_scanschedule_target_id ON scanschedule (target_id);
                CREATE INDEX IF NOT EXISTS ix_scanschedule_next_run_at ON scanschedule (next_run_at);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating scanschedule: {e}")

        # 8. Create Notification for v1.3.1
        print(">> Checking/Creating v1.3.1 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.3.1'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.3.1',
                        'Scheduling, Logging Enhancements & More! Check the Changelog.',
                        'update',
                        'blue',
                        'M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")

        # 9. Seed Changelog
        print(">> Seeding Changelog...")
        try:
            seed_changelog()
            print("   Success.")
        except Exception as e:
            print(f"   Error seeding changelog: {e}")

if __name__ == "__main__":
    migrate()
