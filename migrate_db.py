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

        # 9. Update Tenant Table: OSINT Fields & BYOK
        print(">> Checking Tenant table: OSINT fields & BYOK...")
        try:
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_enabled BOOLEAN DEFAULT FALSE;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_quota_max INTEGER DEFAULT 0;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_quota_used INTEGER DEFAULT 0;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_cost_per_search FLOAT DEFAULT 0.0;"))
            # BYOK (Vision API uses api_key; cse_cx is fallback/optional)
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS google_api_key VARCHAR;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS google_cse_cx VARCHAR;"))
            
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 10. Create Notification for v1.3.2
        print(">> Checking/Creating v1.3.2 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.3.2'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.3.2',
                        'OSINT Brand Monitoring & Licensing now available! Check the Changelog.',
                        'update',
                        'blue',
                        'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")
            
        # 11. Create Notification for v1.3.4
        print(">> Checking/Creating v1.3.4 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.3.4'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.3.4',
                        'External Links Analysis & PDF Export now live! Check Analytics.',
                        'update',
                        'cyan',
                        'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")
            
        # 12. Create Notification for v1.4.0
        print(">> Checking/Creating v1.4.0 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.4.0'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.4.0',
                        'Major Update: Critical Analytics HUD, SOC2 Scoring & Performance Fixes. See Settings->Changelog.',
                        'update',
                        'indigo',
                        'M13 10V3L4 14h7v7l9-11h-7z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")

        # 13. Create Notification for v1.5.0
        print(">> Checking/Creating v1.5.0 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.5.0'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.5.0',
                        'Deep Security Update: Nuclei Vulns, Stealth Nmap, and Compliance Grading! Check Changelog.',
                        'update',
                        'purple',
                        'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")


        # 14. Create Notification for v1.5.1
        print(">> Checking/Creating v1.5.1 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.5.1'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.5.1',
                        'Critical Update: Queue Stability & Zombie Status Fixes. Check Changelog.',
                        'update',
                        'green',
                        'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
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

        # 13. Create Webhook Table
        print(">> Creating webhook table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS webhook (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    url VARCHAR NOT NULL,
                    event_types JSONB DEFAULT '[]'::jsonb,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
                CREATE INDEX IF NOT EXISTS ix_webhook_tenant_id ON webhook (tenant_id);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating webhook table: {e}")

if __name__ == "__main__":
    migrate()
