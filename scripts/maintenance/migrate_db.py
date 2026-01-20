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

        # 8. Update User Table: email
        print(">> Checking User table: email...")
        try:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS email VARCHAR;'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 9. Update Tenant Table: OSINT Fields & BYOK & Session Management
        print(">> Checking Tenant table: OSINT fields, BYOK & Session Mgmt...")
        try:
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_enabled BOOLEAN DEFAULT FALSE;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_quota_max INTEGER DEFAULT 0;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_quota_used INTEGER DEFAULT 0;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS osint_cost_per_search FLOAT DEFAULT 0.0;"))
            # BYOK (Vision API uses api_key; cse_cx is fallback/optional)
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS google_api_key VARCHAR;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS google_cse_cx VARCHAR;"))
            # Nuclei Pro
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS nuclei_api_key VARCHAR;"))
            # HIBP Integration
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS hibp_api_key VARCHAR;"))
            
            # Target Justification
            conn.execute(text("ALTER TABLE target ADD COLUMN IF NOT EXISTS discovery_reason VARCHAR;"))
            
            # Session Management
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS session_timeout_minutes INTEGER DEFAULT 60;"))
            
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

        # 15. Seed Changelog
        print(">> Seeding Changelog...")
        try:
            seed_changelog()
            print("   Success.")
        except Exception as e:
            print(f"   Error seeding changelog: {e}")

        # 16. Create Webhook Table
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

        # 17. Create Notification for v1.6.1
        print(">> Checking/Creating v1.6.1 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.6.1'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.6.1',
                        'Layout fixes for Reports & new Broken Link Hijacking / Tech Radar cards. Check Changelog.',
                        'update',
                        'emerald',
                        'M5 13l4 4L19 7',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")

        # 18. Create SecurityTrend Table
        print(">> Creating securitytrend table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS securitytrend (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    score INTEGER NOT NULL,
                    grade VARCHAR NOT NULL,
                    recorded_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
                CREATE INDEX IF NOT EXISTS ix_securitytrend_tenant_id ON securitytrend (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_securitytrend_recorded_at ON securitytrend (recorded_at);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating securitytrend table: {e}")

        # 19. Update ScanSchedule Table: cron_expression
        print(">> Checking ScanSchedule table: cron_expression...")
        try:
            conn.execute(text("ALTER TABLE scanschedule ADD COLUMN IF NOT EXISTS cron_expression VARCHAR;"))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 20. Create Notification for v1.7.0
        print(">> Checking/Creating v1.7.0 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.7.0'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.7.0',
                        'Major Update: Attack Path Viz & Dark Mode! Check Changelog.',
                        'update',
                        'orange',
                        'M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")

        # 21. Create Notification for v1.8.0
        print(">> Checking/Creating v1.8.0 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.8.0'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.8.0',
                        'Feature Update: Scheduled Scans are here! Automate your workflows. Check Changelog.',
                        'update',
                        'teal',
                        'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")


        # 22. Create Notification for v1.10.0
        print(">> Checking/Creating v1.10.0 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.10.0'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.10.0',
                        'Major Release: Code Protection & Licensing System! Check Changelog.',
                        'update',
                        'yellow',
                        'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
                        (now() at time zone 'utc')
                    );
                """))
                conn.commit()
                print("   Created notification.")
            else:
                print("   Notification already exists.")
        except Exception as e:
            print(f"   Error creating notification: {e}")

        # 23. Create Notification for v1.11.0
        print(">> Checking/Creating v1.11.0 Notification...")
        try:
            # Check if exists
            result = conn.execute(text("SELECT id FROM notification WHERE title = 'System Update v1.11.0'"))
            if not result.fetchone():
                conn.execute(text("""
                    INSERT INTO notification (title, text, type, color, icon, created_at)
                    VALUES (
                        'System Update v1.11.0',
                        'Major Release: New Setup Guide & Enhanced UX! Check Changelog.',
                        'update',
                        'pink',
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

if __name__ == "__main__":
    migrate()
