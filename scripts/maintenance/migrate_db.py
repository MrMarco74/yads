import sys
import os

# Add project root to sys.path to allow importing 'yads'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

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
        
        # 1a. Update User Table: pending_mfa_secret (server-side MFA enrollment, v1.20+)
        print(">> Checking User table: pending_mfa_secret...")
        try:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS pending_mfa_secret VARCHAR;'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

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

        # 24. Create ComplianceTrend Table
        print(">> Creating compliancetrend table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS compliancetrend (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    framework VARCHAR NOT NULL,
                    score INTEGER NOT NULL,
                    grade VARCHAR NOT NULL,
                    passing_controls INTEGER NOT NULL DEFAULT 0,
                    failing_controls INTEGER NOT NULL DEFAULT 0,
                    recorded_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
                CREATE INDEX IF NOT EXISTS ix_compliancetrend_tenant_id ON compliancetrend (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_compliancetrend_framework ON compliancetrend (framework);
                CREATE INDEX IF NOT EXISTS ix_compliancetrend_recorded_at ON compliancetrend (recorded_at);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating compliancetrend table: {e}")

        # 25. Create RemediationTask Table
        print(">> Creating remediationtask table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS remediationtask (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    target_id INTEGER REFERENCES target(id),
                    framework VARCHAR NOT NULL,
                    control_id VARCHAR NOT NULL,
                    finding_description TEXT NOT NULL,
                    title VARCHAR NOT NULL,
                    description TEXT,
                    priority VARCHAR DEFAULT 'medium',
                    status VARCHAR DEFAULT 'open',
                    due_date TIMESTAMP WITHOUT TIME ZONE,
                    sla_breached BOOLEAN DEFAULT FALSE,
                    assignee VARCHAR,
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    resolved_at TIMESTAMP WITHOUT TIME ZONE
                );
                CREATE INDEX IF NOT EXISTS ix_remediationtask_tenant_id ON remediationtask (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_remediationtask_target_id ON remediationtask (target_id);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating remediationtask table: {e}")

        # 26. Create ComplianceTargetStatus Table
        print(">> Creating compliancetargetstatus table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS compliancetargetstatus (
                    id SERIAL PRIMARY KEY,
                    target_id INTEGER NOT NULL REFERENCES target(id),
                    framework VARCHAR NOT NULL,
                    score INTEGER NOT NULL,
                    grade VARCHAR NOT NULL,
                    passing_controls INTEGER NOT NULL DEFAULT 0,
                    failing_controls INTEGER NOT NULL DEFAULT 0,
                    findings JSONB DEFAULT '[]'::jsonb,
                    last_assessed_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
                CREATE INDEX IF NOT EXISTS ix_compliancetargetstatus_target_id ON compliancetargetstatus (target_id);
                CREATE INDEX IF NOT EXISTS ix_compliancetargetstatus_framework ON compliancetargetstatus (framework);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating compliancetargetstatus table: {e}")

        # 27. Create WorkerNode Table (Distributed Workers)
        print(">> Creating workernode table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS workernode (
                    id SERIAL PRIMARY KEY,
                    node_id VARCHAR NOT NULL UNIQUE,
                    hostname VARCHAR NOT NULL,
                    ip_address VARCHAR NOT NULL,
                    is_primary BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    registered_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    last_heartbeat TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    max_concurrent_tasks INTEGER DEFAULT 4,
                    max_network_mbps FLOAT DEFAULT 100.0,
                    current_load FLOAT DEFAULT 0.0,
                    current_tasks INTEGER DEFAULT 0,
                    auth_token_hash VARCHAR NOT NULL,
                    status VARCHAR DEFAULT 'pending',
                    capabilities JSONB DEFAULT '[]'::jsonb,
                    version VARCHAR,
                    cpu_count INTEGER,
                    memory_mb INTEGER
                );
                CREATE INDEX IF NOT EXISTS ix_workernode_node_id ON workernode (node_id);
                CREATE INDEX IF NOT EXISTS ix_workernode_status ON workernode (status);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating workernode table: {e}")

        # 28. Create WorkerTask Table (Distributed Workers)
        print(">> Creating workertask table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS workertask (
                    id SERIAL PRIMARY KEY,
                    task_id VARCHAR NOT NULL UNIQUE,
                    worker_node_id INTEGER REFERENCES workernode(id),
                    target_id INTEGER NOT NULL REFERENCES target(id),
                    tenant_id INTEGER REFERENCES tenant(id),
                    queued_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    started_at TIMESTAMP WITHOUT TIME ZONE,
                    completed_at TIMESTAMP WITHOUT TIME ZONE,
                    status VARCHAR DEFAULT 'queued',
                    scan_types JSONB DEFAULT '[]'::jsonb,
                    error_message TEXT,
                    progress_percent INTEGER DEFAULT 0,
                    current_module VARCHAR
                );
                CREATE INDEX IF NOT EXISTS ix_workertask_task_id ON workertask (task_id);
                CREATE INDEX IF NOT EXISTS ix_workertask_worker_node_id ON workertask (worker_node_id);
                CREATE INDEX IF NOT EXISTS ix_workertask_target_id ON workertask (target_id);
                CREATE INDEX IF NOT EXISTS ix_workertask_tenant_id ON workertask (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_workertask_status ON workertask (status);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating workertask table: {e}")

        # 29. Create ResourceQuota Table (Distributed Workers)
        print(">> Creating resourcequota table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS resourcequota (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER REFERENCES tenant(id),
                    max_concurrent_scans INTEGER DEFAULT 10,
                    max_daily_scans INTEGER DEFAULT 1000,
                    max_network_throughput_mbps FLOAT DEFAULT 50.0,
                    current_concurrent_scans INTEGER DEFAULT 0,
                    scans_today INTEGER DEFAULT 0,
                    last_reset_date TIMESTAMP WITHOUT TIME ZONE,
                    priority INTEGER DEFAULT 5
                );
                CREATE INDEX IF NOT EXISTS ix_resourcequota_tenant_id ON resourcequota (tenant_id);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating resourcequota table: {e}")

        # 30. Update Tenant Table: New OSINT API Keys (v1.15.0)
        print(">> Checking Tenant table: New OSINT API Keys (hunter, github, twitter)...")
        try:
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS hunter_api_key VARCHAR;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS github_token VARCHAR;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS twitter_bearer_token VARCHAR;"))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 31. Create SecurityAuditLog Table (MITRE ATT&CK aligned security logging)
        print(">> Creating securityauditlog table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS securityauditlog (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR NOT NULL,
                    timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    username VARCHAR,
                    user_id INTEGER,
                    source_ip VARCHAR,
                    user_agent VARCHAR,
                    tenant_id INTEGER REFERENCES tenant(id),
                    target_user VARCHAR,
                    target_user_id INTEGER,
                    success BOOLEAN DEFAULT TRUE,
                    details JSONB DEFAULT '{}'::jsonb,
                    mitre_tactic_id VARCHAR,
                    mitre_technique_id VARCHAR
                );
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_event_type ON securityauditlog (event_type);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_timestamp ON securityauditlog (timestamp);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_username ON securityauditlog (username);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_user_id ON securityauditlog (user_id);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_source_ip ON securityauditlog (source_ip);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_tenant_id ON securityauditlog (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_target_user ON securityauditlog (target_user);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_success ON securityauditlog (success);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_mitre_tactic_id ON securityauditlog (mitre_tactic_id);
                CREATE INDEX IF NOT EXISTS ix_securityauditlog_mitre_technique_id ON securityauditlog (mitre_technique_id);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating securityauditlog table: {e}")

        # 32. Create AIAnalysisResult Table (v1.19.0)
        print(">> Creating aianalysisresult table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS aianalysisresult (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER REFERENCES tenant(id),
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    risk_rating VARCHAR NOT NULL,
                    risk_score INTEGER NOT NULL,
                    executive_summary TEXT NOT NULL,
                    key_findings TEXT DEFAULT '[]',
                    recommendations TEXT DEFAULT '[]',
                    llm_provider VARCHAR,
                    llm_model VARCHAR
                );
                CREATE INDEX IF NOT EXISTS ix_aianalysisresult_tenant_id ON aianalysisresult (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_aianalysisresult_created_at ON aianalysisresult (created_at);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating aianalysisresult table: {e}")

        # LLM / AI Report Analysis columns (v1.19.0)
        print(">> Checking Tenant table: LLM/AI settings...")
        try:
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS llm_provider VARCHAR;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS llm_api_url VARCHAR;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS llm_api_key VARCHAR;"))
            conn.execute(text("ALTER TABLE tenant ADD COLUMN IF NOT EXISTS llm_model VARCHAR;"))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        # 33. Target scan_priority + TenantModuleConfig + InstalledModule (v1.20.0)
        print(">> Adding target.scan_priority column (v1.20.0)...")
        try:
            conn.execute(text("ALTER TABLE target ADD COLUMN IF NOT EXISTS scan_priority INTEGER DEFAULT 5;"))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Skipped/Error: {e}")

        print(">> Creating tenantmoduleconfig table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS tenantmoduleconfig (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    module_name VARCHAR NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    updated_by INTEGER REFERENCES "user"(id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_tenantmoduleconfig_tenant_module
                    ON tenantmoduleconfig (tenant_id, module_name);
                CREATE INDEX IF NOT EXISTS ix_tenantmoduleconfig_tenant_id ON tenantmoduleconfig (tenant_id);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating tenantmoduleconfig table: {e}")

        print(">> Creating installedmodule table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS installedmodule (
                    id SERIAL PRIMARY KEY,
                    module_name VARCHAR NOT NULL UNIQUE,
                    label VARCHAR NOT NULL,
                    label_de VARCHAR DEFAULT '',
                    category VARCHAR DEFAULT 'active',
                    version VARCHAR DEFAULT '1.0.0',
                    author VARCHAR DEFAULT '',
                    description VARCHAR DEFAULT '',
                    module_path VARCHAR NOT NULL,
                    requires_http BOOLEAN DEFAULT FALSE,
                    requires_https BOOLEAN DEFAULT FALSE,
                    default_on BOOLEAN DEFAULT FALSE,
                    finding_module BOOLEAN DEFAULT TRUE,
                    extractor VARCHAR DEFAULT 'generic',
                    installed_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    installed_by INTEGER REFERENCES "user"(id),
                    is_active BOOLEAN DEFAULT TRUE,
                    setup_log TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_installedmodule_module_name ON installedmodule (module_name);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating installedmodule table: {e}")

        # 34. ScanProfile + IntegrationConfig tables (v1.20.0)
        print(">> Creating scanprofile table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scanprofile (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER REFERENCES tenant(id),
                    created_by INTEGER REFERENCES "user"(id),
                    name VARCHAR NOT NULL,
                    description VARCHAR,
                    scan_types JSONB DEFAULT '[]'::jsonb,
                    is_default BOOLEAN DEFAULT FALSE,
                    is_public BOOLEAN DEFAULT FALSE,
                    icon VARCHAR,
                    color VARCHAR DEFAULT 'blue',
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
                CREATE INDEX IF NOT EXISTS ix_scanprofile_tenant_id ON scanprofile (tenant_id);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating scanprofile table: {e}")

        print(">> Creating integrationconfig table (if not exists)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS integrationconfig (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL REFERENCES tenant(id),
                    integration_type VARCHAR NOT NULL,
                    config JSONB DEFAULT '{}'::jsonb,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc'),
                    created_by INTEGER REFERENCES "user"(id)
                );
                CREATE INDEX IF NOT EXISTS ix_integrationconfig_tenant_id ON integrationconfig (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_integrationconfig_type ON integrationconfig (integration_type);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating integrationconfig table: {e}")

        print(">> Creating tenantscanconfig table (per-tenant automation)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS tenantscanconfig (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL UNIQUE REFERENCES tenant(id),
                    auto_scan_enabled BOOLEAN DEFAULT FALSE,
                    frequency VARCHAR DEFAULT 'weekly',
                    cron_expression VARCHAR,
                    scan_types JSONB DEFAULT '["dns_scanner", "ssl_scanner", "web_analyzer"]'::jsonb,
                    max_targets_per_run INTEGER DEFAULT 10,
                    max_concurrent_scans INTEGER DEFAULT 3,
                    scan_window_start VARCHAR,
                    scan_window_end VARCHAR,
                    last_auto_run_at TIMESTAMP WITHOUT TIME ZONE,
                    next_auto_run_at TIMESTAMP WITHOUT TIME ZONE,
                    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_tenantscanconfig_tenant
                    ON tenantscanconfig (tenant_id);
                CREATE INDEX IF NOT EXISTS ix_tenantscanconfig_next_run
                    ON tenantscanconfig (next_auto_run_at);
            """))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error creating tenantscanconfig table: {e}")

        # User OIDC fields
        print(">> Adding User OIDC fields (auth_mode, oidc_sub, oidc_tenant)...")
        try:
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS auth_mode VARCHAR DEFAULT \'local\''))
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS oidc_sub VARCHAR'))
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS oidc_tenant VARCHAR'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_user_oidc_sub ON "user" (oidc_sub)'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        # SecurityAuditLog Hash-Chain fields
        print(">> Adding SecurityAuditLog hash-chain fields (DORA EU)...")
        try:
            conn.execute(text('ALTER TABLE securityauditlog ADD COLUMN IF NOT EXISTS prev_entry_hash VARCHAR'))
            conn.execute(text('ALTER TABLE securityauditlog ADD COLUMN IF NOT EXISTS entry_hash VARCHAR'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        # SystemAlertLog table (Health Watcher)
        print(">> Creating systemalertlog table (Health Watcher)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS systemalertlog (
                    id          SERIAL PRIMARY KEY,
                    check_name  VARCHAR NOT NULL,
                    severity    VARCHAR NOT NULL,
                    message     TEXT NOT NULL,
                    detail      TEXT,
                    fired_at    TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
                    resolved_at TIMESTAMP WITHOUT TIME ZONE,
                    notified    BOOLEAN NOT NULL DEFAULT false
                )
            """))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_systemalertlog_check_name ON systemalertlog (check_name)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_systemalertlog_fired_at   ON systemalertlog (fired_at)'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        # Discovery Session tables (v1.43.0)
        print(">> Creating discoverysession table (v1.43.0)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS discoverysession (
                    id                  SERIAL PRIMARY KEY,
                    tenant_id           INTEGER REFERENCES tenant(id),
                    created_by          INTEGER REFERENCES "user"(id),
                    name                VARCHAR NOT NULL,
                    seed_domains        JSONB DEFAULT '[]',
                    max_depth           INTEGER DEFAULT 3,
                    relevance_threshold FLOAT DEFAULT 0.5,
                    max_targets         INTEGER DEFAULT 500,
                    include_typosquats  BOOLEAN DEFAULT false,
                    allowed_tld_filter  JSONB DEFAULT '[]',
                    status              VARCHAR DEFAULT 'pending',
                    started_at          TIMESTAMP WITHOUT TIME ZONE,
                    finished_at         TIMESTAMP WITHOUT TIME ZONE,
                    total_discovered    INTEGER DEFAULT 0,
                    total_accepted      INTEGER DEFAULT 0,
                    total_rejected      INTEGER DEFAULT 0,
                    current_depth       INTEGER DEFAULT 0,
                    created_at          TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                )
            """))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_discoverysession_tenant_id ON discoverysession (tenant_id)'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        print(">> Creating discoverycandidate table (v1.43.0)...")
        try:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS discoverycandidate (
                    id                  SERIAL PRIMARY KEY,
                    session_id          INTEGER NOT NULL REFERENCES discoverysession(id),
                    source_target_id    INTEGER REFERENCES target(id),
                    domain              VARCHAR NOT NULL,
                    source_scanner      VARCHAR NOT NULL,
                    depth               INTEGER DEFAULT 0,
                    relevance_score     FLOAT DEFAULT 0.0,
                    matching_signals    JSONB DEFAULT '[]',
                    status              VARCHAR DEFAULT 'pending',
                    rejection_reason    VARCHAR,
                    created_at          TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() at time zone 'utc')
                )
            """))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_discoverycandidate_session_id ON discoverycandidate (session_id)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_discoverycandidate_domain ON discoverycandidate (domain)'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        print(">> Adding note to discoverydomainblocklist (v1.48.0)...")
        try:
            conn.execute(text('ALTER TABLE discoverydomainblocklist ADD COLUMN IF NOT EXISTS note VARCHAR'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        print(">> Adding web_scraping to discoverysession (v1.48.1)...")
        try:
            conn.execute(text('ALTER TABLE discoverysession ADD COLUMN IF NOT EXISTS web_scraping BOOLEAN DEFAULT FALSE'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        print(">> Adding passive_hunting to discoverysession (v1.48.0)...")
        try:
            conn.execute(text('ALTER TABLE discoverysession ADD COLUMN IF NOT EXISTS passive_hunting BOOLEAN DEFAULT FALSE'))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        print(">> Adding discovery fields to target table (v1.43.0)...")
        try:
            conn.execute(text('ALTER TABLE target ADD COLUMN IF NOT EXISTS discovery_session_id INTEGER REFERENCES discoverysession(id)'))
            conn.execute(text('ALTER TABLE target ADD COLUMN IF NOT EXISTS parent_target_id INTEGER'))
            conn.execute(text('ALTER TABLE target ADD COLUMN IF NOT EXISTS discovery_depth INTEGER DEFAULT 0'))
            conn.execute(text('ALTER TABLE target ADD COLUMN IF NOT EXISTS relevance_score FLOAT'))
            conn.execute(text("ALTER TABLE target ADD COLUMN IF NOT EXISTS discovery_signals JSONB DEFAULT '[]'"))
            conn.commit()
            print("   Success.")
        except Exception as e:
            print(f"   Error: {e}")

        print("\nMigration Complete!")


if __name__ == "__main__":
    migrate()
