from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Request, Form, UploadFile, File, Body, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse, Response
from fastapi.encoders import jsonable_encoder
from sqlmodel import Session, select, func, create_engine, text
from contextlib import asynccontextmanager
import os
import aiofiles
import io
import zipfile
import json
from datetime import datetime
from yads.modules.visual_osint import VisualOSINT
from yads.modules.report_generator import generate_report
from yads.modules.visual_osint import VisualOSINT
from yads.modules.report_generator import generate_report
from yads.modules.brand_monitor import BrandMonitor
from yads.core.seeding import seed_changelog, seed_default_report_templates
from yads.modules.compliance import ComplianceScorer

from yads.config import settings
from yads.models import Target, ScanResult, ModuleState, SystemConfig, Notification, SecurityTrend, HTTPTraffic
from yads.core.logging_config import configure_logging
from yads.core.backup import create_backup_zip, restore_backup_from_zip
from yads.core.scoring import calculate_target_score, get_grade, get_grade_color
from yads.api.routers import auth, analytics, users, tenants, schedules, api_keys, dashboard, targets, graphs, exports, system, tags
from yads.auth.deps import get_current_user_html, RoleChecker, get_current_active_user, PlatformAdminChecker, LoginRequiredException
from yads.models import User
from yads.api.utils.update_checker import UpdateService

# -- Logging Setup --
logger = configure_logging("yads-api")

# -- DB Setup --
from yads.database import engine, get_session, create_db_and_tables, redis_client
import tldextract

@asynccontextmanager
async def lifespan(app: FastAPI):
    import time
    from sqlalchemy.exc import OperationalError
    
    max_retries = 10
    for i in range(max_retries):
        try:
            create_db_and_tables()
            
            # --- Schema Migration & Multi-Tenancy Init ---
            with Session(engine) as session:
                # Check if tenant table exists and columns are present (SQLModel create_all creates tables but doesn't alter)
                # We can rely on basic SQL checks for SQLite/Postgres compatibility or inspection
                # Simplest for this setup: Try to query tenant, if fail, we might be in weird state.
                # But create_all should have created the table "tenant" if it didn't exist.
                
                # Check if User table has tenant_id column
                try:
                    session.exec(text("SELECT tenant_id FROM \"user\" LIMIT 1"))
                except Exception:
                    logger.info("Migrating schema: Adding tenant_id to user table")
                    session.rollback()
                    session.exec(text("ALTER TABLE \"user\" ADD COLUMN tenant_id INTEGER REFERENCES tenant(id)"))
                except Exception:
                    logger.info("Migrating schema: Adding tenant_id to user table")
                    session.rollback()
                    session.exec(text("ALTER TABLE \"user\" ADD COLUMN tenant_id INTEGER REFERENCES tenant(id)"))
                    session.commit()
                    
                # Check for last_login column
                try:
                    session.exec(text("SELECT last_login FROM \"user\" LIMIT 1"))
                except Exception:
                    logger.info("Migrating schema: Adding last_login to user table")
                    session.rollback()
                    session.exec(text("ALTER TABLE \"user\" ADD COLUMN last_login TIMESTAMP WITHOUT TIME ZONE"))
                    session.commit()

                # Check for email column (v1.3.0)
                try:
                    session.exec(text("SELECT email FROM \"user\" LIMIT 1"))
                except Exception:
                    logger.info("Migrating schema: Adding email to user table")
                    session.rollback()
                    session.exec(text("ALTER TABLE \"user\" ADD COLUMN email VARCHAR"))
                    session.commit()
                    
                # Check if Target table has tenant_id column
                # Check if target table has tenant_id column
                try:
                    session.exec(text("SELECT tenant_id FROM target LIMIT 1"))
                except Exception:
                    logger.info("Migrating schema: Adding tenant_id to target table")
                    session.rollback()
                    session.exec(text("ALTER TABLE target ADD COLUMN tenant_id INTEGER REFERENCES tenant(id)"))
                    session.commit()

                # Migration for OSINT API Keys (v1.16.0)
                # Use inspector for robust checking
                from sqlalchemy import inspect
                inspector = inspect(engine)
                
                # Check Tenant Columns
                if inspector.has_table("tenant"):
                    columns = [c["name"] for c in inspector.get_columns("tenant")]
                    
                    if "shodan_api_key" not in columns:
                        logger.info("Migrating schema: Adding shodan_api_key to tenant table")
                        session.exec(text("ALTER TABLE tenant ADD COLUMN shodan_api_key VARCHAR"))
                        
                    if "censys_api_key" not in columns:
                         logger.info("Migrating schema: Adding censys_api_key to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN censys_api_key VARCHAR"))
                         
                    if "virustotal_api_key" not in columns:
                         logger.info("Migrating schema: Adding virustotal_api_key to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN virustotal_api_key VARCHAR"))

                    # v1.15.0 Keys
                    if "hunter_api_key" not in columns:
                         logger.info("Migrating schema: Adding hunter_api_key to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN hunter_api_key VARCHAR"))
                    if "github_token" not in columns:
                         logger.info("Migrating schema: Adding github_token to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN github_token VARCHAR"))
                    if "twitter_bearer_token" not in columns:
                         logger.info("Migrating schema: Adding twitter_bearer_token to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN twitter_bearer_token VARCHAR"))
                    
                    # Session & Branding
                    if "session_timeout_minutes" not in columns:
                         logger.info("Migrating schema: Adding session_timeout_minutes to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN session_timeout_minutes INTEGER DEFAULT 60"))

                    if "report_logo_url" not in columns:
                         logger.info("Migrating schema: Adding report_logo_url to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN report_logo_url VARCHAR"))

                    if "report_company_name" not in columns:
                         logger.info("Migrating schema: Adding report_company_name to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN report_company_name VARCHAR"))

                    if "report_primary_color" not in columns:
                         logger.info("Migrating schema: Adding report_primary_color to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN report_primary_color VARCHAR DEFAULT '#3b82f6'"))

                    if "report_secondary_color" not in columns:
                         logger.info("Migrating schema: Adding report_secondary_color to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN report_secondary_color VARCHAR DEFAULT '#64748b'"))
                         
                    if "report_header_text" not in columns:
                         logger.info("Migrating schema: Adding report_header_text to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN report_header_text VARCHAR"))

                    if "report_footer_text" not in columns:
                         logger.info("Migrating schema: Adding report_footer_text to tenant table")
                         session.exec(text("ALTER TABLE tenant ADD COLUMN report_footer_text VARCHAR"))

                    session.commit()

                # User language preference (i18n v1.20.0)
                user_columns = [c["name"] for c in inspector.get_columns("user")]
                if "language" not in user_columns:
                    logger.info("Migrating schema: Adding language to user table")
                    session.exec(text("ALTER TABLE \"user\" ADD COLUMN language VARCHAR DEFAULT 'en'"))
                    session.commit()

                # Check WorkerNode Columns
                if inspector.has_table("workernode"):
                    columns = [c["name"] for c in inspector.get_columns("workernode")]
                    
                    if "node_id" not in columns:
                        logger.info("Migrating schema: Adding node_id to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN node_id VARCHAR"))
                        
                    if "status" not in columns:
                        logger.info("Migrating schema: Adding status to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN status VARCHAR DEFAULT 'pending'"))
                        
                    if "capabilities" not in columns:
                        logger.info("Migrating schema: Adding capabilities to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN capabilities JSONB DEFAULT '[]'"))

                    if "assigned_tenant_ids" not in columns:
                        logger.info("Migrating schema: Adding assigned_tenant_ids to workernode table")
                        # JSONB column
                        session.exec(text("ALTER TABLE workernode ADD COLUMN assigned_tenant_ids JSONB DEFAULT '[]'"))

                    if "max_daily_scans" not in columns:
                        logger.info("Migrating schema: Adding max_daily_scans to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN max_daily_scans INTEGER"))

                    if "description" not in columns:
                        logger.info("Migrating schema: Adding description to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN description VARCHAR"))

                    if "version" not in columns:
                        logger.info("Migrating schema: Adding version to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN version VARCHAR"))

                    if "cpu_count" not in columns:
                        logger.info("Migrating schema: Adding cpu_count to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN cpu_count INTEGER"))

                    if "memory_mb" not in columns:
                        logger.info("Migrating schema: Adding memory_mb to workernode table")
                        session.exec(text("ALTER TABLE workernode ADD COLUMN memory_mb INTEGER"))

                    session.commit()

                # Ensure Default Tenant "a customer" -> REMOVED PER USER REQ
                # from yads.models import Tenant
                # default_tenant = session.exec(select(Tenant).where(Tenant.name == "a customer")).first()
                # if not default_tenant:
                #     default_tenant = Tenant(name="a customer")
                #     session.add(default_tenant)
                #     session.commit()
                #     session.refresh(default_tenant)
                #     logger.info("Created default tenant: a customer")
                
                # Assign Orphaned Users/Targets?
                # Without default tenant, we can't assign them.
                # Just leave them NULL (orphaned).
                # session.exec(text(f"UPDATE target SET tenant_id = {default_tenant.id} WHERE tenant_id IS NULL"))
                pass
                
            logger.info("Database connected, tables created, and schema migrated.")
            
            # Enforce Paused State on Boot (Configurable)
            with Session(engine) as session:
                from yads.models import SystemConfig
                config = session.get(SystemConfig, "QUEUE_ACTIVE")
                if not config:
                    # If key doesn't exist, default to ACTIVE (unless pause on boot is requested)
                    default_state = "false" if settings.QUEUE_PAUSE_ON_BOOT else "true"
                    config = SystemConfig(key="QUEUE_ACTIVE", value=default_state)
                    session.add(config)
                    session.commit()
                else:
                    # If key exists, check if we should force pause
                    if settings.QUEUE_PAUSE_ON_BOOT:
                         if config.value.lower() == "true":
                            config.value = "false"
                            session.add(config)
                            session.commit()
                            logger.info("Auto-start disabled: Queue execution paused by configuration.")
            
            # Broadcast Pause Command IF actually paused
            # We check the DB state again to be sure
            with Session(engine) as session:
                from yads.models import SystemConfig
                config = session.get(SystemConfig, "QUEUE_ACTIVE")
                if config and config.value.lower() == "false":
                    try:
                        from yads.worker import celery_app
                        celery_app.control.cancel_consumer('celery', reply=True)
                        logger.info("Queue consumer cancelled (Paused).")
                    except Exception as e:
                        logger.warning(f"Failed to pause worker on boot: {e}")
            
            
            # Create Default Admin if None Exist
            with Session(engine) as session:
                from yads.models import User
                from yads.auth.security import get_password_hash
                existing_users = session.exec(select(User)).first()
                if not existing_users:
                    logger.warning("No users found. Creating default 'admin' user.")
                    default_admin = User(
                        username="admin", 
                        password_hash=get_password_hash("admin"),
                        role="admin"
                    )
                    session.add(default_admin)
                    session.commit()

                    session.commit()
            
            # --- Seed Changelog ---
            seed_changelog()

            # --- Seed Default Report Templates ---
            seed_default_report_templates()

            # --- Load License Key to Settings ---
            with Session(engine) as session:
                from yads.models import SystemConfig
                lic = session.get(SystemConfig, "license_key")
                if lic and lic.value:
                    settings.LICENSE_KEY = lic.value
                    logger.info("License key loaded from database into runtime settings.")
                else:
                    logger.warning("No license key found in database.")

            # --- Register Default Worker ---
            try:
                from yads.core.worker_manager import worker_manager
                node_id = worker_manager.register_primary_worker()
                if node_id:
                    logger.info(f"Default worker registered: {node_id}")
            except Exception as e:
                logger.warning(f"Could not register default worker: {e}")

            break
        except Exception as e:
            if i == max_retries - 1:
                logger.error(f"Could not connect to database after retries. Error: {e}")
                raise
            logger.warning(f"Database/Startup not ready... retrying ({i+1}/{max_retries}). Error: {e}")
            time.sleep(2)
            
    yield

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# -- Static & Templates --
app.mount("/static", StaticFiles(directory="yads/api/static"), name="static")
from yads.api.templating import templates

# Inject Globals
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

# Custom Filters
def timestamp_to_time(value):
    if not value:
        return "-"
    try:
        dt = datetime.fromtimestamp(float(value))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(value)

templates.env.filters["timestamp_to_time"] = timestamp_to_time

# -- Template Globals --
def get_all_tenants():
    # Helper to fetch all tenants for Platform Admin dropdown
    # Must use separate session as this runs in Jinja context
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

# -- CORS Setup --
# Kept for dev compatibility, though strictly not needed for server-side rendering
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- TLS Enforcement Middleware --
from yads.core.tls_config import is_https_required

@app.middleware("http")
async def tls_enforcement_middleware(request: Request, call_next):
    """
    Reject non-HTTPS requests if HTTPS_ONLY is enabled.
    """
    # Skip for local health checks/metrics if needed, 
    # but generally, we want everything secure.
    if not settings.DEBUG:
         # Check if HTTPS is required via DB/Env
         with Session(engine) as session:
             if is_https_required(session):
                 if request.url.scheme != "https":
                     # Allow for specific headers if behind a proxy (X-Forwarded-Proto)
                     forwarded_proto = request.headers.get("X-Forwarded-Proto")
                     if forwarded_proto != "https":
                         return JSONResponse(
                             {"detail": "SSL/TLS Required. Please use HTTPS."}, 
                             status_code=403
                         )
    
    return await call_next(request)

# -- Language Middleware (i18n) --
from yads.core.i18n import set_lang, normalize_lang

@app.middleware("http")
async def language_middleware(request: Request, call_next):
    """Set request-scoped language from yads_lang cookie."""
    lang = request.cookies.get("yads_lang", "en")
    set_lang(normalize_lang(lang))
    return await call_next(request)

# -- Prometheus Metrics Middleware --
import time as _time
from yads.core.metrics import get_metrics as _get_metrics

@app.middleware("http")
async def prometheus_metrics_middleware(request: Request, call_next):
    """
    Middleware to record HTTP request metrics for Prometheus.
    Records request count and duration for each endpoint.
    """
    prom_metrics = _get_metrics()

    # Skip metrics collection if disabled
    if not prom_metrics.enabled:
        return await call_next(request)

    # Skip metrics endpoint itself to avoid recursion
    if request.url.path == "/metrics":
        return await call_next(request)

    start_time = _time.perf_counter()
    response = await call_next(request)
    duration = _time.perf_counter() - start_time

    # Normalize path to avoid cardinality explosion
    # Replace numeric IDs with placeholders
    path_template = request.url.path
    for route in app.routes:
        if hasattr(route, 'path_regex') and route.path_regex:
            match = route.path_regex.match(request.url.path)
            if match:
                path_template = route.path
                break

    # Record metrics
    prom_metrics.record_http_request(
        method=request.method,
        path_template=path_template,
        status_code=response.status_code,
        duration_seconds=duration
    )

    return response

# -- Celery --
from celery import Celery
celery_app = Celery("yads_worker", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

# -- Routers --
# -- Routers --

# -- Routers --
@app.middleware("http")
async def setup_middleware(request: Request, call_next):
    # Skip if setup is complete
    if settings.SETUP_COMPLETE:
        return await call_next(request)
        
    path = request.url.path
    # Allow static resources and setup endpoints
    if path.startswith("/static") or path.startswith("/setup") or path == "/favicon.ico":
         return await call_next(request)
         
    # Redirect to setup wizard
    return RedirectResponse(url="/setup")

# -- Routers --
from yads.api.routers import analytics, auth, users, changelog, help, profile, queue, notifications, osint, tenant_settings, compliance, reports, ports, email_security, secrets, tech_drift, cert_timeline, asr, cloud_assets, search, setup, archived, workers, mobile, storage, updates, metrics, report_builder, v1, pqc, security_findings, changes

# Include Setup Router FIRST to ensure it handles its requests before others if overlap (though unique prefix avoids this)
app.include_router(setup.router)

app.include_router(analytics.router)
app.include_router(analytics.ui_router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(tenants.router)
app.include_router(api_keys.router)
app.include_router(changelog.router)
app.include_router(help.router)
app.include_router(profile.router)
app.include_router(schedules.router)
app.include_router(queue.router)
app.include_router(notifications.router)
app.include_router(osint.router)
app.include_router(tenant_settings.router)
app.include_router(compliance.router)
app.include_router(archived.router)
app.include_router(reports.router)
app.include_router(report_builder.router)
app.include_router(ports.router)
app.include_router(email_security.router)
app.include_router(security_findings.router)
app.include_router(changes.router)
app.include_router(secrets.router)
app.include_router(tech_drift.router)
app.include_router(cert_timeline.router)
app.include_router(asr.router)
app.include_router(cloud_assets.router)
app.include_router(pqc.router)
app.include_router(search.router)
app.include_router(workers.router)
app.include_router(workers.ui_router)
app.include_router(mobile.router)
app.include_router(storage.router)
app.include_router(updates.router)
app.include_router(metrics.router)
app.include_router(v1.router)
app.include_router(dashboard.router)
app.include_router(graphs.router)
app.include_router(targets.router)
app.include_router(exports.router)
app.include_router(system.router)
app.include_router(tags.router)

@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if settings.SETUP_COMPLETE:
        return RedirectResponse(url="/")
    return templates.TemplateResponse("setup.html", {"request": request})


@app.exception_handler(LoginRequiredException)
async def login_required_handler(request: Request, exc: LoginRequiredException):
    return RedirectResponse(url="/login")

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Check if request expects HTML (simple check)
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse("error.html", {
            "request": request, 
            "status_code": exc.status_code,
            "detail": exc.detail,
            "user": None # Context might not have user if auth failed, base.html handles this
        }, status_code=exc.status_code)
    
    # Fallback to default JSON behavior
    return JSONResponse(
        {"detail": exc.detail}, 
        status_code=exc.status_code
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    import traceback
    tb = traceback.format_exc()
    logger.error(f"Unhandled exception at {request.url}: {exc}\n{tb}")
    
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse("error.html", {
            "request": request, 
            "status_code": 500,
            "detail": f"Internal Server Error: {str(exc)}",
            "user": None
        }, status_code=500)
    
    return JSONResponse(
        {"detail": "Internal Server Error", "error": str(exc)}, 
        status_code=500
    )


# -- UI Routes --

# -- Bulk Actions (Must be defined before generic {target_id} routes) --






# -- Table View & Bulk Actions --



# -- Backup & Restore Routes --

# Deprecated simple restore (keep checking for legacy calls or remove?)
# Removing original direct restore endpoint to force use of new flow
# Or keeping it but redirecting?
# Let's replace the old endpoint logic to be safe or just remove it.
# The previous POST /api/backup/restore is REPLACED by the logic above or we just re-route.







# -- Graph View --





from yads.core.compliance import calculate_security_grade, generate_compliance_report


# -- Settings Routes --




# --- Visualizations ---

@app.get("/api/visualizations/redirects")


# --- Analytics ---

@app.get("/analytics", response_class=HTMLResponse)
async def view_analytics(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    # Fetch targets for the dropdown (Tenant Scoped)
    query = select(Target.domain, Target.id).order_by(Target.domain)
    
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
        
    targets = session.exec(query).all()
    
    return templates.TemplateResponse("analytics.html", {"request": request, "targets": targets, "user": user})

# --- Tagging API ---

@app.get("/api/stats/security-risks")
async def get_security_risks(session: Session = Depends(get_session)):
    """
    Aggregates security risks for visualizations:
    - SSL Expiry Timeline
    - Reputation Monitor (Blacklists)
    - Open Buckets
    """
    from datetime import datetime
    
    # helper for filtering latest result of a type
    # (In a real app, this might be a complex window function query, but we loop for simplicity on small datasets)
    
    # Fetch all targets
    targets = session.exec(select(Target)).all()
    
    ssl_timeline = []
    reputation_issues = []
    open_buckets = []
    open_buckets = []
    secrets_leaks = []
    vulnerabilities = []
    
    for t in targets:
        # Get latest relevant scans
        # SSL
        ssl_res = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "ssl_scanner"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        # Infra
        infra_res = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "infrastructure_scanner"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        # Process SSL
        if ssl_res and ssl_res.data:
            not_after = ssl_res.data.get("notAfter")
            
            if not_after:
                try:
                    # Parse date string "May 25 12:00:00 2025 GMT"
                    # Python's datetime.strptime can handle this if we match format
                    # Example format from stdlib: 'Oct  5 23:59:59 2025 GMT'
                    try:
                        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    except:
                        # Sometimes day is single digit with 2 spaces "Oct  5"
                        # Try removing extra spaces or multiple formats
                        # Quickfix: just try generic dateutil if available or robust parse
                        dt = datetime.strptime(not_after.replace("  ", " "), "%b %d %H:%M:%S %Y %Z")
                        
                    days_left = (dt - datetime.utcnow()).days
                    
                    status = "ok"
                    if days_left < 7: status = "critical"
                    elif days_left < 30: status = "warning"
                    
                    ssl_timeline.append({
                        "target": t.domain,
                        "target_id": t.id,
                        "days_left": days_left,
                        "expiry_date": dt.strftime("%Y-%m-%d"),
                        "status": status
                    })
                except Exception as e:
                    pass

        # Process Infra (Reputation + Buckets)
        if infra_res and infra_res.data:
            # Buckets
            buckets = infra_res.data.get("buckets", [])
            for bucket in buckets:
                if bucket.get("status") == "Public":
                    open_buckets.append({
                        "target": t.domain,
                        "target_id": t.id,
                        "url": bucket.get("url"),
                        "code": bucket.get("code")
                    })
            
            # Reputation
            rep = infra_res.data.get("reputation", [])
            if rep:
                ip = infra_res.data.get("ip", "Unknown")
                reputation_issues.append({
                    "target": t.domain,
                    "target_id": t.id,
                    "issues": rep
                })

        # Process Secrets (Web Analyzer)
        web_res = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "web_analyzer"
        ).order_by(ScanResult.scanned_at.desc())).first()


        
        if web_res and web_res.data and web_res.data.get("secrets"):
            found = web_res.data.get("secrets")
            if found:
                 secrets_leaks.append({
                     "target": t.domain,
                     "target_id": t.id,
                     "count": len(found),
                     "secrets": found # Contains type, value
                 })

        # Process Vulnerabilities (Web Analyzer CVEs)
        if web_res and web_res.data and web_res.data.get("cves"):
             for cve in web_res.data.get("cves"):
                 vulnerabilities.append({
                     "target": t.domain,
                     "target_id": t.id,
                     "id": cve.get("id"),
                     "severity": cve.get("severity", "UNKNOWN"),
                     "description": cve.get("description", ""),
                     "product": cve.get("product", "")
                 })

    # Sort SSL by urgency
    ssl_timeline.sort(key=lambda x: x["days_left"])
    
    return {
        "ssl_timeline": ssl_timeline,
        "reputation_issues": reputation_issues,
        "open_buckets": open_buckets,
        "secrets_leaks": secrets_leaks,
        "vulnerabilities": vulnerabilities
    }








