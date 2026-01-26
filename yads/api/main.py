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
from yads.api.routers import auth, analytics, users, tenants, schedules
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

                # Check WorkerNode Columns
                if inspector.has_table("workernode"):
                    columns = [c["name"] for c in inspector.get_columns("workernode")]
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
from yads.api.routers import analytics, auth, users, changelog, help, profile, queue, notifications, osint, tenant_settings, compliance, reports, ports, email_security, secrets, tech_drift, cert_timeline, asr, cloud_assets, search, setup, archived, workers, mobile, storage, updates, metrics, report_builder

# Include Setup Router FIRST to ensure it handles its requests before others if overlap (though unique prefix avoids this)
app.include_router(setup.router)

app.include_router(analytics.router)
app.include_router(analytics.ui_router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(tenants.router)
app.include_router(changelog.router)
app.include_router(help.router)
app.include_router(profile.router)
app.include_router(schedules.router)
app.include_router(queue.router)
app.include_router(notifications.router)
app.include_router(osint.router)
app.include_router(tenant_settings.router)
app.include_router(compliance.router)
app.include_router(reports.router)
app.include_router(report_builder.router)
app.include_router(ports.router)
app.include_router(email_security.router)
app.include_router(secrets.router)
app.include_router(tech_drift.router)
app.include_router(cert_timeline.router)
app.include_router(asr.router)
app.include_router(cloud_assets.router)
app.include_router(search.router)
app.include_router(archived.router)
app.include_router(workers.router)
app.include_router(workers.ui_router)
app.include_router(mobile.router)
app.include_router(storage.router)
app.include_router(updates.router)
app.include_router(metrics.router)

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

@app.post("/targets/bulk/scan", response_class=HTMLResponse)
async def bulk_scan_targets(
    request: Request,
    scan_types: List[str] = Form(default=[]), 
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    form = await request.form()
    target_ids = form.getlist("target_ids") 
    
    if not target_ids:
         return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)
         
    scan_types_selected = form.getlist("scan_types")
    
    valid_types = ["dns_cleanup", "subdomain_scanner", "dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint", "ssl_scanner", "wayback_scanner", "crawler", "cve_scanner", "content_discovery", "tld_scanner", "port_scanner", "nmap_scanner", "nuclei_scanner", "brand_intelligence", "email_intelligence", "social_media_scanner", "deception_detector", "full_scan"]
    final_types = [t for t in scan_types_selected if t in valid_types]
    
    if "full_scan" in final_types:
        # User explicitly requested EVERYTHING
        final_types = [t for t in valid_types if t != "full_scan"]
    
    if not final_types:
         return RedirectResponse(url="/targets/table?msg=Error:+No+valid+scan+types+selected", status_code=303)

    import logging
    logger = logging.getLogger("yads-api")
    logger.info(f"DEBUG: Bulk Scan Request. Target Count: {len(target_ids)}. Selected Types: {scan_types_selected}. Final: {final_types}")

    count = 0
    
    # Check Queue Status
    from yads.models import SystemConfig
    queue_config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = False
    if queue_config and queue_config.value.lower() == "true":
        queue_active = True

    for tid_str in target_ids:
        try:
            tid = int(tid_str)
            target = session.exec(select(Target).where(Target.id == tid, Target.tenant_id == user.tenant_id)).first()
            if target:
                # --- License Check ---
                from yads.models import SystemConfig
                from yads.core.license import license_manager
                lc = session.get(SystemConfig, "license_key")
                if not lc or not lc.value or not license_manager.verify(lc.value):
                     # Skip queueing, maybe just continue or error?
                     # For bulk, continuing is safer but we should probably stop.
                     # But let's just skip this one (effectively stopping all if loop continues)
                     # Actually, return error immediately
                     return RedirectResponse(url="/targets/table?msg=Error:+License+Required+for+Scanning", status_code=303)
                # ---------------------

                target.scan_status = "queued"
                session.add(target)
                
                # Always dispatch to Redis (even if paused, it waits there).
                # This ensures arguments (scan_types) are preserved.
                # Bulk scan is also a MANUAL action, BUT we now RESPECT the queue pause.
                # If Queue is Paused, valid consumer won't pick it up OR worker will abort if it checks DB.
                # We set ignore_queue_pause=False (default).
                celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, final_types, user.tenant_id])
                count += 1
        except Exception as e:
            logger.error(f"Failed to queue target {tid_str}: {e}")
            continue
            
    session.commit()
            
    return RedirectResponse(url=f"/targets/table?msg=Queued+{count}+scans", status_code=303)

@app.post("/targets/import", response_class=HTMLResponse)
async def bulk_import_targets(
    request: Request,
    file_upload: UploadFile = File(None),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    form = await request.form()
    raw_text = form.get("targets_raw", "")
    discovery_reason = form.get("discovery_reason")
    next_url = form.get("next", "/targets/table")
    verify_dns = form.get("verify_dns") == "true"
    
    # Process File Upload if present
    if file_upload and file_upload.filename:
        try:
            content = await file_upload.read()
            # Try decoding as utf-8, fallback to latin-1
            try:
                decoded = content.decode("utf-8")
            except:
                decoded = content.decode("latin-1")
            
            raw_text += "\n" + decoded
        except Exception as e:
            logger.error(f"Failed to read uploaded file: {e}")
    
    if not raw_text.strip():
        return RedirectResponse(url=f"{next_url}?msg=No+data+provided", status_code=303)
        
    # Split lines and process
    # Use set to remove duplicates within the import batch immediately
    lines = list(set([l.strip().lower() for l in raw_text.splitlines() if l.strip()]))
    
    imported_count = 0
    duplicate_count = 0
    skipped_dns_count = 0
    
    import dns.resolver  # Import here execution context
    
    for domain in lines:
        # Basic cleanup - remove http/https if present and trailing slashes
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        domain = domain.strip().lower()

        if not domain: continue
        
        # DNS Verification if enabled
        if verify_dns:
            try:
                # Try resolving A record
                dns.resolver.resolve(domain, 'A')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
                try:
                    # Fallback to AAAA
                     dns.resolver.resolve(domain, 'AAAA')
                except:
                     skipped_dns_count += 1
                     continue
            except Exception:
                # Other DNS errors -> skip
                skipped_dns_count += 1
                continue
        
        # Check duplicate (Tenant Scoped)
        existing = session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == user.tenant_id)).first()
        if existing:
            duplicate_count += 1
            continue
            
        # --- License Check ---
        # 1. Get current count (Tenant Scoped or Global? License is usually Global per instance)
        # But if we license per customer name, and customer name == tenant name? 
        # For simplicity in this Single-Instance model: Global Count.
        total_active_targets = session.exec(select(func.count()).select_from(Target)).one()
        
        # 2. Verify License
        from yads.models import SystemConfig
        from yads.core.license import license_manager
        import time
        
        license_conf = session.get(SystemConfig, "license_key")
        limit = 0
        valid_license = False
        
        if license_conf and license_conf.value:
            data = license_manager.verify(license_conf.value)
            if data:
                limit = data.get("max_targets", 0)
                valid_license = True
        
        # 3. Enforce
        # If no license or invalid -> Limit is 0? Or default free tier?
        # Let's say Default Free Tier = 5 targets if no license.
        if not valid_license:
            limit = 5 
        
        if total_active_targets >= limit:
            # Check if this specific domain is what pushes us over?
            # We are creating one by one in loop.
            # If we reached limit, stop importing.
            skipped_dns_count += 0 # metric hack
            # LOG/Notify?
            msg = f"License Limit Reached ({limit}). Upgrade license to add more targets."
            return RedirectResponse(url=f"{next_url}?error={msg}", status_code=303)

        # Create
        # Create
        new_target = Target(domain=domain, tenant_id=user.tenant_id, discovery_reason=discovery_reason)
        session.add(new_target)
        imported_count += 1
        
    session.commit()
    
    msg = f"Imported+{imported_count}+targets"
    if duplicate_count > 0:
        msg += f"+({duplicate_count}+skipped+duplicates)"
    if skipped_dns_count > 0:
        msg += f"+({skipped_dns_count}+skipped+offline)"
        
    return RedirectResponse(url=f"{next_url}?msg={msg}", status_code=303)

@app.post("/targets/bulk/delete", response_class=HTMLResponse)
async def bulk_delete_targets(
    target_ids: List[int] = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """
    Deletes multiple targets and their associated data.
    """
    if not target_ids:
        # Should probably return an error or just redirect
        return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)

    # Convert to set for safety
    ids_to_delete = set(target_ids)
    
    # 1. Delete Dependencies (ScanResults, ModuleStates)
    # Using raw SQL for efficiency with list of IDs
    ids_str = ",".join(map(str, ids_to_delete))
    
    # Check if empty (shouldn't be due to check above)
    if ids_str:
        # 1a. Revoke Active/Queued Tasks for these Targets
        # This is tricky without task IDs stored in DB.
        # We have to inspect active/reserved tasks and check args.
        i = celery_app.control.inspect()
        active = i.active() if i else None
        reserved = i.reserved() if i else None
        
        tasks_to_revoke = []
        
        def check_tasks(task_list):
            for worker_name, tasks in task_list.items():
                for task in tasks:
                    # task args is usually [target_id, domain, ...]
                    args = task.get("args", [])
                    if args and isinstance(args, list) and len(args) > 0:
                        try:
                            tid = int(args[0])
                            if tid in ids_to_delete:
                                tasks_to_revoke.append(task.get("id"))
                        except:
                            pass
                            
        if active: check_tasks(active)
        if reserved: check_tasks(reserved)
        
        for tid_revoke in tasks_to_revoke:
            celery_app.control.revoke(tid_revoke, terminate=True)
            
        # 1b. Delete Dependencies
        session.exec(text(f"DELETE FROM scanresult WHERE target_id IN ({ids_str})"))
        session.exec(text(f"DELETE FROM modulestate WHERE target_id IN ({ids_str})"))
        
        # 2. Delete Targets (Verify ownership implicitly by filtering ID list first? Better to rely on prior checks or simple query)
        # But here we used raw delete for speed. 
        # Safety check: Ensure all IDs belong to user.tenant_id
        # For bulk delete, it's safer to fetch IDs that match tenant first.
        
        owned_targets = session.exec(select(Target.id).where(Target.id.in_(ids_to_delete), Target.tenant_id == user.tenant_id)).all()
        # Only delete what we own
        safe_ids = set(owned_targets)
        
        if len(safe_ids) != len(ids_to_delete):
            # Some IDs were not owned. Log warning?
            pass
            
        if safe_ids:
            safe_ids_str = ",".join(map(str, safe_ids))
            
            # Prune dependencies using safe list
            session.exec(text(f"DELETE FROM scanresult WHERE target_id IN ({safe_ids_str})"))
            session.exec(text(f"DELETE FROM modulestate WHERE target_id IN ({safe_ids_str})"))
            session.exec(text(f"DELETE FROM target WHERE id IN ({safe_ids_str})"))
        
        session.commit()
    
    count = len(ids_to_delete)
    revoke_count = len(tasks_to_revoke) if 'tasks_to_revoke' in locals() else 0
    msg = f"Deleted+{count}+targets"
    if revoke_count > 0:
        msg += f"+(Stopped+{revoke_count}+scans)"
        
    return RedirectResponse(url=f"/targets/table?msg={msg}", status_code=303)

@app.post("/targets/bulk/archive", response_class=HTMLResponse)
async def bulk_archive_targets(
    target_ids: List[int] = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """
    Archives multiple targets.
    """
    if not target_ids:
        return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)

    ids_to_archive = set(target_ids)
    
    # Verify ownership
    owned_targets = session.exec(
        select(Target).where(
            Target.id.in_(ids_to_archive), 
            Target.tenant_id == user.tenant_id,
            Target.is_archived == False
        )
    ).all()
    
    count = 0
    from datetime import datetime
    for target in owned_targets:
        target.is_archived = True
        target.archived_at = datetime.utcnow()
        target.archived_reason = "manual"
        session.add(target)
        count += 1
        
    session.commit()
    
    msg = f"Archived+{count}+targets"
    return RedirectResponse(url=f"/targets/table?msg={msg}", status_code=303)

@app.post("/targets/{target_id}/scan")
async def trigger_scan(target_id: int, request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))):
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Parse form data for scan types
    form = await request.form()
    scan_types = form.getlist("scan_types") # Returns list of values for keys named "scan_types"
    
    # Validation/Default
    valid_types = ["dns_cleanup", "subdomain_scanner", "dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint", "ssl_scanner", "wayback_scanner", "crawler", "cve_scanner", "content_discovery", "tld_scanner", "port_scanner", "nmap_scanner", "nuclei_scanner", "brand_intelligence", "email_intelligence", "social_media_scanner", "deception_detector", "full_scan"]
    selected_types = [t for t in scan_types if t in valid_types]
    
    if "full_scan" in selected_types:
        # User explicitly requested EVERYTHING
        # Expand 'full_scan' to all real scanner types
        # Remove 'full_scan' pseudo-type to avoid worker conflict
        real_types = [t for t in valid_types if t != "full_scan"]
        selected_types = real_types
    
    # --- License Check ---
    from yads.models import SystemConfig
    from yads.core.license import license_manager
    lc = session.get(SystemConfig, "license_key")
    if not lc or not lc.value or not license_manager.verify(lc.value):
         msg = "Error: Scanning requires a valid license."
         return RedirectResponse(url=f"/targets/{target_id}?error={msg}", status_code=303)
    # ---------------------

    if not selected_types:
        # DO NOT FALLBACK TO ALL.
        # Fail if nothing valid selected.
        msg = "Error: No valid scan types selected."
        return RedirectResponse(url=f"/targets/{target_id}?error={msg}", status_code=303)

    # Trigger Celery Task (and update status)
    target.scan_status = "queued"
    session.add(target)
    session.commit()
    
    # Always dispatch to Redis (even if paused, it waits there).
    # This ensures argments are preserved.
    # We pass ignore_queue_pause=False so it respects the "Stop All" state.
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, selected_types, user.tenant_id])
    
    return RedirectResponse(url=f"/targets/{target_id}", status_code=303)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    # Check for YADS Updates (Automatic)
    update_info = None
    try:
        update_info = UpdateService.check_for_updates()
    except Exception as e:
        logger.warning(f"Dashboard update check failed: {e}")

    # Calculate stats (Tenant Scoped)
    total_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)).one()
    
    # Total scans is bit harder to filter if scanresult doesn't have tenant_id. 
    # We have to join.
    total_scans_count = session.exec(select(func.count(ScanResult.id)).join(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Pagination defaults for initial load
    page = 1
    limit = 9
    offset = 0
    
    # Fetch Paginated Targets (Tenant Scoped)
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
    # Fetch Active Scans (Tenant Scoped)
    active_scans = session.exec(select(Target).where(Target.scan_status == "running", Target.tenant_id == user.tenant_id)).all()
    
    # Calculate Dead DNS Count
    dns_dead_count = session.exec(
        select(func.count()).select_from(Target).where(
            Target.tenant_id == user.tenant_id, 
            Target.is_archived == True, 
            Target.archived_reason == "dns_dead"
        )
    ).one()
    
    total_pages = (total_targets + limit - 1) // limit
    
    # Calculate Last Scan for each target per module
    last_scans = {}
    
    # Fetch states only for visible targets (optimization)
    target_ids = [t.id for t in targets]
    if target_ids:
        all_states = session.exec(select(ModuleState).where(ModuleState.target_id.in_(target_ids))).all()
        for state in all_states:
            if state.target_id not in last_scans:
                last_scans[state.target_id] = {}
            last_scans[state.target_id][state.module_name] = state.last_scanned_at

    # Queue Stats
    # Queue Stats (From DB for accuracy & tenant isolation)
    queue_len = session.exec(select(func.count()).select_from(Target).where(
        Target.tenant_id == user.tenant_id, 
        Target.scan_status == "queued"
    )).one()
    
    from yads.models import SystemConfig
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = config.value.lower() == "true" if config else False

    # Compliance Calculation
    # Fetch LATEST results for ALL visible targets (for this tenant)
    # This might be heavy if thousands of targets, but acceptable for MVP optimization.
    # We reuse 'targets' (paginated) for display, but for compliance we need ALL targets' data?
    # Strictly speaking, compliance score should reflect the WHOLE infrastructure.
    # So we need a query for all targets + their latest results.
    
    # Optimization: We only fetch what ComplianceScorer needs.
    # Using raw SQL to get latest row per (target, module) efficiently.
    compliance_stats = {"score": 0, "grade": "F", "passing_controls": 0, "failures": []}
    
    try:
        if total_targets > 0:
            query_compliance = f"""
                SELECT DISTINCT ON (s.target_id, s.module_name) 
                    s.target_id, s.module_name, s.data 
                FROM scanresult s
                JOIN target t ON s.target_id = t.id
                WHERE s.module_name IN ('ssl_scanner', 'web_analyzer', 'cve_scanner', 'infrastructure_scanner', 'port_scanner')
                AND t.tenant_id {f"= {user.tenant_id}" if user.tenant_id else "IS NULL"}
                ORDER BY s.target_id, s.module_name, s.scanned_at DESC
            """
            # Fetch all targets for the map (not paginated)
            all_targets_query = select(Target).where(Target.tenant_id == user.tenant_id)
            all_targets = session.exec(all_targets_query).all()
            
            comp_results = session.exec(text(query_compliance)).all()
            
            # Convert raw rows to pseudo-ScanResult objects or dicts for the scorer
            # Scorer expects List[ScanResult] with .target_id, .module_name, .data
            class MockResult:
                def __init__(self, tid, mod, d):
                    self.target_id = tid
                    self.module_name = mod
                    self.data = d
            
            mock_results = [MockResult(r[0], r[1], r[2]) for r in comp_results]
            
            scorer = ComplianceScorer()
            compliance_stats = scorer.calculate_score(all_targets, mock_results)

            # --- Critical Attention Calculation ---
            # Reuse mock_results to find critical issues
            critical_map = {}
            target_lookup = {t.id: t for t in all_targets}
            
            for res in mock_results:
                reason = None
                risk = "High"
                
                # Check SSL Expiry
                if res.module_name == "ssl_scanner":
                    if res.data.get("expired"):
                        reason = "SSL Certificate Expired"
                        risk = "Critical"
                    elif res.data.get("grade") in ["F", "T", "M"]:
                        reason = "Weak SSL Configuration"
                        risk = "High"
                        
                # Check Critical CVEs
                elif res.module_name in ["cve_scanner", "web_analyzer"]:
                    cves = res.data.get("cves", [])
                    max_cvss = 0
                    for cve in cves:
                        try:
                            score = float(cve.get("cvss", 0))
                            if score > max_cvss: max_cvss = score
                        except: pass
                    
                    if max_cvss >= 9.0:
                        reason = f"Critical Vulnerability (CVSS {max_cvss})"
                        risk = "Critical"
                    elif max_cvss >= 7.0:
                        reason = f"High Vulnerability (CVSS {max_cvss})"
                        risk = "High"
                
                # Check Public Buckets
                elif res.module_name == "infrastructure_scanner":
                    buckets = res.data.get("buckets", [])
                    if any(b.get("status") == "Public" for b in buckets):
                        reason = "Public Cloud Storage Bucket"
                        risk = "Critical"

                if reason and res.target_id in target_lookup:
                    # Priority: Critical > High
                    # If target already in map, only update if new risk is higher
                    if res.target_id in critical_map:
                        current = critical_map[res.target_id]
                        if current["risk_score"] == "High" and risk == "Critical":
                            critical_map[res.target_id].update({"risk_score": risk, "issue": reason})
                    else:
                        t = target_lookup[res.target_id]
                        critical_map[res.target_id] = {
                            "id": t.id,
                            "domain": t.domain,
                            "risk_score": risk,
                            "issue": reason,
                            "action": "Investigate"
                        }
            
            critical_targets = list(critical_map.values())
            # Sort: Critical first
            critical_targets.sort(key=lambda x: x["risk_score"], reverse=True) # C > H alphabetically? No. Critical < High alphabetically.
            # Custom sort
            critical_targets.sort(key=lambda x: 0 if x["risk_score"] == "Critical" else 1)
            
    except Exception as e:
        logger.error(f"Compliance/Critical Calc Failed: {e}")
        # specific fallback?
        pass

    # Fetch Recent Activity (ScanResults)
    recent_activity = session.exec(
        select(ScanResult).join(Target)
        .where(Target.tenant_id == user.tenant_id)
        .order_by(ScanResult.scanned_at.desc())
        .limit(5)
    ).all()

    # Ensure critical_targets is defined if logic skipped/failed
    if 'critical_targets' not in locals():
        critical_targets = []

    # Calculate Average Security Score for Tenant
    # Fetch ALL targets and their latest results to calculate accurate average?
    # For MVP performance, we might want to cache this or just calculate on the fly for visible targets?
    # Calculating for ALL is better for accuracy.
    # Reuse `comp_results` if available (it has latest results for key modules)
    avg_security_score = 0
    if total_targets > 0 and 'comp_results' in locals():
        # comp_results is list of tuples (tid, mod, data)
        # We need to group by target_id
        target_results_map = {} # {tid: {mod: result_obj}}
        for tid, mod, data in comp_results:
             if tid not in target_results_map:
                 target_results_map[tid] = {}
             # Mock result object for scorer (it expects .data)
             class MockRes:
                 def __init__(self, d): self.data = d
             target_results_map[tid][mod] = MockRes(data)
        
        total_score = 0
        scored_count = 0
        for t in all_targets:
             t_res = target_results_map.get(t.id, {})
             # Use safe version of scorer that accepts dict of objects with .data
             s, g, f = calculate_target_score(t, t_res)
             total_score += s
             scored_count += 1
        
        if scored_count > 0:
            avg_security_score = int(total_score / scored_count)
    
    avg_grade = get_grade(avg_security_score)

    # Snapshot Trend (Once per day per tenant)
    try:
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        existing_trend = session.exec(select(SecurityTrend).where(
            SecurityTrend.tenant_id == user.tenant_id, 
            SecurityTrend.recorded_at >= today_start
        )).first()
        
        if not existing_trend and total_targets > 0:
            new_trend = SecurityTrend(
                tenant_id=user.tenant_id,
                score=avg_security_score,
                grade=avg_grade
            )
            session.add(new_trend)
            session.commit()
    except Exception as e:
        # Don't fail dashboard load on trend error
        print(f"Error snapshotting trend: {e}")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "critical_targets": critical_targets, # Added
        "targets": targets,
        "active_scans": active_scans,
        "last_scans": last_scans,
        "recent_activity": recent_activity, # Added
        "stats": {
            "active_targets": total_targets,
            "services_monitored": "-",  # Placeholder
            "total_scans": total_scans_count,
            "queue_length": queue_len,
            "queue_active": queue_active,
            "compliance": compliance_stats,
            "security_score": avg_security_score,
            "security_grade": avg_grade,
            "dns_dead_count": dns_dead_count
        },
        "pagination": {
        },
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "total_count": total_targets,
            "start_item": 1,
            "end_item": min(limit, total_targets)
        },
        "user": user, # Pass user to context
        "update_info": update_info
    })


@app.get("/dashboard/stats", response_class=HTMLResponse)
async def dashboard_stats(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """HTMX endpoint for auto-updating stats"""
    total_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)).one()
    total_scans_count = session.exec(select(func.count(ScanResult.id)).join(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Queue Stats
    # Queue Stats (From DB for accuracy & tenant isolation)
    queue_len = session.exec(select(func.count()).select_from(Target).where(
        Target.tenant_id == user.tenant_id, 
        Target.scan_status == "queued"
    )).one()
    
    from yads.models import SystemConfig
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = config.value.lower() == "true" if config else False

    # Calculate Average Security Score for Tenant
    avg_security_score = 0
    avg_grade = "F"
    
    try:
        if total_targets > 0:
            # Fetch latest results for security-relevant modules
            query_security = f"""
                SELECT DISTINCT ON (s.target_id, s.module_name) 
                    s.target_id, s.module_name, s.data 
                FROM scanresult s
                JOIN target t ON s.target_id = t.id
                WHERE s.module_name IN ('ssl_scanner', 'web_analyzer', 'cve_scanner', 'infrastructure_scanner', 'port_scanner')
                AND t.tenant_id {f"= {user.tenant_id}" if user.tenant_id else "IS NULL"}
                ORDER BY s.target_id, s.module_name, s.scanned_at DESC
            """
            
            # Fetch all targets for scoring
            all_targets_query = select(Target).where(Target.tenant_id == user.tenant_id)
            all_targets = session.exec(all_targets_query).all()
            
            security_results = session.exec(text(query_security)).all()
            
            # Build target results map
            target_results_map = {}
            for tid, mod, data in security_results:
                if tid not in target_results_map:
                    target_results_map[tid] = {}
                # Mock result object for scorer
                class MockRes:
                    def __init__(self, d): self.data = d
                target_results_map[tid][mod] = MockRes(data)
            
            # Calculate average score
            total_score = 0
            scored_count = 0
            for t in all_targets:
                t_res = target_results_map.get(t.id, {})
                s, g, f = calculate_target_score(t, t_res)
                total_score += s
                scored_count += 1
            
            if scored_count > 0:
                avg_security_score = int(total_score / scored_count)
        
        avg_grade = get_grade(avg_security_score)
    except Exception as e:
        logger.error(f"Security score calculation failed in dashboard_stats: {e}")
        # Use defaults on error

    return templates.TemplateResponse("_dashboard_stats.html", {
        "request": request,
        "stats": {
            "active_targets": total_targets,
            "services_monitored": "-",
            "total_scans": total_scans_count,
            "queue_length": queue_len,
            "queue_active": queue_active,
            "security_score": avg_security_score,
            "security_grade": avg_grade
        },
        "user": user
    })

@app.get("/dashboard/active_scans", response_class=HTMLResponse)
async def dashboard_active_scans(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """HTMX endpoint to refresh the active scans list"""
    try:
        active_scans = session.exec(select(Target).where(Target.scan_status == "running", Target.tenant_id == user.tenant_id)).all()
        return templates.TemplateResponse("_active_scans.html", {
            "request": request,
            "active_scans": active_scans,
            "user": user
        })
    except Exception as e:
        with open("/tmp/yads_debug.log", "a") as f:
            f.write(f"Error in dashboard_active_scans: {e}\n")
        raise e

@app.get("/dashboard/targets", response_class=HTMLResponse)
async def dashboard_targets(request: Request, page: int = 1, limit: int = 9, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """
    HTMX endpoint to poll for target list updates (status/progress).
    Returns just the table rows/grid.
    """
    offset = (page - 1) * limit
    total_count = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)).one()
    
    # Fetch Paginated (Tenant Scoped)
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
    total_pages = (total_count + limit - 1) // limit
    
    # We need to calculate last_scans for the fragment too, or just mock it?
    # Ideally replicate logic or extract it.
    last_scans = {}
    
    # Fetch states only for visible targets (optimization)
    target_ids = [t.id for t in targets]
    if target_ids:
        all_states = session.exec(select(ModuleState).where(ModuleState.target_id.in_(target_ids))).all()
        for state in all_states:
            if state.target_id not in last_scans:
                last_scans[state.target_id] = {}
            last_scans[state.target_id][state.module_name] = state.last_scanned_at

    return templates.TemplateResponse("_target_list.html", {
            "request": request, 
            "targets": targets, 
            "last_scans": last_scans,
            "pagination": {
                "page": page,
                "limit": limit,
                "total_pages": total_pages,
                "total_count": total_count,
                 "start_item": offset + 1,
                "end_item": min(offset + limit, total_count)
            },
            "user": user
        })


@app.get("/logs", response_class=HTMLResponse)
async def view_logs_page(request: Request, user: User = Depends(RoleChecker(["admin", "tenant_admin"]))):
    """
    Renders the Logs page with a list of available log files.
    """
    log_dir = os.getenv("LOG_DIR", "logs")
    log_files = []
    if os.path.exists(log_dir):
        # List all .log files
        log_files = [f for f in os.listdir(log_dir) if f.endswith('.log')]
        log_files.sort()
    
    # Default to yads-api.log if available, else first one
    default_log = "yads-api.log"
    if default_log not in log_files and log_files:
        default_log = log_files[0]
    elif not log_files:
        default_log = ""

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "log_files": log_files,
        "current_log": default_log,
        "user": user
    })

@app.get("/api/logs/stream")
async def get_logs_stream(file: str = "yads-api.log", user: User = Depends(RoleChecker(["admin", "tenant_admin"]))):
    """Reads the last 100 lines of the specified log file. Filters by tenant if not global admin."""
    log_dir = os.getenv("LOG_DIR", "logs")
    
    # Security: Ensure clean filename (basename only) to prevent traversal
    safe_filename = os.path.basename(file)
    log_file = os.path.join(log_dir, safe_filename)
    
    if not os.path.exists(log_file):
        return {"logs": [f"Log file '{safe_filename}' not found."]}
    
    lines_to_return = []
    
    # Efficiently read last N lines
    # For now, we read full file or chunk and filter. 
    # Since we need to filter, reading just last 100 bytes is risky if we filter them all out.
    # We'll read a reasonable tail size, say last 2000 lines, filter them, and return last 100 matches.
    
    try:
        async with aiofiles.open(log_file, mode='r') as f:
            # Reading all lines might be memory intensive for huge logs.
            # But for YADS scale (<100MB logs usually due to rotation), it's okay for now.
            content = await f.read()
            lines = content.splitlines()
            
            # Filtering Logic
            if user.role == "admin":
                # Admin sees all
                lines_to_return = lines
            else:
                # Tenant Admin sees only lines with [Tenant: ID]
                tenant_tag = f"[Tenant: {user.tenant_id}]"
                lines_to_return = [line for line in lines if tenant_tag in line]
                
            return {"logs": lines_to_return[-100:]}
            
    except Exception as e:
        return {"logs": [f"Error reading log file: {str(e)}"]}

@app.post("/targets/add", response_class=HTMLResponse)
async def ui_add_target(request: Request, domain: str = Form(...), session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """HTMX endpoint to add a target"""
    domain = domain.lower().strip()
    # Tenant Scope
    existing = session.exec(select(Target).where(Target.domain == domain, Target.tenant_id == user.tenant_id)).first()
    
    if existing:
        target = existing
    else:
        target = Target(domain=domain, tenant_id=user.tenant_id)
        session.add(target)
        session.commit()
        session.refresh(target)
        
    # Always Trigger Scan (New or Existing) - DISABLED by user request (Import Only)
    # celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain])
    
    # Return standard target list row fragment or redirect
    return await dashboard(request, session, user) 
    # In a real HTMX app, we'd return just the new row or the updated list fragment.
    # For simplicity, refreshing the page or returning full page is easiest for now.

@app.delete("/targets/{target_id}")
async def delete_target(target_id: int, request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Manually delete related records if no cascade is set up in DB
    # SQLModel/SQLAlchemy usually handles this if relationships are defined with cascade.
    # Let's purge explicitly to be safe as we didn't inspect FK constraints deeply in DB init.
    
    # Delete ScanResults
    session.exec(text(f"DELETE FROM scanresult WHERE target_id = {target_id}"))
    # Delete ModuleStates
    session.exec(text(f"DELETE FROM modulestate WHERE target_id = {target_id}"))
    
    session.delete(target)
    session.commit()
    
    # Return empty string or redirect? 
    # If HTMX deletes the row, we return empty body (200 OK) so the row disappears.
    return HTMLResponse(content="", status_code=200)

# -- Real-time Scan Status & Logs --

@app.get("/api/scans/{target_id}/status")
async def get_scan_status(target_id: int):
    """
    Returns the latest status message and progress from Redis/DB.
    """
    r = redis_client
    
    # Check Redis for live status first
    status_msg = r.get(f"scan:status:{target_id}")
    if status_msg:
        return {"status": status_msg}
        
    # Fallback to DB if no live status (e.g. idle or finished)
    with Session(engine) as session:
        t = session.get(Target, target_id)
        if t:
            return {"status": t.scan_progress or t.scan_status}
            
    return {"status": "Unknown"}

@app.get("/api/scans/{target_id}/logs")
async def get_scan_logs(target_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns the recent log lines from Redis.
    """
    import json
    r = redis_client
    
    # Security Check
    target = session.get(Target, target_id)
    if not target:
        return {"logs": []}
        
    if user.role != "admin" and target.tenant_id != user.tenant_id:
        # Silently return empty or error? Error 403 is better but this is likely consumed by polling JS.
        # Returning explicit error message in logs list is safer for UI feedback or just 403.
        raise HTTPException(status_code=403, detail="Not authorized to view these logs")

    # Fetch List
    logs = r.lrange(f"scan:logs:{target_id}", 0, -1)
    parsed_logs = []
    
    for l in logs:
        try:
            entry = json.loads(l)
            parsed_logs.append(entry)
        except:
            parsed_logs.append({"msg": l})
            
    return {"logs": parsed_logs}

@app.get("/api/scans/{target_id}/network-context")
async def get_scan_network_context(target_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns the network context (external IP, resolved IPs) for a scan.
    """
    from yads.core.redis_logger import get_scan_network_context as get_network_ctx

    # Security Check
    target = session.get(Target, target_id)
    if not target:
        return {"network_context": None}

    if user.role != "admin" and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this data")

    context = get_network_ctx(target_id)
    return {"network_context": context, "target_domain": target.domain}


@app.get("/components/log_viewer/{target_id}", response_class=HTMLResponse)
async def component_log_viewer(request: Request, target_id: int):
    """
    Returns the HTML fragment for the log viewer.
    """
    return templates.TemplateResponse("_log_viewer.html", {
        "request": request,
        "target_id": target_id
    })

@app.get("/components/log_lines/{target_id}", response_class=HTMLResponse)
async def component_log_lines(request: Request, target_id: int):
    """
    Returns just the <li> elements for the log viewer (polled by HTMX).
    """
    import json
    r = redis_client
    
    logs = r.lrange(f"scan:logs:{target_id}", 0, -1)
    parsed_logs = []
    for l in logs:
        try:
            entry = json.loads(l)
            parsed_logs.append(entry)
        except:
            parsed_logs.append({"msg": l, "ts": "", "level": "INFO"})
            
    return templates.TemplateResponse("_log_viewer_lines.html", {
        "request": request, 
        "logs": parsed_logs
    })


# -- Table View & Bulk Actions --

@app.get("/targets/table", response_class=HTMLResponse)
async def view_target_table(
    request: Request, 
    page: int = 1, 
    limit: int = 20, 
    filter_online: str = "all",

    filter_server: Optional[str] = None,
    filter_asn: Optional[str] = None,
    filter_last_scan: str = "all",
    filter_tag: Optional[str] = None,
    filter_domain: Optional[str] = None,
    filter_web_probe: str = "all",
    
    # New Per-Column Filters
    filter_http_status: Optional[str] = None,
    filter_https_status: Optional[str] = None,
    filter_redirect: Optional[str] = None, # "yes", "no", "all"
    filter_wildcard: Optional[str] = None, # "yes", "no", "all"
    filter_scan_status: Optional[str] = None, # "running", "queued", "idle", "failed"
    
    # New Functional Filters
    filter_login: Optional[str] = None,
    filter_dns: Optional[str] = None,
    filter_secrets: Optional[str] = None,
    filter_takeover: Optional[str] = None,
    filter_ssl: Optional[str] = None,
    
    # New: Persist Scan Options
    scan_types: List[str] = Query(None),
    
    # New: Sorting & Scope
    filter_scope: str = "all", # "all", "external", "internal"
    filter_root_domain: Optional[str] = None, # For the dedicated root filter
    filter_archived: str = "no", # "yes", "no", "only"
    
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Renders a detailed table view of all targets with bulk actions.
    Supports pagination and filtering (Online Status, Last Scan).
    """
    from fastapi import Query # Ensure import availability if not global, but usually at top.
    from datetime import datetime, timedelta
    from sqlmodel import or_, and_, col

    # Scan Types Persistence Logic
    default_scan_types = []  # Default to NOTHING selected to force explicit choice and avoid accidental full scans
    
    # If not provided (initial load or link without params), use defaults
    if scan_types is None:
        selected_scan_types = default_scan_types
    else:
        selected_scan_types = scan_types

    # Base Query (Tenant Scoped)
    query = select(Target).where(Target.tenant_id == user.tenant_id)

    # -- Filter: Archived --
    if filter_archived == "no":
        query = query.where(Target.is_archived == False)
    elif filter_archived == "only":
        query = query.where(Target.is_archived == True)
    # else filter_archived == "yes" -> show all
    
    # -- Filter: Domain (Wildcard) --
    if filter_domain:
        clean_filter = filter_domain.strip()
        if '*' in clean_filter:
            # Shell-style wildcard: * -> SQL %
            sql_pattern = clean_filter.replace('*', '%')
            query = query.where(Target.domain.ilike(sql_pattern))
        else:
            # Strict match if no wildcard provided? 
            # Or standard contains? 
            # Given explicit "using * as wildcard" request, we default to exact match if no * finds, 
            # BUT usually search bars are "contains". 
            # Let's do exact match here to honor the distinction, or maybe simple substring?
            # User request: "filter domains using * as wildcard"
            # It implies "*" is the mechanism.
            # I'll implement: Treat as exact string unless * is present. 
            # Actually, let's treat it as "starts with" or partial?
            # Safe bet: default to partial match (contains) is usually what users want if they don't know wildcards.
            # BUT if they specifically asked for * wildcard, maybe they want to be precise.
            # I will use ILIKE logic: if no * is present, I will treat it as a straight ILIKE match (exact). 
            # Users can add *name* to do contains.
            # Wait, that might be annoying.
            # Compromise: I'll blindly replace * with % and run ILIKE. 
            # If they don't use *, it's an exact match. 
            # If they want contains, they type *foo*.
            # User explicitly requested strict behavior: "Only example-client.de without anything else"
            # So if no wildcard is used, we enforce STRICT equality.
            query = query.where(func.lower(Target.domain) == clean_filter.lower())
    
    # -- Filter: Last Scan Time --
    if filter_last_scan != "all":
        if filter_last_scan == "never":
            # Targets that utilize NO ScanResults
            # We use a subquery to find all target_ids that HAVE results
            sub_scanned = select(ScanResult.target_id).distinct()
            query = query.where(Target.id.notin_(sub_scanned))
        else:
            cutoff = datetime.utcnow()
            if filter_last_scan == "24h":
                cutoff -= timedelta(hours=24)
            elif filter_last_scan == "7d":
                cutoff -= timedelta(days=7)
            
            # Subquery: Targets with at least one scan after cutoff
            sub_recent = select(ScanResult.target_id).where(ScanResult.scanned_at >= cutoff).distinct()
            query = query.where(Target.id.in_(sub_recent))

    # -- Filter: Online Status --
    if filter_online != "all":
        # Define what "Online" means in terms of specific findings
        # 1. Infrastructure Scanner: data->ip is present
        # 2. Web Analyzer: data->status_code is > 0
        
        # Note: We use `text` for raw JSON/Cast operations compatible with PostgreSQL
        online_criteria = or_(
             and_(ScanResult.module_name == 'infrastructure_scanner', text("data->>'ip' IS NOT NULL")),
             and_(ScanResult.module_name == 'web_analyzer', text("(data->>'status_code')::int > 0")),
             and_(ScanResult.module_name == 'port_scanner', text("data->>'is_active' = 'true'"))
        )
        
        sub_online = select(ScanResult.target_id).where(online_criteria).distinct()

        if filter_online == "online":
            query = query.where(Target.id.in_(sub_online))
            
        elif filter_online == "offline":
             # Offline = Has been scanned (at least once) BUT is not in the "Online" list
             # 1. Get all scanned IDs
             sub_scanned = select(ScanResult.target_id).distinct()
             
             query = query.where(Target.id.in_(sub_scanned))
             query = query.where(Target.id.notin_(sub_online))
             
        elif filter_online == "unknown":
             # Unknown = Never Scanned (Same as Last Scan: Never)
             sub_scanned = select(ScanResult.target_id).distinct()
             query = query.where(Target.id.notin_(sub_scanned))

    # -- Filter: Server (Web Analyzer) --
    if filter_server:
        # Subquery: Targets having web_analyzer scan with specific server header
        # Using cast to text for JSON comparison
        sub_server = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'server_header' = :server").bindparams(server=filter_server)
        ).distinct()
        query = query.where(Target.id.in_(sub_server))

    # -- Filter: ASN (Infrastructure Scanner) --
    if filter_asn:
        # Subquery: Targets having infrastructure_scanner with specific ASN
        sub_asn = select(ScanResult.target_id).where(
            ScanResult.module_name == 'infrastructure_scanner',
            text("data->'asn'->>'asn' = :asn").bindparams(asn=filter_asn)
        ).distinct()
        query = query.where(Target.id.in_(sub_asn))

    # -- Filter: Tags --
    if filter_tag:
        # JSONB Containment: tags contains [filter_tag]
        query = query.where(Target.tags.contains([filter_tag]))

    # -- Filter: Scan Status --
    if filter_scan_status and filter_scan_status != "all":
        query = query.where(Target.scan_status == filter_scan_status)

    # -- Filter: HTTP Status (Web Analyzer) --
    if filter_http_status:
        # Find targets where Web Analyzer result has this http_status
        # Note: data->'http_status' might be number or string. Cast to text for comparison.
        try:
            status_code = int(filter_http_status)
            sub_http = select(ScanResult.target_id).where(
                ScanResult.module_name == 'web_analyzer',
                text("data->>'http_status' = :code").bindparams(code=str(status_code))
            ).distinct()
            query = query.where(Target.id.in_(sub_http))
        except:
            pass # Invalid integer input

    # -- Filter: HTTPS Status (Web Analyzer) --
    if filter_https_status:
        try:
            status_code = int(filter_https_status)
            sub_https = select(ScanResult.target_id).where(
                ScanResult.module_name == 'web_analyzer',
                text("data->>'https_status' = :code").bindparams(code=str(status_code))
            ).distinct()
            query = query.where(Target.id.in_(sub_https))
        except:
            pass

    # -- Filter: Redirect (Web Analyzer) --
    if filter_redirect and filter_redirect != "all":
        # check data->'https_redirect' (boolean)
        is_redir = "true" if filter_redirect == "yes" else "false"
        sub_redir = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'https_redirect' = :val").bindparams(val=is_redir)
        ).distinct()
        query = query.where(Target.id.in_(sub_redir))

    # -- Filter: Wildcard (DNS Scanner) --
    if filter_wildcard and filter_wildcard != "all":
        # check data->'wildcard_detected' (boolean)
        is_wild = "true" if filter_wildcard == "yes" else "false"
        # Check both dns_scanner and subdomain_scanner as they both detect wildcards
        sub_wild = select(ScanResult.target_id).where(
            or_(ScanResult.module_name == 'dns_scanner', ScanResult.module_name == 'subdomain_scanner'),
            text("data->>'wildcard_detected' = :val").bindparams(val=is_wild)
        ).distinct()
        query = query.where(Target.id.in_(sub_wild))

    # -- Filter: Login Page --
    if filter_login and filter_login != "all":
        is_login = "true" if filter_login == "yes" else "false"
        sub_login = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'is_login_page' = :val").bindparams(val=is_login)
        ).distinct()
        query = query.where(Target.id.in_(sub_login))

    # -- Filter: DNS (Has Data/Subdomains) --
    if filter_dns and filter_dns != "all":
        # "has_data" means either dns_scanner or subdomain_scanner has results
        # We check if 'subdomains' array length > 0 OR 'records' is not empty
        if filter_dns == "active":
             sub_dns = select(ScanResult.target_id).where(
                or_(ScanResult.module_name == 'dns_scanner', ScanResult.module_name == 'subdomain_scanner'),
                text("jsonb_array_length(data->'subdomains') > 0")
             ).distinct()
             query = query.where(Target.id.in_(sub_dns))
        elif filter_dns == "none":
            # Harder to filter "None" with subquery IN, usually requires NOT IN
            pass # TODO: Implement "No DNS" cleanly if needed, or just focus on Active

    # -- Filter: Secrets --
    if filter_secrets and filter_secrets == "found":
        sub_sec = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("jsonb_array_length(data->'secrets') > 0")
        ).distinct()
        query = query.where(Target.id.in_(sub_sec))

    # -- Filter: Takeover --
    if filter_takeover and filter_takeover == "found":
        sub_take = select(ScanResult.target_id).where(
            ScanResult.module_name == 'dns_scanner',
            text("jsonb_array_length(data->'takeover_risks') > 0")
        ).distinct()
        query = query.where(Target.id.in_(sub_take))

    # -- Filter: SSL Issues --
    if filter_ssl and filter_ssl == "issues":
         # Look for scan result with "error" key present in data
         sub_ssl = select(ScanResult.target_id).where(
            ScanResult.module_name == 'ssl_scanner',
            text("data ? 'error'") # JSONB operator for key existence
         ).distinct()
         query = query.where(Target.id.in_(sub_ssl))
    
    # -- Filter: Server Header --
    if filter_server:
        # data->'server_header' contains string
        search_srv = f"%{filter_server}%"
        sub_srv = select(ScanResult.target_id).where(
            ScanResult.module_name == 'web_analyzer',
            text("data->>'server_header' ILIKE :srv").bindparams(srv=search_srv)
        ).distinct()
        query = query.where(Target.id.in_(sub_srv))

    # -- Filter: ASN --
    if filter_asn:
        # data->'asn'->>'asn' (e.g. "AS1234") or 'asn_description'
        search_asn = f"%{filter_asn}%"
        sub_asn = select(ScanResult.target_id).where(
            ScanResult.module_name == 'infrastructure_scanner',
            text("(data->'asn'->>'asn' ILIKE :asn OR data->'asn'->>'asn_description' ILIKE :asn)").bindparams(asn=search_asn)
        ).distinct()
        query = query.where(Target.id.in_(sub_asn)) 

    # -- Filter: Scope (Internal vs External) --
    INTERNAL_TLDS = ['.vrnet', '.internal', '.local', '.lan', '.test']
    
    if filter_scope == "external":
        # Exclude internal TLDs
        for tld in INTERNAL_TLDS:
            query = query.where(func.lower(Target.domain).not_like(f"%{tld}"))
            
    elif filter_scope == "internal":
        # Include ONLY internal TLDs
        conditions = [func.lower(Target.domain).like(f"%{tld}") for tld in INTERNAL_TLDS]
        query = query.where(or_(*conditions))

    # -- Filter: Root Domain --
    if filter_root_domain:
        # Match EXACT root OR anything ending in .root
        # This covers example-client.de and sub.example-client.de
        query = query.where(
            or_(
                Target.domain == filter_root_domain,
                Target.domain.like(f"%.{filter_root_domain}")
            )
        )

    # Calculate offset

    # Calculate offset
    offset = (page - 1) * limit
    
    # Get Total Count (Applying Filters)
    # We use query.whereclause to count matching records
    if query.whereclause is not None:
        total_count = session.exec(select(func.count()).select_from(Target).where(query.whereclause)).one()
    else:
        total_count = session.exec(select(func.count()).select_from(Target)).one()
    
    # Fetch Paginated Targets
    # Default Sorting: Hierarchical (Reversed Domain)
    # This puts example-client.de (ed.knabzd) before sub.example-client.de (ed.knabzd.bus)
    # Using func.reverse from SQLAlchemy (Postgres supported)
    targets = session.exec(query.order_by(func.reverse(Target.domain)).offset(offset).limit(limit)).all()
    
    # Calculate Total Pages
    total_pages = (total_count + limit - 1) // limit

    # -- Cipher Compliance Setup --
    from yads.models import SystemConfig
    approved_ciphers_set = set()
    ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
    raw_ac = ""
    if ac_conf:
        raw_ac = ac_conf.value
    else:
        # Load from file default
        try:
             import os
             if os.path.exists("ciphers.csv"):
                with open("ciphers.csv", "r") as f:
                    raw_ac = f.read()
        except:
            pass
    
    if raw_ac:
        for line in raw_ac.splitlines():
            # Format: TLS Version,Cipherset
            # We care about the 2nd column "Cipherset" which is the distinct name
            parts = line.split(',')
            if len(parts) >= 2:
                cipher_name = parts[1].strip()
                if cipher_name and cipher_name.lower() != "cipherset": # Skip header
                    approved_ciphers_set.add(cipher_name)
        
    # Prepare table rows with summary data
    table_rows = []
    for t in targets:
        results = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).all()
        
        # Summaries
        # Look for either dns_scanner or subdomain_scanner, prioritizing subdomain_scanner (more data)
        sub_scan = next((r for r in results if r.module_name == 'subdomain_scanner'), None)
        dns_scan = next((r for r in results if r.module_name == 'dns_scanner'), None)
        dns = sub_scan if sub_scan else dns_scan
        
        ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
        web = next((r for r in results if r.module_name == 'web_analyzer'), None)
        infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
        tld_scan = next((r for r in results if r.module_name == 'tld_scanner'), None)
        tld_scan = next((r for r in results if r.module_name == 'tld_scanner'), None)
        port_scan = next((r for r in results if r.module_name == 'port_scanner'), None)
        nuclei_scan = next((r for r in results if r.module_name == 'nuclei_scanner'), None)
        
        # Security Score Calculation
        # Convert results list to dict {module_name: result} for scorer
        latest_results_map = {r.module_name: r for r in results}
        score, grade, factors = calculate_target_score(t, latest_results_map)
        grade_color = get_grade_color(grade)

        
        # Online Status Logic (Mirroring the Filter Logic)
        is_online = None 
        if infra or web or port_scan:
            has_ip = False
            if infra and infra.data and infra.data.get("ip"):
                has_ip = True
            
            has_http = False
            if web and web.data and web.data.get("status_code"):
                code = web.data.get("status_code")
                if isinstance(code, int) and code > 0:
                    has_http = True
            
            has_probe = False
            if port_scan and port_scan.data and port_scan.data.get("is_active"):
                has_probe = True

            if has_ip or has_http or has_probe:
                is_online = True
            else:
                is_online = False

        # Extract DNS A Record (IP)
        # Data structure: data["records"]["A"] = ["1.2.3.4", ...]
        dns_ip = None
        if dns and dns.data and "records" in dns.data and "A" in dns.data["records"]:
             a_records = dns.data["records"]["A"]
             if a_records:
                 dns_ip = a_records[0]

        row_data = {
            "target": t,
            "is_online": is_online,
            "dns_ip": dns_ip,
            "dns_count": len(dns.data.get("subdomains", [])) if (dns and dns.data) else 0,
            "ssl_issuer": ssl.data.get("issuer", {}).get("commonName") if (ssl and ssl.data and not ssl.data.get("error")) else None,
            "ssl_expiry": ssl.data.get("notAfter") if (ssl and ssl.data and not ssl.data.get("error")) else None,
            "web_server": web.data.get("server_header") if (web and web.data) else None,
            "asn": infra.data.get("asn", {}).get("asn") if (infra and infra.data) else None,
            "http_status": web.data.get("http_status") if (web and web.data) else None,
            "https_status": web.data.get("https_status") if (web and web.data) else None,
            "https_redirect": web.data.get("https_redirect") if (web and web.data) else None,
            "wildcard_detected": dns.data.get("wildcard_detected") if (dns and dns.data) else None,
            "takeover_risks": dns.data.get("takeover_risks", []) if (dns and dns.data) else [],
            "tld_stats": tld_scan.data if (tld_scan and tld_scan.data) else None,
            "port_scan": port_scan.data if (port_scan and port_scan.data) else None,
            "nuclei_stats": nuclei_scan.data.get("stats") if (nuclei_scan and nuclei_scan.data) else None,
            "last_scan": results[0].scanned_at if results else None,
            "last_scan": results[0].scanned_at if results else None,
            "modules": list(set([r.module_name for r in results])),
            "last_scan": results[0].scanned_at if results else None,
            "modules": list(set([r.module_name for r in results])),
            "is_login_page": web.data.get("is_login_page", False) if (web and web.data) else False,
            "security_score": score,
            "security_grade": grade,
            "security_grade_color": grade_color,
            "score_factors": factors
        }
        
        # Calculate Compliance
        compliant = 0
        non_compliant = 0
        if ssl and ssl.data and not ssl.data.get("error"):
            detected_ciphers = ssl.data.get("ciphers", [])
            # detected_ciphers is list of dicts: {name, version, bits}
            for dc in detected_ciphers:
                name = dc.get("name")
                if name:
                    if name in approved_ciphers_set:
                        compliant += 1
                    else:
                        non_compliant += 1
                        
        row_data["cipher_compliant"] = compliant
        row_data["cipher_compliant"] = compliant
        row_data["cipher_non_compliant"] = non_compliant
        
        # CVE Statistics
        cve_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        secrets_count = 0
        
        if web and web.data:
            if "cves" in web.data:
                for cve in web.data["cves"]:
                    try:
                        cvss = float(cve.get("cvss", 0))
                        if cvss >= 9.0:
                            cve_stats["critical"] += 1
                        elif cvss >= 7.0:
                            cve_stats["high"] += 1
                        elif cvss >= 4.0:
                            cve_stats["medium"] += 1
                        else:
                            cve_stats["low"] += 1
                    except (ValueError, TypeError):
                        pass
            
            # Secret Stats
            if "secrets" in web.data:
                secrets_count = len(web.data["secrets"])

        row_data["cve_stats"] = cve_stats
        row_data["secrets_count"] = secrets_count
        
        # Root Domain Logic
        ext = tldextract.extract(t.domain)
        # Reconstruct root (e.g. example-client.de)
        root = f"{ext.domain}.{ext.suffix}"
        row_data["root_domain"] = root
        # Check if this target IS the root (ignoring subdomain part if empty or 'www'?)
        # Strict check: is the subdomain empty?
        row_data["is_root"] = (not ext.subdomain)
        
        # Calculate visual depth
        # If no subdomain, depth 0. Else dot count + 1
        if not ext.subdomain:
            row_data["depth"] = 0
        else:
             row_data["depth"] = ext.subdomain.count('.') + 1
        
        table_rows.append(row_data)

    # -- Extract Unique Root Domains for Filter --
    # Optimization: If list is huge, this might be slow. 
    # Query all domains ONLY if we need to populate the filter?
    # Let's do a lightweight query for all domains to build the dropdown. (Tenant Scoped)
    all_domains = session.exec(select(Target.domain).where(Target.tenant_id == user.tenant_id)).all()
    unique_roots = set()
    for d in all_domains:
        ext = tldextract.extract(d)
        if ext.domain and ext.suffix:
            unique_roots.add(f"{ext.domain}.{ext.suffix}")
    
    unique_roots_list = sorted(list(unique_roots))

    return templates.TemplateResponse("target_table.html", {
        "user": user,
        "request": request, 
        "rows": table_rows,
        "filter_online": filter_online,
        "filter_last_scan": filter_last_scan,
        "filter_tag": filter_tag,
        "filter_server": filter_server,
        "filter_asn": filter_asn,
        "filter_domain": filter_domain,
        "filter_web_probe": filter_web_probe,
        
        "filter_http_status": filter_http_status,
        "filter_https_status": filter_https_status,
        "filter_redirect": filter_redirect,
        "filter_wildcard": filter_wildcard,
        "filter_scan_status": filter_scan_status,
        
        "filter_scope": filter_scope,
        "filter_root_domain": filter_root_domain,
        "unique_root_domains": unique_roots_list,
        
        "limit": limit,
        "total_targets": total_count,
        "total_pages": total_pages,
        "selected_scan_types": selected_scan_types,
        "unique_tags": get_unique_tags(session),
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "total_count": total_count,
            "start_item": offset + 1,
            "end_item": min(offset + limit, total_count)
        }
    })




@app.post("/scans/stop-all")
async def stop_all_scans(session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """
    Panic Button: Immediately stops all scans.
    1. Pauses the Queue (prevent new tasks).
    2. Purges Redis Queue (remove pending).
    3. FORCE KILLS (SIGKILL) all active and reserved tasks.
    4. Updates DB status.
    """
    # 1. Pause Queue
    # We need to ensure QUEUE_ACTIVE is set to false
    # Check if we have set_system_config helper, if not, do it manually
    conf = session.exec(select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")).first()
    if not conf:
        conf = SystemConfig(key="QUEUE_ACTIVE", value="false")
        session.add(conf)
    else:
        conf.value = "false"
        session.add(conf)
    session.commit() # Commit pause immediately

    # 2. Purge Pending Queue
    purged_count = celery_app.control.purge()
    
    # 3. Force Kill Active & Reserved Tasks
    i = celery_app.control.inspect()
    active = i.active() if i else None
    reserved = i.reserved() if i else None
    revoked_count = 0
    
    # Helper to kill tasks
    def kill_tasks(task_dict):
        count = 0
        if task_dict:
            for worker, tasks in task_dict.items():
                for task in tasks:
                    task_id = task.get("id")
                    if task_id:
                        # SIGKILL is required for a true "Stop All"
                        celery_app.control.revoke(task_id, terminate=True, signal='SIGKILL')
                        count += 1
        return count

    revoked_count += kill_tasks(active)
    revoked_count += kill_tasks(reserved)
    
    # 4. Update DB Status
    statement = select(Target).where(Target.scan_status.in_(["running", "queued", "scanning"]))
    targets = session.exec(statement).all()
    
    db_updated_count = 0
    for t in targets:
        t.scan_status = "stopped"
        t.scan_progress = "Manually stopped (Panic)"
        session.add(t)
        db_updated_count += 1
        
    session.commit()
    
    msg = f"PANIC STOP: Queue Paused. Purged: {purged_count}, Killed: {revoked_count}, Updated: {db_updated_count}"
    return RedirectResponse(url=f"/?msg={msg}", status_code=303)


# -- Backup & Restore Routes --

@app.post("/api/backup/export")
async def export_data(
    tenant_ids: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    session: Session = Depends(get_session)
):
    """
    Generates and downloads a full or partial system backup (Zip).
    """
    try:
        # Parse tenant_ids
        t_ids_list = []
        if tenant_ids:
             try:
                 t_ids_list = [int(x.strip()) for x in tenant_ids.split(",") if x.strip()]
             except ValueError:
                 logger.warning(f"Invalid tenant_ids format: {tenant_ids}")
                 pass

        zip_file = create_backup_zip(session, tenant_ids=t_ids_list, password=password)
        
        # Determine extension based on encryption
        ext = "enc" if password else "zip"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"yads_backup_{timestamp}.{ext}"
        
        return StreamingResponse(
            zip_file, 
            media_type="application/octet-stream", # Generic binary
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/backup/analyze", response_class=HTMLResponse)
async def analyze_backup(
    request: Request,
    file: UploadFile = File(...),
    password: Optional[str] = Form(None),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"])),
    session: Session = Depends(get_session)
):
    """
    Analyzes the uploaded backup file and returns a summary for confirmation.
    """
    contents = await file.read()
    
    meta = {}
    db_summary = {}
    
    # Try to handle potential encryption
    file_bytes = io.BytesIO(contents)
    is_encrypted = False
    
    # Attempt to open as Zip
    try:
        zf_check = zipfile.ZipFile(file_bytes, 'r')
        zf_check.close()
        file_bytes.seek(0)
    except zipfile.BadZipFile:
        # Might be encrypted
        if password:
            try:
                from yads.core.backup import decrypt_data
                decrypted = decrypt_data(contents, password)
                file_bytes = io.BytesIO(decrypted)
                is_encrypted = True
            except Exception as e:
                return HTMLResponse(f"<div class='text-red-400'>Decryption failed: {str(e)}</div>", status_code=400)
        else:
             return HTMLResponse("<div class='text-red-400'>Invalid Zip File. If encrypted, please provide password.</div>", status_code=400)

    try:
        with zipfile.ZipFile(file_bytes, 'r') as zf:
            if "metadata.json" in zf.namelist():
                meta = json.loads(zf.read("metadata.json"))
            
            # Count records roughly
            for name in zf.namelist():
                if name.startswith("data/") and name.endswith(".json"):
                    table = name.replace("data/", "").replace(".json", "")
                    data = json.loads(zf.read(name))
                    db_summary[table] = len(data)
    except Exception as e:
        logger.error(f"Error analyzing backup content: {e}")
        return HTMLResponse(f"<div class='text-red-400'>Error analyzing backup: {str(e)}</div>", status_code=400)

    # Encode contents to pass to next step? NO. Too large.
    # We should save to a temp file and confirm via ID?
    # Security risk: Temp file handling.
    # Or: The User re-uploads for confirmation (simpler stateless)?
    # OR: We use a signed token/cache.
    
    # SIMPLE APPROACH: Save to /tmp/yads_restore_pending.zip
    # Not thread safe for multiple admins restoring same time, but acceptable for this scope.
    import os
    tmp_path = "/tmp/yads_restore_pending.zip"
    with open(tmp_path, "wb") as f:
        f.write(contents)
    logger.info(f"Backup saved to temporary path: {tmp_path}")
        
    # Look up Tenant Names (Pre-load from DB first, then try to fill from Zip if unknown)
    tenant_ids = meta.get("tenant_ids", [])
    tenant_map = {tid: f"Unknown ID {tid}" for tid in tenant_ids}

    # 1. Try to read from Zip (Best source for restore)
    try:
        with zipfile.ZipFile(file_bytes, 'r') as zf:
            if "data/tenant.json" in zf.namelist():
                t_data = json.loads(zf.read("data/tenant.json"))
                for t in t_data:
                    if t.get("id") in tenant_map:
                        tenant_map[t.get("id")] = t.get("name")
    except Exception as e:
        logger.warning(f"Could not read tenant names from zip: {e}")

    # 2. Flatten for template
    tenant_names = [tenant_map.get(tid, f"ID {tid}") for tid in tenant_ids]
    
    from yads.core.backup import SYSTEM_TABLES
    # Render Confirmation Modal
    return templates.TemplateResponse("components/restore_confirmation_modal.html", {
        "request": request,
        "meta": meta,
        "db_summary": db_summary, # Assuming db_summary is now 'stats' in the new template context
        "tenant_names": tenant_names,
        "is_partial": bool(tenant_ids),
        "tmp_path": tmp_path,
        "skipped_tables": SYSTEM_TABLES,
        "filename": file.filename, # Added filename
        "password": password # Pass back to be embedded in hidden field
    })

@app.post("/api/backup/execute_restore")
async def execute_restore(
    confirmed: bool = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin"]))
):
    """
    Actually executes the restore from the temp file.
    """
    logger.info(f"Received restore execution request. Confirmed: {confirmed}")
    if not confirmed:
         return RedirectResponse(url="/settings?msg=Restore+Cancelled", status_code=303)
         
    import os
    tmp_path = "/tmp/yads_restore_pending.zip"
    if not os.path.exists(tmp_path):
        return RedirectResponse(url="/settings?error=Restore+Timeout:+File+not+found.+Please+upload+again.", status_code=303)
        
    try:
        with open(tmp_path, "rb") as f:
            content = f.read()
            
        from yads.core.backup import restore_backup_from_zip
        # Re-read meta for safety (logic inside restore anyway)
        restore_backup_from_zip(session, content)
        
        # Cleanup
        os.remove(tmp_path)
        
        return RedirectResponse(url="/settings?msg=System+Restored+Successfully.+Tenant+data+has+been+updated.", status_code=303)
    except Exception as e:
        logger.error(f"Restore Error: {e}")
        return RedirectResponse(url=f"/settings?error=Restore+Failed:+{str(e)}", status_code=303)

# Deprecated simple restore (keep checking for legacy calls or remove?)
# Removing original direct restore endpoint to force use of new flow
# Or keeping it but redirecting?
# Let's replace the old endpoint logic to be safe or just remove it.
# The previous POST /api/backup/restore is REPLACED by the logic above or we just re-route.







# -- Graph View --

@app.get("/targets/graph", response_class=HTMLResponse)
async def view_graph_page(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Renders the Graph View page.
    """
    # Filter by user's tenant
    if user.role == "admin" and not user.tenant_id:
        targets = session.exec(select(Target)).all()
    else:
        targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id)).all()
        
    return templates.TemplateResponse("graph.html", {"request": request, "targets": targets, "user": user})


@app.get("/api/graph/{target_id}")
async def get_graph_data(target_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns nodes and edges for the graph visualization.
    """
    target = session.get(Target, target_id)
    if not target:
        return {"error": "Target not found"}

    # Tenant Check
    if user.role != "admin" or user.tenant_id:
        if target.tenant_id != user.tenant_id:
             return {"error": "Unauthorized access to target"}
             
    nodes = []
    edges = []
    
    # 1. Root Node (The Target)
    nodes.append({
        "id": f"domain_{target.id}", 
        "label": target.domain, 
        "color": "#ff5e5e",
        "shape": "dot",
        "size": 30
    })

    # Fetch latest results
    results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc())).all()
    
    # DNS Result
    dns = next((r for r in results if r.module_name == 'dns_scanner'), None)
    if dns and dns.data:
        # A Records -> IP Nodes
        for i, ip in enumerate(dns.data.get("a_records", [])):
            ip_node_id = f"ip_{ip}"
            # Check duplicates in list (simple check)
            if not any(n['id'] == ip_node_id for n in nodes):
                nodes.append({"id": ip_node_id, "label": ip, "color": "#2e86de"})
            
            edges.append({"from": f"domain_{target.id}", "to": ip_node_id, "label": "resolves_to", "length": 150})
        
        # Subdomains -> Subdomain Nodes
        for sub in dns.data.get("subdomains", []):
            # sub structure: {subdomain: "...", ips: []}
            s_name = sub.get("subdomain")
            if s_name and s_name != target.domain:
                 sub_id = f"sub_{s_name}"
                 if not any(n['id'] == sub_id for n in nodes):
                     nodes.append({"id": sub_id, "label": s_name, "color": "#ff9f43"})
                 
                 edges.append({"from": f"domain_{target.id}", "to": sub_id, "label": "subdomain", "length": 200})

    # SSL Result
    ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
    if ssl and ssl.data and not ssl.data.get("error"):
         issuer = ssl.data.get("issuer", {}).get("commonName")
         if issuer:
             issuer_id = f"issuer_{issuer}"
             if not any(n['id'] == issuer_id for n in nodes):
                 nodes.append({"id": issuer_id, "label": issuer, "color": "#1dd1a1"})
             edges.append({"from": f"domain_{target.id}", "to": issuer_id, "label": "issued_by"})

    # Infra Result
    infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
    if infra and infra.data:
         asn = infra.data.get("asn", {}).get("asn")
         desc = infra.data.get("asn", {}).get("asn_description")
         if asn:
             asn_label = f"{asn}\n{desc}" if desc else asn
             asn_id = f"asn_{asn}"
             if not any(n['id'] == asn_id for n in nodes):
                  nodes.append({"id": asn_id, "label": asn_label, "color": "#a55eea", "shape": "box"})

             # Link to IP or Domain?
             # If we have IPs, usually ASN is linked to IP. But for simplicity, link Domain -> ASN
             edges.append({"from": f"domain_{target.id}", "to": asn_id, "label": "hosted_by"})

    # Deception Detection Results
    deception = next((r for r in results if r.module_name == 'deception_detector'), None)
    if deception and deception.data:
        summary = deception.data.get("summary", {})

        # Add honeypot nodes (amber/orange warning color)
        for hp in deception.data.get("honeypots", []):
            hp_name = hp.get("name", "Unknown")
            hp_type = hp.get("type", "generic")
            hp_conf = hp.get("confidence", 0)
            hp_port = hp.get("port", 0)
            hp_id = f"honeypot_{hp_type}_{hp_port}"

            if not any(n['id'] == hp_id for n in nodes):
                # Color based on confidence: higher = more red/orange
                color = "#f97316" if hp_conf >= 70 else "#fbbf24"  # orange-500 or amber-400
                nodes.append({
                    "id": hp_id,
                    "label": f"🍯 {hp_name}\n({hp_conf}%)",
                    "color": color,
                    "shape": "diamond",
                    "size": 20 + (hp_conf // 10),
                    "title": f"Honeypot: {hp.get('indicator', '')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": hp_id,
                "label": f"honeypot:{hp_port}",
                "color": {"color": "#f97316", "opacity": 0.7},
                "dashes": True
            })

        # Add sinkhole nodes (red warning color)
        for sh in deception.data.get("sinkholes", []):
            sh_operator = sh.get("sinkhole_operator", "Unknown")
            sh_ip = sh.get("sinkhole_ip", "")
            sh_conf = sh.get("confidence", 0)
            sh_id = f"sinkhole_{sh_ip}" if sh_ip else f"sinkhole_{sh_operator}"

            if not any(n['id'] == sh_id for n in nodes):
                color = "#ef4444" if sh_conf >= 80 else "#f87171"  # red-500 or red-400
                nodes.append({
                    "id": sh_id,
                    "label": f"🕳️ Sinkhole\n{sh_operator}",
                    "color": color,
                    "shape": "triangle",
                    "size": 25,
                    "title": f"Sinkhole: {sh.get('indicator', '')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": sh_id,
                "label": "sinkholed",
                "color": {"color": "#ef4444", "opacity": 0.8},
                "dashes": True,
                "width": 2
            })

        # Add tarpit nodes (yellow warning color)
        for tp in deception.data.get("tarpits", []):
            tp_type = tp.get("type", "generic")
            tp_port = tp.get("port", 0)
            tp_delay = tp.get("response_delay_ms", 0)
            tp_conf = tp.get("confidence", 0)
            tp_id = f"tarpit_{tp_type}_{tp_port}"

            if not any(n['id'] == tp_id for n in nodes):
                color = "#eab308" if tp_conf >= 60 else "#facc15"  # yellow-500 or yellow-400
                nodes.append({
                    "id": tp_id,
                    "label": f"🐢 Tarpit\n{tp_delay}ms",
                    "color": color,
                    "shape": "square",
                    "size": 18,
                    "title": f"Tarpit: {tp.get('indicator', '')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": tp_id,
                "label": f"tarpit:{tp_port}",
                "color": {"color": "#eab308", "opacity": 0.6},
                "dashes": [5, 5]
            })

        # Add summary node if significant detections found
        if summary.get("total_detections", 0) > 0:
            risk = summary.get("overall_risk", "none")
            risk_colors = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#ca8a04",
                "low": "#65a30d",
                "none": "#6b7280"
            }
            summary_id = f"deception_summary_{target.id}"
            if not any(n['id'] == summary_id for n in nodes):
                nodes.append({
                    "id": summary_id,
                    "label": f"⚠️ Deception\nRisk: {risk.upper()}",
                    "color": risk_colors.get(risk, "#6b7280"),
                    "shape": "star",
                    "size": 30,
                    "title": f"Total detections: {summary.get('total_detections', 0)}, Likelihood: {summary.get('deception_likelihood', 'unknown')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": summary_id,
                "label": "deception_analysis",
                "color": {"color": risk_colors.get(risk, "#6b7280"), "opacity": 0.5},
                "width": 3
            })

    return {"nodes": nodes, "edges": edges}


@app.get("/targets/export/excel")
async def export_targets_excel(session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """
    Generates an Excel report of all targets and their latest scan results.
    """
    import pandas as pd
    from io import BytesIO
    
    # Fetch targets for this tenant
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id).order_by(Target.created_at.desc())).all()
    
    # -- Cipher Compliance Setup --
    from yads.models import SystemConfig
    approved_ciphers_set = set()
    ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
    raw_ac = ""
    if ac_conf:
        raw_ac = ac_conf.value
    else:
        # Load from file default
        try:
             import os
             if os.path.exists("ciphers.csv"):
                with open("ciphers.csv", "r") as f:
                    raw_ac = f.read()
        except:
            pass
    
    if raw_ac:
        for line in raw_ac.splitlines():
             parts = line.split(',')
             if len(parts) >= 2:
                cipher_name = parts[1].strip()
                # Skip header if it exists
                if cipher_name and cipher_name.lower() != "cipherset":
                    approved_ciphers_set.add(cipher_name)
    
    data = []
    for t in targets:
        # Fetch latest results for each module
        results = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).all()
        
        # Identify specific module results
        sub_scan = next((r for r in results if r.module_name == 'subdomain_scanner'), None)
        dns_scan = next((r for r in results if r.module_name == 'dns_scanner'), None)
        dns = sub_scan if sub_scan else dns_scan
        
        ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
        web = next((r for r in results if r.module_name == 'web_analyzer'), None)
        infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
        tld_scan = next((r for r in results if r.module_name == 'tld_scanner'), None)
        port_scan = next((r for r in results if r.module_name == 'port_scanner'), None)
        
        # Online Status Logic
        is_online = "Unknown"
        if infra or web or port_scan:
            has_ip = bool(infra and infra.data and infra.data.get("ip"))
            has_http = False
            if web and web.data and web.data.get("status_code"):
                code = web.data.get("status_code")
                if isinstance(code, int) and code > 0:
                    has_http = True
            has_probe = bool(port_scan and port_scan.data and port_scan.data.get("is_active"))
            is_online = "Online" if (has_ip or has_http or has_probe) else "Offline"

        # DNS 
        dns_ip = ""
        if dns and dns.data and "records" in dns.data and "A" in dns.data["records"]:
             a_records = dns.data["records"]["A"]
             if a_records:
                 dns_ip = a_records[0]

        # Compliance
        compliant = 0
        non_compliant = 0
        if ssl and ssl.data and not ssl.data.get("error"):
            detected_ciphers = ssl.data.get("ciphers", [])
            for dc in detected_ciphers:
                name = dc.get("name")
                if name:
                    if name in approved_ciphers_set: compliant += 1
                    else: non_compliant += 1
        
        # CVEs
        cve_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        if web and web.data and "cves" in web.data:
            for cve in web.data["cves"]:
                try:
                    cvss = float(cve.get("cvss", 0))
                    if cvss >= 9.0: cve_stats["critical"] += 1
                    elif cvss >= 7.0: cve_stats["high"] += 1
                    elif cvss >= 4.0: cve_stats["medium"] += 1
                    else: cve_stats["low"] += 1
                except: pass

        # TLDs
        tld_free = tld_scan.data.get("free_count", 0) if tld_scan and tld_scan.data else 0
        tld_diff = tld_scan.data.get("registered_count_diff_owner", 0) if tld_scan and tld_scan.data else 0

        row = {
            "ID": t.id,
            "Domain": t.domain,
            "Online": is_online,
            "Probe": "Active" if (port_scan and port_scan.data and port_scan.data.get("is_active")) else ("Inactive" if port_scan else "-"),
            "HTTP": web.data.get("http_status") if web and web.data else "-",
            "HTTPS": web.data.get("https_status") if web and web.data else "-",
            "HTTPS_Redirect": "Yes" if (web and web.data and web.data.get("https_redirect")) else "No",
            "Wildcard": "Yes" if (dns and dns.data and dns.data.get("wildcard_detected")) else "No",
            "Login_Detected": "Yes" if (web and web.data and web.data.get("is_login_page")) else "No",
            "IP": dns_ip,
            "Subdomain_Count": len(dns.data.get("subdomains", [])) if (dns and dns.data) else 0,
            "Scan_Status": t.scan_status,
            "Last_Scan": results[0].scanned_at.strftime("%Y-%m-%d %H:%M") if results else "-",
            "SSL_Issuer": ssl.data.get("issuer", {}).get("commonName", "") if (ssl and ssl.data and not ssl.data.get("error")) else "",
            "SSL_Expiry": ssl.data.get("notAfter", "") if (ssl and ssl.data and not ssl.data.get("error")) else "",
            "Cipher_Compliant": compliant,
            "Cipher_NonCompliant": non_compliant,
            "Web_Server": web.data.get("server_header", "") if web and web.data else "",
            "ASN": infra.data.get("asn", {}).get("asn", "") if infra and infra.data else "",
            "ISP": infra.data.get("asn", {}).get("asn_description", "") if infra and infra.data else "",
            "Secrets_Count": len(web.data.get("secrets", [])) if (web and web.data) else 0,
            "CVE_Critical": cve_stats["critical"],
            "CVE_High": cve_stats["high"],
            "CVE_Med": cve_stats["medium"],
            "Takeover_Risks": len(dns.data.get("takeover_risks", [])) if (dns and dns.data) else 0,
            "TLD_Free": tld_free,
            "TLD_Suspect": tld_diff,
            "Created_At": t.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        data.append(row)

    df = pd.DataFrame(data)
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Targets')
        # Auto-adjust column width? Openpyxl can do this but requires more code.
        # Pandas default is fine for MVP.
        
    output.seek(0)
    
    headers = {
        'Content-Disposition': 'attachment; filename="yads_targets_export.xlsx"'
    }
    return StreamingResponse(output, headers=headers, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@app.get("/targets/{target_id}/export")
async def export_target_pdf(target_id: int, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """
    Generates a COMPREHENSIVE PDF report for a single target using FPDF.
    Includes full details from all scan modules.
    """
    from fpdf import FPDF
    from io import BytesIO

    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc())).all()
    
    # Extract Data
    dns = next((r for r in results if r.module_name == 'dns_scanner'), None)
    web = next((r for r in results if r.module_name == 'web_analyzer'), None)
    ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
    infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
    typosquat = next((r for r in results if r.module_name == 'typosquat_scanner'), None)
    visual = next((r for r in results if r.module_name == 'visual_osint'), None)

    class PDF(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 15)
            self.cell(0, 10, f'YADS Security Report: {target.domain}', align='C')
            self.ln(12)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', align='C')

        def chapter_title(self, label):
            self.ln(5)
            self.set_font('Helvetica', 'B', 12)
            self.set_fill_color(200, 220, 255)
            self.set_x(self.l_margin)
            self.cell(0, 8, label, fill=True, align='L')
            self.ln(10)

        def content_text(self, text):
            self.set_font('Helvetica', '', 10)
            self.set_x(self.l_margin)
            self.multi_cell(0, 5, text)
            self.ln(1)

        def section_kv(self, key, value):
            # Safe string conversion
            text_value = str(value) if value is not None else "N/A"
            if not text_value: text_value = "N/A"
            
            # Check for page break needed
            if self.get_y() > 270:
                self.add_page()
            
            self.set_x(self.l_margin)
            
            # Key
            self.set_font('Helvetica', 'B', 10)
            self.cell(45, 5, f"{key}:", align='L')
            
            # Value
            self.set_font('Helvetica', '', 10)
            # Calculate remaining width strictly
            # cell moved cursor 45 to the right (implicit)
            # We want to use the rest of the line
            remaining_w = self.w - self.l_margin - self.r_margin - 45
            self.multi_cell(remaining_w, 5, text_value, align='L')
            
        def section_header(self, title):
             self.ln(3)
             if self.get_y() > 270: self.add_page()
             self.set_x(self.l_margin)
             self.set_font('Helvetica', 'B', 10)
             self.cell(0, 6, title, align='L')
             self.ln(6)
            
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # helper for checking data
    def safe_get(obj, *keys, default="N/A"):
        try:
            val = obj
            for k in keys:
                val = val.get(k, {})
            return val if val else default
        except:
            return default

    # 1. Overview
    pdf.chapter_title('Target Overview')
    pdf.section_kv("Domain", target.domain)
    pdf.section_kv("Target ID", target.id)
    pdf.section_kv("Scan Status", target.scan_status)
    pdf.section_kv("Scan Progress", f"{target.scan_progress}%" if target.scan_progress else "N/A")
    pdf.section_kv("Created At", target.created_at.strftime("%Y-%m-%d %H:%M:%S") if target.created_at else "N/A")

    # 2. DNS Analysis
    pdf.chapter_title('DNS Analysis')
    if dns and dns.data:
        ip_records = dns.data.get("a_records", [])
        mx_records = dns.data.get("mx_records", [])
        txt_records = dns.data.get("txt_records", [])
        cname_records = dns.data.get("cname_records", [])
        ns_records = dns.data.get("ns_records", [])
        soa_records = dns.data.get("soa_records", [])
        subdomains = dns.data.get("subdomains", [])
        
        pdf.section_kv("A Records", ", ".join(ip_records) if ip_records else "None")
        pdf.section_kv("MX Records", ", ".join(mx_records) if mx_records else "None")
        pdf.section_kv("NS Records", ", ".join(ns_records) if ns_records else "None")
        pdf.section_kv("CNAME Records", ", ".join(cname_records) if cname_records else "None")
        pdf.section_kv("SOA Records", ", ".join(soa_records) if soa_records else "None")
        
        if txt_records:
             pdf.section_header("TXT Records")
             pdf.set_font('Courier', '', 8)
             for txt in txt_records:
                 if pdf.get_y() > 270: pdf.add_page()
                 pdf.set_x(pdf.l_margin)
                 pdf.multi_cell(0, 4, txt)
                 pdf.ln(1)

        if subdomains:
            pdf.section_header(f"Subdomains Found ({len(subdomains)})")
            pdf.set_font('Helvetica', '', 9)
            for s in subdomains:
                if pdf.get_y() > 270: pdf.add_page()
                line = f"- {s.get('subdomain')} ({', '.join(s.get('ips', []))})"
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 5, line)
    else:
        pdf.content_text("No DNS data available.")
    
    # 3. Web Analysis
    pdf.chapter_title('Web Analysis')
    if web and web.data:
        pdf.section_kv("Title", web.data.get("title", "No Title"))
        pdf.section_kv("Server", web.data.get("server_header", "Unknown"))
        pdf.section_kv("Status Code", web.data.get("status_code", "Unknown"))
        
        tech = web.data.get("technologies", [])
        pdf.section_kv("Technologies", ", ".join(tech) if tech else "None detected")
        
        headers_dict = web.data.get("http_headers", {})
        if headers_dict:
            pdf.section_header("HTTP Headers")
            pdf.set_font('Courier', '', 8)
            for k, v in headers_dict.items():
                if pdf.get_y() > 270: pdf.add_page()
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 4, f"{k}: {v}")
                
        redirects = web.data.get("redirect_chain", [])
        if redirects:
            pdf.section_header("Redirect Chain")
            pdf.set_font('Helvetica', '', 9)
            for r in redirects:
                 if pdf.get_y() > 270: pdf.add_page()
                 pdf.set_x(pdf.l_margin)
                 pdf.cell(0, 5, f"-> {r}", ln=True)
                 
        risk = web.data.get("risk_hints", [])
        if risk:
            pdf.section_header("Risk Indicators")
            pdf.set_text_color(200, 50, 50)
            pdf.set_font('Helvetica', 'B', 9)
            for r in risk:
                if pdf.get_y() > 270: pdf.add_page()
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 5, f"[!] {r}")
            pdf.set_text_color(0, 0, 0)
            
    else:
        pdf.content_text("No Web analysis data available.")
    
    # 4. SSL Configuration
    pdf.chapter_title('SSL Configuration')
    if ssl and ssl.data:
        if ssl.data.get("error"):
            pdf.set_text_color(200, 50, 50)
            pdf.content_text(f"Error: {ssl.data.get('error')}")
            pdf.set_text_color(0, 0, 0)
        else:
            issuer = safe_get(ssl.data, "issuer", "commonName")
            org = safe_get(ssl.data, "issuer", "organizationName")
            
            subject_cn = safe_get(ssl.data, "subject", "commonName")
            
            pdf.section_kv("Issued To", subject_cn)
            pdf.section_kv("Issued By", f"{issuer} ({org})")
            pdf.section_kv("Valid From", ssl.data.get("notBefore"))
            pdf.section_kv("Valid To", ssl.data.get("notAfter"))
            
            sans = ssl.data.get("subjectAltName", [])
            if sans:
                 pdf.section_header(f"Subject Alternative Names ({len(sans)})")
                 pdf.set_font('Helvetica', '', 8)
                 # Join them into a block of text
                 sans_text = ", ".join([s[1] for s in sans])
                 pdf.set_x(pdf.l_margin)
                 pdf.multi_cell(0, 4, sans_text)

    else:
        pdf.content_text("No SSL data available.")

    # 5. Infrastructure
    pdf.chapter_title('Infrastructure')
    if infra and infra.data:
        asn = safe_get(infra.data, "asn", "asn")
        org = safe_get(infra.data, "asn", "asn_description")
        country = safe_get(infra.data, "geoip", "country_name")
        cloud = infra.data.get("cloud_provider", "Unknown")
        
        pdf.section_kv("IP Address", infra.data.get("ip"))
        pdf.section_kv("ASN", f"{asn} ({org})")
        pdf.section_kv("Location", country)
        pdf.section_kv("Cloud Provider", cloud)
        
        buckets = infra.data.get("buckets", [])
        if buckets:
             pdf.section_header("Storage Buckets")
             pdf.set_font('Helvetica', '', 9)
             for b in buckets:
                 if pdf.get_y() > 270: pdf.add_page()
                 status = b.get('status')
                 pdf.set_x(pdf.l_margin)
                 pdf.multi_cell(0, 5, f"- {b.get('url')} [{status}]")

    else:
        pdf.content_text("No Infrastructure data available.")

    # 6. Typosquatting
    pdf.chapter_title('Typosquatting')
    if typosquat and typosquat.data:
        found = typosquat.data.get("found", [])
        scanned = typosquat.data.get("scanned_count", 0)
        total = typosquat.data.get("total_variations", 0)
        
        pdf.section_kv("Variations Checked", f"{scanned} / {total}")
        pdf.section_kv("Suspicious Found", len(found))
        
        if found:
            pdf.ln(2)
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 5, "Detected Squats:", new_x="LMARGIN", new_y="NEXT")
            
            # Simple table for squats
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(60, 6, "Domain", border=1)
            pdf.cell(40, 6, "IP", border=1)
            pdf.cell(60, 6, "Registrar/Info", border=1)
            pdf.ln()
            
            pdf.set_font('Helvetica', '', 8)
            for sq in found:
                domain = str(sq.get('domain', ''))[:35]
                ip = str(sq.get('ip', ''))[:20]
                info = str(sq.get('fuzzer', ''))[:35]
                
                pdf.cell(60, 6, domain, border=1)
                pdf.cell(40, 6, ip, border=1)
                pdf.cell(60, 6, info, border=1)
                pdf.ln()
    else:
        pdf.chapter_body("No Typosquatting data available.")

    # 7. Visual OSINT
    pdf.chapter_title('Visual OSINT')
    if visual and visual.data:
        logos = visual.data.get("logos", [])
        if logos:
             pdf.section_kv("Logos Found", len(logos))
             pdf.ln()
             for logo in logos:
                 pdf.set_font('Helvetica', '', 9)
                 pdf.multi_cell(0, 5, f" - {logo.get('source')} ({logo.get('type')}): {logo.get('url')}")
        else:
             pdf.chapter_body("No external visual identity found.")
    else:
        pdf.chapter_body("No Visual OSINT data available.")

    # Output
    output_pdf = BytesIO(pdf.output()) 
    
    headers = {
        'Content-Disposition': f'attachment; filename="target_{target.domain}_report.pdf"'
    }
    return StreamingResponse(output_pdf, headers=headers, media_type='application/pdf')


from yads.core.compliance import calculate_security_grade, generate_compliance_report

@app.get("/targets/{target_id}", response_class=HTMLResponse)
async def view_target_detail(request: Request, target_id: int, history_id: Optional[int] = None, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Fetch all results for history list (limit 50 mostly for brevity)
    history_entries = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc()).limit(50)).all()
    
    # Determine which results to show
    current_results = []
    
    if history_id:
        # User requested specific historic entry
        # For simplicity in this tailored logic: if history_id is for a DNS result, we'll try to find a Web result close to it (same "run")
        # But this basic app stores them as separate rows.
        # IMPROVED LOGIC: 
        # If history_id is provided, we fetch THAT specific result.
        # But we also need the "complementary" result (e.g. if viewing DNS, we might want to see the Web result from same time).
        # For this iteration: We just highlight the requested one, and show latest for others OR try to find closest in time.
        # Let's keep it simple: Show the specifically requested result as the "Main" one for its type.
        
        target_result = session.get(ScanResult, history_id)
        if target_result and target_result.target_id == target_id:
            current_results = [target_result]
            # Try to populate the OTHER type with the result closest in time to `target_result`
            other_type = 'web_analyzer' if target_result.module_name == 'dns_scanner' else 'dns_scanner'
            
            # Find closest
            # This is a bit complex in pure SQLModel without complex filtering, so we'll do a loose search or just fetch latest of other type.
            # Loose search:
            closest_other = session.exec(select(ScanResult).where(
                ScanResult.target_id == target_id,
                ScanResult.module_name == other_type,
                ScanResult.scanned_at <= target_result.scanned_at # Closest previous or same time
            ).order_by(ScanResult.scanned_at.desc()).limit(1)).first()
            
            if closest_other:
                current_results.append(closest_other)
        else:
            # Fallback
             current_results = history_entries 
    else:
    # Default: Latest results (derived from the history list we already fetched)
        # We need latest of EACH type.
        latest_subdomain = next((r for r in history_entries if r.module_name == 'subdomain_scanner'), None)
        latest_dns = next((r for r in history_entries if r.module_name == 'dns_scanner'), None)
        latest_web = next((r for r in history_entries if r.module_name == 'web_analyzer'), None)
        latest_typosquat = next((r for r in history_entries if r.module_name == 'typosquat_scanner'), None)
        latest_infra = next((r for r in history_entries if r.module_name == 'infrastructure_scanner'), None)
        latest_visual = next((r for r in history_entries if r.module_name == 'visual_osint'), None)
        latest_ssl = next((r for r in history_entries if r.module_name == 'ssl_scanner'), None)
        latest_wayback = next((r for r in history_entries if r.module_name == 'wayback_scanner'), None)
        latest_crawler = next((r for r in history_entries if r.module_name == 'crawler'), None)
        latest_cd = next((r for r in history_entries if r.module_name == 'content_discovery'), None)
        latest_tld = next((r for r in history_entries if r.module_name == 'tld_scanner'), None)
        latest_port = next((r for r in history_entries if r.module_name == 'port_scanner'), None)
        latest_nmap = next((r for r in history_entries if r.module_name == 'nmap_scanner'), None)
        latest_nuclei = next((r for r in history_entries if r.module_name == 'nuclei_scanner'), None)
        latest_seed_files = next((r for r in history_entries if r.module_name == 'seed_files_scanner'), None)
        latest_csp = next((r for r in history_entries if r.module_name == 'csp_scanner'), None)

        current_results = [r for r in [latest_subdomain, latest_dns, latest_web, latest_typosquat, latest_infra, latest_visual, latest_ssl, latest_wayback, latest_crawler, latest_cd, latest_tld, latest_port, latest_nmap, latest_nuclei, latest_seed_files, latest_csp] if r]

    
    # Extract specific results for template
    # Extract specific results for template
    # Prioritize subdomain_scanner for DNS view as it contains everything + subdomains
    subdomain_result = next((r for r in current_results if r.module_name == 'subdomain_scanner'), None)
    dns_only_result = next((r for r in current_results if r.module_name == 'dns_scanner'), None)
    dns_result = subdomain_result if subdomain_result else dns_only_result

    web_result = next((r for r in current_results if r.module_name == 'web_analyzer'), None)
    typosquat_result = next((r for r in current_results if r.module_name == 'typosquat_scanner'), None)
    infra_result = next((r for r in current_results if r.module_name == 'infrastructure_scanner'), None)
    visual_result = next((r for r in current_results if r.module_name == 'visual_osint'), None)
    ssl_result = next((r for r in current_results if r.module_name == 'ssl_scanner'), None)
    wayback_result = next((r for r in current_results if r.module_name == 'wayback_scanner'), None)
    crawler_result = next((r for r in current_results if r.module_name == 'crawler'), None)
    content_discovery_result = next((r for r in current_results if r.module_name == 'content_discovery'), None)
    tld_result = next((r for r in current_results if r.module_name == 'tld_scanner'), None)
    port_result = next((r for r in current_results if r.module_name == 'port_scanner'), None)
    nmap_result = next((r for r in current_results if r.module_name == 'nmap_scanner'), None)
    nuclei_result = next((r for r in current_results if r.module_name == 'nuclei_scanner'), None)
    seed_files_result = next((r for r in current_results if r.module_name == 'seed_files_scanner'), None)
    csp_result = next((r for r in current_results if r.module_name == 'csp_scanner'), None)

    # -- Compliance & Grading --
    comp_input = {
        "web_result": web_result,
        "ssl_result": ssl_result,
        "nmap_result": nmap_result,
        "nuclei_result": nuclei_result,
        "port_result": port_result
    }
    security_grade = calculate_security_grade(comp_input)
    compliance_report = generate_compliance_report(comp_input)

    # -- Cipher Compliance Setup --
    from yads.models import SystemConfig
    approved_ciphers_set = set()
    ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
    raw_ac = ""
    if ac_conf:
        raw_ac = ac_conf.value
    else:
        try:
             import os
             if os.path.exists("ciphers.csv"):
                with open("ciphers.csv", "r") as f:
                    raw_ac = f.read()
        except:
            pass
    
    if raw_ac:
        for line in raw_ac.splitlines():
             parts = line.split(',')
             if len(parts) >= 2:
                cipher_name = parts[1].strip()
                if cipher_name and cipher_name.lower() != "cipherset":
                    approved_ciphers_set.add(cipher_name)

    # Fetch Schedule
    from yads.models import ScanSchedule
    schedule = session.exec(select(ScanSchedule).where(ScanSchedule.target_id == target_id)).first()
    
    return templates.TemplateResponse("target_detail.html", {
        "user": user,
        "request": request,
        "target": target,
        "dns_result": dns_result,
        "web_result": web_result,
        "typosquat_result": typosquat_result,
        "infra_result": infra_result,
        "visual_result": visual_result,
        "ssl_result": ssl_result,
        "wayback_result": wayback_result,
        "crawler_result": crawler_result,
        "content_discovery_result": content_discovery_result,
        "tld_result": tld_result,
        "port_result": port_result,
        "nmap_result": nmap_result,
        "nuclei_result": nuclei_result,
        "seed_files_result": seed_files_result,
        "csp_result": csp_result,
        "security_grade": security_grade,
        "compliance_report": compliance_report,
        "history_entries": history_entries, # Pass full history
        "current_history_id": history_id,
        "raw_results": jsonable_encoder([r.model_dump() for r in current_results]),
        "approved_ciphers": approved_ciphers_set,
        "schedule": schedule
    })




# -- API Endpoints (Legacy/JSON) --

@app.post("/api/targets/", response_model=Target)
def add_target(domain: str, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    domain = domain.lower().strip()
    existing = session.exec(select(Target).where(Target.domain == domain)).first()
    if existing:
        target = existing
    else:
        target = Target(domain=domain, tenant_id=user.tenant_id)
        session.add(target)
        session.commit()
        session.refresh(target)
    
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, None, target.tenant_id])
    return target

@app.get("/api/targets/", response_model=List[Target])
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target)).all()

@app.get("/api/targets/{target_id}/traffic")
def get_target_traffic(
    target_id: int, 
    session: Session = Depends(get_session), 
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
    limit: int = Query(100, le=1000),
    offset: int = Query(0)
):
    """
    Returns historical HTTP traffic for a specific target.
    """
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    traffic = session.exec(
        select(HTTPTraffic)
        .where(HTTPTraffic.target_id == target_id)
        .order_by(HTTPTraffic.timestamp.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    
    return traffic

@app.post("/api/targets/{target_id}/traffic/{traffic_id}/replay")
def replay_traffic(
    target_id: int, 
    traffic_id: int,
    session: Session = Depends(get_session), 
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """
    Re-executes a captured HTTP request and returns the result.
    """
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    traffic = session.get(HTTPTraffic, traffic_id)
    if not traffic or traffic.target_id != target_id:
        raise HTTPException(status_code=404, detail="Traffic log not found")
        
    import requests
    import time
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    start_time = time.time()
    try:
        # Filter headers that might cause issues during replay (like host-specific or length)
        headers = {k: v for k, v in (traffic.request_headers or {}).items() if k.lower() not in ['content-length', 'host']}
        
        response = requests.request(
            method=traffic.method,
            url=traffic.url,
            headers=headers,
            timeout=10,
            verify=False
        )
        duration = round(time.time() - start_time, 2)
        
        return {
            "status_code": response.status_code,
            "duration": duration,
            "response_headers": dict(response.headers),
            "response_body_snippet": response.text[:5000]
        }
    except Exception as e:
        return {
            "status_code": 0,
            "duration": round(time.time() - start_time, 2),
            "error": str(e)
        }

@app.get("/api/targets/{target_id}", response_model=Target)
def get_target(target_id: int, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@app.get("/api/targets/{target_id}/results")
def get_target_results(target_id: int, session: Session = Depends(get_session)):
    results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc())).all()
    return results

@app.post("/api/targets/{target_id}/brand-hunt")
def brand_hunt(target_id: int, logo_url: str = Body(..., embed=True), session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """
    Triggers a visual comparison between a reference logo and identified typosquat domains.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Get latest typosquat results
    ts_result = session.exec(select(ScanResult).where(
        ScanResult.target_id == target_id,
        ScanResult.module_name == "typosquat_scanner"
    ).order_by(ScanResult.scanned_at.desc())).first()
    
    if not ts_result or not ts_result.data or not ts_result.data.get("found"):
        return {"message": "No typosquat candidates found to hunt against.", "matches": []}
        
    candidates = ts_result.data.get("found", [])
    
    monitor = BrandMonitor()
    # This might take a few seconds, but since its a "Hunt" action, blocking slightly is okay-ish for MVP.
    # ideally async or task, but for <50 squats usually fine.
    # If many, we should background task it. But user wants "feature to select... and search".
    # Let's run it synchronously for immediate feedback as requested, unless it times out.
    matches = monitor.hunt_lookalikes(logo_url, candidates)
    
    return {"matches": matches, "count": len(matches)}

# -- Brand Logo Management --

@app.post("/targets/{target_id}/logo")
async def set_target_logo(
    target_id: int, 
    logo_url: str = Form(...), 
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "scanner"]))
):
    """
    Sets the primary brand logo for a target.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    target.brand_logo_url = logo_url.strip()
    session.add(target)
    session.commit()
    
    return RedirectResponse(url=f"/targets/{target_id}?msg=Logo+updated", status_code=303)

@app.post("/targets/{target_id}/logo/upload")
async def upload_target_logo(
    target_id: int, 
    file: UploadFile = File(...), 
    session: Session = Depends(get_session)
):
    """
    Uploads a custom logo file and sets it as primary.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Validate
    if not file.content_type.startswith("image/"):
        return RedirectResponse(url=f"/targets/{target_id}?error=Invalid+file+type", status_code=303)
        
    # Save
    import shutil
    import uuid
    
    ext = file.filename.split('.')[-1].lower() if '.' in file.filename else "png"
    if ext not in ["png", "jpg", "jpeg", "svg", "webp", "ico"]:
        return RedirectResponse(url=f"/targets/{target_id}?error=Invalid+extension", status_code=303)
        
    filename = f"logo_{target_id}_{uuid.uuid4().hex[:8]}.{ext}"
    upload_dir = "yads/api/static/logos"
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Update Target
        # URL path is relative to static root
        logo_url = f"/static/logos/{filename}"
        target.brand_logo_url = logo_url
        session.add(target)
        session.commit()
        
        return RedirectResponse(url=f"/targets/{target_id}?msg=Logo+uploaded", status_code=303)
    except Exception as e:
         logger.error(f"Logo upload failed: {e}")
         return RedirectResponse(url=f"/targets/{target_id}?error=Upload+failed", status_code=303)

# -- Settings Routes --

@app.post("/admin/tools/nuclei-update")
async def admin_nuclei_update(request: Request, user: User = Depends(RoleChecker(["admin"]))):
    """
    Manually triggers 'nuclei -ut' to update vulnerability templates.
    """
    import subprocess
    logger.info(f"Admin {user.username} triggered Nuclei template update.")
    try:
        # Run update command
        proc = subprocess.Popen(["nuclei", "-ut"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=600) # 10 min timeout
        
        if proc.returncode == 0:
            last_line = stdout.splitlines()[-1] if stdout.strip() else "Templates are up to date."
            return HTMLResponse(content=f'<div class="bg-green-900/40 border border-green-500/50 text-green-200 p-2 rounded text-[10px] mt-2 animate-fade-in">{last_line}</div>')
        else:
            return HTMLResponse(content=f'<div class="bg-red-900/40 border border-red-500/50 text-red-200 p-2 rounded text-[10px] mt-2 animate-fade-in">Update failed ({proc.returncode}): {stderr[:100]}</div>')
    except Exception as e:
        logger.error(f"Nuclei update failed: {e}")
        return HTMLResponse(content=f'<div class="bg-red-900/40 border border-red-500/50 text-red-200 p-2 rounded text-[10px] mt-2 animate-fade-in">Error: {str(e)}</div>')

@app.post("/admin/update/check", response_class=HTMLResponse)
async def manual_update_check(request: Request, user: User = Depends(RoleChecker(["admin"]))):
    """
    Manually triggers an update check (HTMX).
    """
    try:
        # Use global redis_client
        r = redis_client
        r.delete(UpdateService.CACHE_KEY)

        update = UpdateService.check_for_updates()
        if update:
            return HTMLResponse(content=f'''
                <div class="bg-indigo-900/40 border border-indigo-500/50 p-4 rounded-xl animate-fade-in">
                    <div class="flex items-center gap-3">
                        <div class="p-2 bg-indigo-500/20 rounded-lg text-indigo-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        </div>
                        <div>
                            <p class="text-sm font-bold text-white">YADS Update Available: v{update['version']}</p>
                            <p class="text-xs text-indigo-300 mt-1">{update['text']}</p>
                            <a href="{update['url']}" target="_blank" class="inline-block mt-3 text-xs font-bold text-indigo-400 hover:text-indigo-300 underline uppercase tracking-wider">Download & Patch</a>
                        </div>
                    </div>
                </div>
            ''')
        else:
            return HTMLResponse(content=f'''
                <div class="bg-slate-800/50 border border-slate-700 p-4 rounded-xl animate-fade-in">
                    <div class="flex items-center gap-3">
                        <div class="p-2 bg-green-500/10 rounded-lg text-green-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                        </div>
                        <div>
                            <p class="text-sm font-bold text-white">System Up to Date</p>
                            <p class="text-xs text-slate-400">You are running the latest version (v{settings.VERSION}).</p>
                        </div>
                    </div>
                </div>
            ''')
    except Exception as e:
        return HTMLResponse(content=f'''
            <div class="bg-red-900/40 border border-red-500/50 p-4 rounded-xl text-red-200 text-xs animate-fade-in">
                Update check failed: {str(e)}
            </div>
        ''')

@app.get("/settings", response_class=HTMLResponse)
async def view_settings(request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin"]))):
    from yads.models import SystemConfig, Tenant

    # Fetch tenants for Export UI
    allowed_tenants = session.exec(select(Tenant).order_by(Tenant.name)).all()
    
    # Defaults
    auto_queue = settings.AUTO_QUEUE_SUBDOMAINS
    rate_limit = settings.SCAN_QUEUE_RATE_LIMIT
    web_request_delay = 2.0
    worker_concurrency = 4 # Default if not set
    session_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    otp_window = 1
    
    # Load from DB
    aq_conf = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
    if aq_conf:
        auto_queue = aq_conf.value.lower() == 'true'
        
    rl_conf = session.get(SystemConfig, "SCAN_QUEUE_RATE_LIMIT")
    if rl_conf:
        rate_limit = rl_conf.value

    # Web Timeout
    web_request_timeout = settings.WEB_REQUEST_TIMEOUT
    wt_conf = session.get(SystemConfig, "WEB_REQUEST_TIMEOUT")
    if wt_conf:
         try:
             web_request_timeout = int(wt_conf.value)
         except:
             pass

    wrd_conf = session.get(SystemConfig, "WEB_RATE_LIMIT_DELAY")
    if wrd_conf:
        try:
            web_request_delay = float(wrd_conf.value)
        except:
             pass

    wc_conf = session.get(SystemConfig, "WORKER_CONCURRENCY")
    if wc_conf:
        try:
            worker_concurrency = int(wc_conf.value)
        except:
            pass
        


    # Session Config
    sm_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
    if sm_conf:
        try:
            session_minutes = int(sm_conf.value)
        except:
             pass

    otp_conf = session.get(SystemConfig, "OTP_VALID_WINDOW")
    if otp_conf:
        try:
            otp_window = int(otp_conf.value)
        except:
            pass

    # Load Approved Ciphers
    approved_ciphers = ""
    ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
    if ac_conf:
        approved_ciphers = ac_conf.value
    else:
        # Default load
        try:
             import os
             if os.path.exists("ciphers.csv"):
                with open("ciphers.csv", "r") as f:
                    approved_ciphers = f.read()
        except:
            pass

    # Load Custom DNS
    custom_dns_servers = ""
    dns_conf = session.get(SystemConfig, "CUSTOM_DNS_SERVERS")
    if dns_conf:
        custom_dns_servers = dns_conf.value

    # Load Network Rate Limit
    network_rate_limit = ""
    nrl_conf = session.get(SystemConfig, "NETWORK_RATE_LIMIT")
    if nrl_conf:
        network_rate_limit = nrl_conf.value
        
    # Custom Wordlist Status
    has_custom_wordlist = False
    custom_wordlist_lines = 0
    default_wordlist_count = 18 # Default fallback list size
    try:
        # Use BASE_DIR from settings for robust path resolution
        # yads/data/wordlists/subdomains.txt
        wordlist_path = os.path.join(settings.BASE_DIR, "data", "wordlists", "subdomains.txt")
        
        # Fallback for Docker environment if path resolution is weird
        if not os.path.exists(wordlist_path):
            wordlist_path = "/app/yads/data/wordlists/subdomains.txt"
        
        if os.path.exists(wordlist_path):
            has_custom_wordlist = True
            with open(wordlist_path, 'rb') as f:
                custom_wordlist_lines = sum(1 for _ in f)
    except:
        pass

    # Nuclei Update Status
    nuclei_last_updated = "Never"
    try:
        nuclei_path = "/root/nuclei-templates"
        if os.path.exists(nuclei_path):
             # Check modification time
             mtime = os.path.getmtime(nuclei_path)
             nuclei_last_updated = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
    except:
        pass

    # Splunk Config
    splunk_hec_url = ""
    splunk_hec_token = ""
    su_conf = session.get(SystemConfig, "SPLUNK_HEC_URL")
    if su_conf: splunk_hec_url = su_conf.value
    st_conf = session.get(SystemConfig, "SPLUNK_HEC_TOKEN")
    if st_conf: splunk_hec_token = st_conf.value

    # Email Config
    smtp_host = ""
    smtp_port = ""
    smtp_user = ""
    smtp_password = ""
    
    sh_conf = session.get(SystemConfig, "SMTP_HOST")
    if sh_conf: smtp_host = sh_conf.value
    
    sp_conf = session.get(SystemConfig, "SMTP_PORT")
    if sp_conf: smtp_port = sp_conf.value
    
    suser_conf = session.get(SystemConfig, "SMTP_USER")
    if suser_conf: smtp_user = suser_conf.value
    
    spass_conf = session.get(SystemConfig, "SMTP_PASSWORD")
    if spass_conf: smtp_password = spass_conf.value

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # --- License Info ---
    from yads.core.license import license_manager
    license_conf = session.get(SystemConfig, "license_key")
    license_data = None
    license_status = "Free Tier (Limit 5)"
    license_limit = 5

    if license_conf and license_conf.value:
        data = license_manager.verify(license_conf.value)
        if data:
            license_data = data
            license_limit = data.get("max_targets", 0)
            exp_date = datetime.fromtimestamp(data.get("exp", 0)).strftime("%Y-%m-%d")
            license_status = f"Valid (Customer: {data.get('sub')}, Expires: {exp_date})"
        else:
            license_status = "Invalid / Expired"

    # --- TLS/SSL Certificate Settings ---
    https_only = False
    custom_ca_cert_path = ""
    client_cert_path = ""
    client_key_path = ""
    verify_ssl = True

    # Environment variable override status
    https_only_env_override = settings.DISABLE_HTTPS_ONLY

    https_conf = session.get(SystemConfig, "HTTPS_ONLY")
    if https_conf:
        https_only = https_conf.value.lower() == "true"

    ca_conf = session.get(SystemConfig, "CUSTOM_CA_CERT_PATH")
    if ca_conf:
        custom_ca_cert_path = ca_conf.value

    cc_conf = session.get(SystemConfig, "CLIENT_CERT_PATH")
    if cc_conf:
        client_cert_path = cc_conf.value

    ck_conf = session.get(SystemConfig, "CLIENT_KEY_PATH")
    if ck_conf:
        client_key_path = ck_conf.value

    vs_conf = session.get(SystemConfig, "VERIFY_SSL")
    if vs_conf:
        verify_ssl = vs_conf.value.lower() != "false"

    # Validate certificate files
    tls_validation = {"valid": True, "errors": [], "warnings": []}
    if custom_ca_cert_path and not os.path.exists(custom_ca_cert_path):
        tls_validation["errors"].append(f"CA certificate not found: {custom_ca_cert_path}")
        tls_validation["valid"] = False
    if client_cert_path and not os.path.exists(client_cert_path):
        tls_validation["errors"].append(f"Client certificate not found: {client_cert_path}")
        tls_validation["valid"] = False
    if client_key_path and not os.path.exists(client_key_path):
        tls_validation["errors"].append(f"Client key not found: {client_key_path}")
        tls_validation["valid"] = False
    if bool(client_cert_path) != bool(client_key_path):
        tls_validation["errors"].append("Client certificate and key must both be provided")
        tls_validation["valid"] = False

    # --- Distributed Worker Settings ---
    global_max_concurrent_scans = 50
    global_max_network_mbps = 500

    gmcs_conf = session.get(SystemConfig, "GLOBAL_MAX_CONCURRENT_SCANS")
    if gmcs_conf:
        try:
            global_max_concurrent_scans = int(gmcs_conf.value)
        except:
            pass

    gmnm_conf = session.get(SystemConfig, "GLOBAL_MAX_NETWORK_MBPS")
    if gmnm_conf:
        try:
            global_max_network_mbps = float(gmnm_conf.value)
        except:
            pass

    # --- Prometheus Metrics Settings ---
    metrics_enabled = settings.METRICS_ENABLED
    metrics_auth_mode = settings.METRICS_AUTH_MODE
    metrics_token = settings.METRICS_TOKEN or ""
    metrics_include_tenant_labels = settings.METRICS_INCLUDE_TENANT_LABELS

    me_conf = session.get(SystemConfig, "METRICS_ENABLED")
    if me_conf:
        metrics_enabled = me_conf.value.lower() == "true"

    mam_conf = session.get(SystemConfig, "METRICS_AUTH_MODE")
    if mam_conf:
        metrics_auth_mode = mam_conf.value

    mt_conf = session.get(SystemConfig, "METRICS_TOKEN")
    if mt_conf:
        metrics_token = mt_conf.value

    mitl_conf = session.get(SystemConfig, "METRICS_INCLUDE_TENANT_LABELS")
    if mitl_conf:
        metrics_include_tenant_labels = mitl_conf.value.lower() == "true"

    return templates.TemplateResponse("settings.html", {
        "allowed_tenants": allowed_tenants,
        "user": user,
        "request": request,
        "auto_queue": auto_queue,
        "rate_limit": rate_limit,
        "web_request_delay": web_request_delay,
        "web_request_timeout": web_request_timeout,
        "worker_concurrency": worker_concurrency,
        "approved_ciphers": approved_ciphers,
        "custom_dns_servers": custom_dns_servers,
        "network_rate_limit": network_rate_limit,
        "has_custom_wordlist": has_custom_wordlist,
        "custom_wordlist_lines": custom_wordlist_lines,
        "session_minutes": session_minutes,
        "otp_window": otp_window,
        "splunk_hec_url": splunk_hec_url,
        "splunk_hec_token": splunk_hec_token,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_password": smtp_password,
        "license_key": license_conf.value if license_conf else "",
        "license_status": license_status,
        "license_data": license_data,
        "license_limit": license_limit,
        "global_max_concurrent_scans": global_max_concurrent_scans,
        "global_max_network_mbps": global_max_network_mbps,
        "default_wordlist_count": default_wordlist_count,
        "nuclei_last_updated": nuclei_last_updated,
        # TLS/SSL Settings
        "https_only": https_only,
        "https_only_env_override": https_only_env_override,
        "custom_ca_cert_path": custom_ca_cert_path,
        "client_cert_path": client_cert_path,
        "client_key_path": client_key_path,
        "verify_ssl": verify_ssl,
        "tls_validation": tls_validation,
        # Prometheus Metrics Settings
        "metrics_enabled": metrics_enabled,
        "metrics_auth_mode": metrics_auth_mode,
        "metrics_token": metrics_token,
        "metrics_include_tenant_labels": metrics_include_tenant_labels
    })

@app.post("/settings", response_class=HTMLResponse)
async def update_settings(
    request: Request,
    user: User = Depends(RoleChecker(["admin"])),
    auto_queue: bool = Form(False), 
    rate_limit: str = Form(None),
    web_request_delay: str = Form(None),
    web_request_timeout: int = Form(None),
    worker_concurrency: int = Form(4),
    session_minutes: int = Form(60),
    otp_window: int = Form(1),
    approved_ciphers: Optional[str] = Form(None),
    custom_dns_servers: str = Form(None),
    network_rate_limit: str = Form(None),
    splunk_hec_url: str = Form(None),
    splunk_hec_token: str = Form(None),
    smtp_host: str = Form(None),
    smtp_port: str = Form(None),
    smtp_user: Optional[str] = Form(None),
    smtp_password: Optional[str] = Form(None),
    
    # License
    license_key: Optional[str] = Form(None),

    # Distributed Worker Settings
    global_max_concurrent_scans: int = Form(50),
    global_max_network_mbps: float = Form(500),

    # TLS/SSL Settings
    https_only: bool = Form(False),
    custom_ca_cert_path: Optional[str] = Form(None),
    client_cert_path: Optional[str] = Form(None),
    client_key_path: Optional[str] = Form(None),
    verify_ssl: bool = Form(True),

    # Prometheus Metrics Settings
    metrics_enabled: bool = Form(False),
    metrics_auth_mode: str = Form("token"),
    metrics_token: Optional[str] = Form(None),
    metrics_include_tenant_labels: bool = Form(False),

    session: Session = Depends(get_session)
):
    from yads.models import SystemConfig
    from typing import Optional

    # Helper to upsert config
    def set_conf(k, v):
        conf = session.get(SystemConfig, k)
        if not conf:
            conf = SystemConfig(key=k, value=v)
            session.add(conf)
        else:
            conf.value = v
            session.add(conf)
            
    # Save License
    if license_key is not None:
        trimmed_lic = license_key.strip()
        set_conf("license_key", trimmed_lic)
        settings.LICENSE_KEY = trimmed_lic
        logger.info(f"Runtime License Key updated via UI.")
    
    # Update Auto Queue
    if auto_queue is not None: set_conf("AUTO_QUEUE_SUBDOMAINS", "true") 
    else: set_conf("AUTO_QUEUE_SUBDOMAINS", "false")
        
    # Rate Limit
    rl_conf = session.get(SystemConfig, "SCAN_QUEUE_RATE_LIMIT")
    if not rl_conf:
        rl_conf = SystemConfig(key="SCAN_QUEUE_RATE_LIMIT", value=rate_limit)
        session.add(rl_conf)
    else:
        rl_conf.value = rate_limit
        session.add(rl_conf)

    # Worker Concurrency
    wc_conf = session.get(SystemConfig, "WORKER_CONCURRENCY")
    if not wc_conf:
        wc_conf = SystemConfig(key="WORKER_CONCURRENCY", value=str(worker_concurrency))
        session.add(wc_conf)
    else:
        wc_conf.value = str(worker_concurrency)
        session.add(wc_conf)
        
    # Session Minutes
    sm_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
    if not sm_conf:
        sm_conf = SystemConfig(key="ACCESS_TOKEN_EXPIRE_MINUTES", value=str(session_minutes))
        session.add(sm_conf)
    else:
        sm_conf.value = str(session_minutes)
        session.add(sm_conf)

    # OTP Window
    otp_conf = session.get(SystemConfig, "OTP_VALID_WINDOW")
    if not otp_conf:
        otp_conf = SystemConfig(key="OTP_VALID_WINDOW", value=str(otp_window))
        session.add(otp_conf)
    else:
        otp_conf.value = str(otp_window)
        session.add(otp_conf)

    # Approved Ciphers
    if approved_ciphers is not None:
        # Normalize line endings
        approved_ciphers = approved_ciphers.replace("\r\n", "\n")
        ac_conf = session.get(SystemConfig, "APPROVED_CIPHERS")
        if not ac_conf:
             ac_conf = SystemConfig(key="APPROVED_CIPHERS", value=approved_ciphers)
             session.add(ac_conf)
        else:
             ac_conf.value = approved_ciphers
             session.add(ac_conf)
             
    # Custom DNS Servers
    if custom_dns_servers is not None:
         dns_conf = session.get(SystemConfig, "CUSTOM_DNS_SERVERS")
         if not dns_conf:
             dns_conf = SystemConfig(key="CUSTOM_DNS_SERVERS", value=custom_dns_servers)
             session.add(dns_conf)
         else:
             dns_conf.value = custom_dns_servers
             session.add(dns_conf)

    # Network Rate Limit
    if network_rate_limit is not None:
         nrl_conf = session.get(SystemConfig, "NETWORK_RATE_LIMIT")
         if not nrl_conf:
             nrl_conf = SystemConfig(key="NETWORK_RATE_LIMIT", value=network_rate_limit)
             session.add(nrl_conf)
         else:
             nrl_conf.value = network_rate_limit
             session.add(nrl_conf)

    # Distributed Worker Settings
    set_conf("GLOBAL_MAX_CONCURRENT_SCANS", str(global_max_concurrent_scans))
    set_conf("GLOBAL_MAX_NETWORK_MBPS", str(global_max_network_mbps))

    # TLS/SSL Settings
    set_conf("HTTPS_ONLY", "true" if https_only else "false")
    set_conf("VERIFY_SSL", "true" if verify_ssl else "false")

    if custom_ca_cert_path is not None:
        custom_ca_cert_path = custom_ca_cert_path.strip()
        set_conf("CUSTOM_CA_CERT_PATH", custom_ca_cert_path)

    if client_cert_path is not None:
        client_cert_path = client_cert_path.strip()
        set_conf("CLIENT_CERT_PATH", client_cert_path)

    if client_key_path is not None:
        client_key_path = client_key_path.strip()
        set_conf("CLIENT_KEY_PATH", client_key_path)

    # Prometheus Metrics Settings
    set_conf("METRICS_ENABLED", "true" if metrics_enabled else "false")
    set_conf("METRICS_AUTH_MODE", metrics_auth_mode)
    set_conf("METRICS_INCLUDE_TENANT_LABELS", "true" if metrics_include_tenant_labels else "false")

    if metrics_token is not None:
        metrics_token = metrics_token.strip()
        if metrics_token:  # Only save if non-empty
            set_conf("METRICS_TOKEN", metrics_token)

    session.commit()
    
    # Broadcast Updates
    
    # 1. Rate Limit
    if rate_limit:
        try:
             celery_app.control.rate_limit("yads.worker.run_all_scans", rate_limit)
        except Exception:
             pass

    # 3. Web Request Delay
    if web_request_delay:
        wrd_conf = session.get(SystemConfig, "WEB_RATE_LIMIT_DELAY")
        if not wrd_conf:
            wrd_conf = SystemConfig(key="WEB_RATE_LIMIT_DELAY", value=web_request_delay)
            session.add(wrd_conf)
        else:
            wrd_conf.value = web_request_delay
            session.add(wrd_conf)
        session.commit()

    # 4. Web Request Timeout
    if web_request_timeout:
        wt_conf = session.get(SystemConfig, "WEB_REQUEST_TIMEOUT")
        if not wt_conf:
             wt_conf = SystemConfig(key="WEB_REQUEST_TIMEOUT", value=str(web_request_timeout))
             session.add(wt_conf)
        else:
             wt_conf.value = str(web_request_timeout)
             session.add(wt_conf)
        session.commit()


    # 2. Worker Concurrency (Autoscale)
    try:
        # Set min=max to force fixed concurrency
        celery_app.control.autoscale(max=worker_concurrency, min=worker_concurrency)
    except Exception:
        pass

    return RedirectResponse(url="/settings?saved=true", status_code=303)

@app.post("/settings/wordlist/upload", response_class=RedirectResponse)
async def upload_custom_wordlist(
    wordlist_file: UploadFile = File(...), 
    session: Session = Depends(get_session)
):
    try:
        # Define path
        wordlist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists")
        os.makedirs(wordlist_dir, exist_ok=True)
        wordlist_path = os.path.join(wordlist_dir, "subdomains.txt")
        
        # Save file
        async with aiofiles.open(wordlist_path, 'wb') as out_file:
            while content := await wordlist_file.read(1024):
                await out_file.write(content)
                
        return RedirectResponse(url="/settings?saved=true&msg=Wordlist+Uploaded", status_code=303)
    except Exception as e:
        logger.error(f"Failed to upload wordlist: {e}")
        return RedirectResponse(url=f"/settings?error=Upload+Failed:+{str(e)}", status_code=303)

@app.post("/settings/wordlist/delete", response_class=RedirectResponse)
async def delete_custom_wordlist(session: Session = Depends(get_session)):
    try:
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "subdomains.txt")
        if os.path.exists(wordlist_path):
            os.remove(wordlist_path)
            
        return RedirectResponse(url="/settings?saved=true&msg=Custom+Wordlist+Deleted", status_code=303)
    except Exception as e:
        logger.error(f"Failed to delete wordlist: {e}")
        return RedirectResponse(url=f"/settings?error=Delete+Failed:+{str(e)}", status_code=303)

@app.post("/admin/reset", response_class=HTMLResponse)
async def admin_reset(session: Session = Depends(get_session)):
    """
    Resets the system:
    1. Purges Redis Queue
    2. Deletes DB Data (Targets, ScanResults, ModuleStates)
    """
    # 1. Purge & Kill Queue/Tasks
    try:
        # Purge waiting tasks
        celery_app.control.purge()
        
        # Revoke Active & Reserved Tasks
        i = celery_app.control.inspect()
        if i:
            active = i.active() or {}
            reserved = i.reserved() or {}
            
            # Combine all task IDs
            tasks_to_kill = []
            for worker_tasks in [active, reserved]:
                for worker, tasks in worker_tasks.items():
                    for task in tasks:
                         tasks_to_kill.append(task['id'])
            
            if tasks_to_kill:
                celery_app.control.revoke(tasks_to_kill, terminate=True)
                logger.warning(f"Reset: Revoked {len(tasks_to_kill)} active/reserved tasks.")
                
    except Exception as e:
        logger.error(f"Failed to purge queue: {e}")

    # 2. Delete Data
    # Truncate tables (Cascading usually handles it, but we do explicit delete for safety/clarity)
    session.exec(text("DELETE FROM changeevent"))
    session.exec(text("DELETE FROM scanresult"))
    session.exec(text("DELETE FROM modulestate"))
    session.exec(text("DELETE FROM target"))
    
    # 3. Clear Tenant Data (Requested by User)
    # Must preserve Users, but unlink them.
    session.exec(text('UPDATE "user" SET tenant_id = NULL'))
    session.exec(text("DELETE FROM usertenantlink"))
    session.exec(text("DELETE FROM tenant"))

    # 4. Re-Initialize Default Tenant -> REMOVED PER USER REQ
    # from yads.models import Tenant, UserTenantLink, User
    # default_tenant = Tenant(name="a customer")
    # session.add(default_tenant)
    # session.commit()
    # session.refresh(default_tenant)
    # logger.info("Reset: Re-created default tenant: a customer")
    
    # Auto-link 'admin' to default tenant -> REMOVED
    # admin = session.exec(select(User).where(User.username == "admin")).first()
    # if admin:
    #     session.add(UserTenantLink(user_id=admin.id, tenant_id=default_tenant.id))
    #     admin.tenant_id = default_tenant.id
    #     session.add(admin)
    #     session.commit()
    #     logger.info("Reset: Re-linked admin to default tenant.")

    # Reset Config? Maybe optional. Let's keep config.
    
    session.commit()
    
    logger.warning("System RESET executed by user.")
    
    return RedirectResponse(url="/settings?saved=true&msg=System+Reset+Complete", status_code=303)


# -- Table View & Bulk Actions --

    return RedirectResponse(url=f"/targets/table?msg=Queued+{count}+scans", status_code=303)

@app.get("/targets/export/excel")
async def export_targets_excel(session: Session = Depends(get_session)):
    """
    Generates an Excel report of all targets and their latest scan results.
    """
    import pandas as pd
    from io import BytesIO
    
    # Fetch all targets
    targets = session.exec(select(Target).order_by(Target.created_at.desc())).all()
    
    data = []
    for t in targets:
        # Fetch latest results for each module (simplified: could use window functions for speed)
        # We rely on lazy loading or simple queries here. For 100 targets it's okay.
        # Ideally: select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())
        # But we need one per module.
        
        row = {
            "ID": t.id,
            "Domain": t.domain,
            "Created At": t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Status": t.scan_status,
            "Progress": t.scan_progress or ""
        }
        
        # Helper to get latest module data
        results = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).all()
        
        # Modules: dns_scanner, ssl_scanner, web_analyzer, infrastructure_scanner, typosquat_scanner, visual_osint
        
        # DNS
        dns = next((r for r in results if r.module_name == 'dns_scanner'), None)
        if dns and dns.data:
            row["DNS_IP"] = dns.data.get("a_records", [""])[0] if dns.data.get("a_records") else ""
            row["DNS_Subs_Count"] = len(dns.data.get("subdomains", []))
            row["DNS_MX"] = ", ".join(dns.data.get("mx_records", []))
        else:
             row["DNS_IP"] = ""
             row["DNS_Subs_Count"] = 0
             row["DNS_MX"] = ""

        # SSL
        ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
        if ssl and ssl.data:
            if ssl.data.get("error"):
                 row["SSL_Issuer"] = "Error"
                 row["SSL_Expiry"] = ssl.data.get("error")
            else:
                row["SSL_Issuer"] = ssl.data.get("issuer", {}).get("commonName", "")
                row["SSL_Expiry"] = ssl.data.get("notAfter", "")
                row["SSL_SANs_Count"] = len(ssl.data.get("subjectAltName", []))
        else:
            row["SSL_Issuer"] = ""
            row["SSL_Expiry"] = ""
            row["SSL_SANs_Count"] = 0

        # Web
        web = next((r for r in results if r.module_name == 'web_analyzer'), None)
        if web and web.data:
            row["Web_Server"] = web.data.get("server_header", "")
            row["Web_Title"] = web.data.get("title", "")
            row["Web_Tech"] = ", ".join(web.data.get("technologies", []))
        else:
            row["Web_Server"] = ""
            row["Web_Title"] = ""
            row["Web_Tech"] = ""
            
         # Infra
        infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
        if infra and infra.data:
             row["Infra_ASN"] = infra.data.get("asn", {}).get("asn", "")
             row["Infra_Org"] = infra.data.get("asn", {}).get("asn_description", "")
             row["Infra_Country"] = infra.data.get("geoip", {}).get("country_name", "")
        else:
             row["Infra_ASN"] = ""
             row["Infra_Org"] = ""
             row["Infra_Country"] = ""

        data.append(row)

    df = pd.DataFrame(data)
    
    # Create Excel in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Targets')
        # Auto-adjust column width? Openpyxl can do this but requires more code.
        # Pandas default is fine for MVP.
        
    output.seek(0)
    
    headers = {
        'Content-Disposition': 'attachment; filename="yads_targets_export.xlsx"'
    }
    return StreamingResponse(output, headers=headers, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# --- Visualizations ---

@app.get("/api/visualizations/redirects")
async def get_redirect_graph(domain: str = None, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns graph data (nodes, edges) for the Redirect Spiderweb visualization.
    Optional: ?domain=example.com filter.
    """
    # Filter by user's tenant
    query = select(Target).where(Target.tenant_id == user.tenant_id)
    if domain:
        # Filter by specific domain (exact match on target)
        query = query.where(Target.domain == domain)
        
    targets = session.exec(query).all()
    
    nodes = {} # id -> {id, label, type, value(size)}
    edges = []
    
    # Helper to get/create node
    def get_or_create_node(url, node_type="unknown"):
        # Simplify URL for label (remove protocol)
        if not url: return "unknown"
        label = url.replace("https://", "").replace("http://", "").rstrip('/')
        node_id = label # Use label as ID for simplicity
        
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "group": node_type, # for vis-network styling
                "value": 1, # size
                "title": url # tooltip
            }
        else:
            # Upgrade type if we find a landing page
            if node_type == "landing" and nodes[node_id]["group"] != "landing":
                 nodes[node_id]["group"] = "landing"
                 
        return node_id

    for t in targets:
        # Get latest Web Scan
        scan = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "web_analyzer"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        if not scan or not scan.data:
            # Add orphan/unscanned target
            get_or_create_node(t.domain, "source")
            continue
            
        data = scan.data
        chain = data.get("redirect_chain", [])
        
        # Start Node (The Target)
        start_node = get_or_create_node(t.domain, "source")
        
        if not chain:
            pass
        else:
            # Process Chain
            prev_node = start_node
            
            for i, hop_url in enumerate(chain):
                # Determine type
                if i == len(chain) - 1:
                    ntype = "landing" 
                else:
                    ntype = "redirector"
                
                curr_node = get_or_create_node(hop_url, ntype)
                
                # Add Edge
                if prev_node != curr_node:
                    edges.append({
                        "from": prev_node,
                        "to": curr_node,
                        "arrows": "to"
                    })
                
                # Increase size of current node (more incoming links = bigger)
                nodes[curr_node]["value"] += 1
                
                prev_node = curr_node

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }

@app.get("/api/visualizations/redirects/centrality")
async def get_redirect_centrality(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Analyzes the redirect graph to find the most central node (highest degree).
    """
    # 1. Reconstruct Graph (Simplified Logic from get_redirect_graph)
    # We need to build the graph structure in memory to calculate degrees
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id)).all()
    
    # Adjacency List: Node -> {in: 0, out: 0}
    degrees = {}
    
    def touch_node(n):
        if n not in degrees: degrees[n] = {"in": 0, "out": 0}

    for t in targets:
        scan = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "web_analyzer"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        start_node = t.domain.replace("https://", "").replace("http://", "").rstrip('/')
        touch_node(start_node)
        
        if not scan or not scan.data: continue
        
        chain = scan.data.get("redirect_chain", [])
        if chain:
            prev_node = start_node
            for hop_url in chain:
                curr_node = hop_url.replace("https://", "").replace("http://", "").rstrip('/')
                touch_node(curr_node)
                
                if prev_node != curr_node:
                    degrees[prev_node]["out"] += 1
                    degrees[curr_node]["in"] += 1
                
                prev_node = curr_node

    if not degrees:
        return {"error": "No graph data available."}

    # 2. Find Max Degree (Centrality)
    # Score = In-Degree + Out-Degree (Total Connections)
    sorted_nodes = sorted(
        degrees.items(), 
        key=lambda item: (item[1]["in"] + item[1]["out"]), 
        reverse=True
    )
    
    top_node_id, stats = sorted_nodes[0]
    total_degree = stats["in"] + stats["out"]
    
    if total_degree == 0:
         return {"message": "Graph has no connections."}

    return {
        "node_id": top_node_id,
        "stats": {
            "total_connections": total_degree,
            "inbound": stats["in"],
            "outbound": stats["out"]
        }
    }

@app.get("/api/visualizations/network")
async def get_network_graph(
    target_id: Optional[int] = None, 
    filter_empty: bool = False,
    filter_online: str = "all",
    include_web_links: bool = False,
    max_nodes: int = 500,  # Limit for performance - prevents browser from crashing on large datasets
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Returns graph data (nodes, edges) for the Network Relationship visualization.
    Integrates DNS records and Subdomains.
    max_nodes: Maximum number of target nodes to process (default 500 for performance)
    """
    from sqlmodel import or_, and_, text
    from urllib.parse import urlparse
    
    # Filter by user's tenant
    if user.role == "admin" and not user.tenant_id:
        query = select(Target)
    else:
        query = select(Target).where(Target.tenant_id == user.tenant_id)
    
    # 1. Online/Offline Filter (using subquery to filter Targets)
    if filter_online != "all":
        online_criteria = or_(
             and_(ScanResult.module_name == 'infrastructure_scanner', text("data->>'ip' IS NOT NULL")),
             and_(ScanResult.module_name == 'web_analyzer', text("(data->>'status_code')::int > 0")),
             and_(ScanResult.module_name == 'port_scanner', text("data->>'is_active' = 'true'"))
        )
        sub_online = select(ScanResult.target_id).where(online_criteria).distinct()

        if filter_online == "online":
            query = query.where(Target.id.in_(sub_online))
        elif filter_online == "offline":
             sub_scanned = select(ScanResult.target_id).distinct()
             query = query.where(Target.id.in_(sub_scanned))
             query = query.where(Target.id.notin_(sub_online))

    if target_id:
        query = query.where(Target.id == target_id)
    
    # Get total count before limiting
    from sqlmodel import func as sqlfunc
    count_query = select(sqlfunc.count()).select_from(query.subquery())
    total_targets = session.exec(count_query).one()
    
    # Apply limit for performance
    query = query.limit(max_nodes)
    targets = session.exec(query).all()
    
    # Track if results were truncated
    truncated = total_targets > max_nodes
    
    nodes = {} # id -> node object (Cytoscape format: {data: {...}})
    edges = [] # list of edge objects (Cytoscape format: {data: {...}})
    
    # Track node risk for Attack Path
    risk_map = {} # node_id -> {is_compromised: bool, risk_score: int, reasons: []}
    
    def get_risk(nid):
        return risk_map.get(nid, {"is_compromised": False, "risk_score": 0, "reasons": []})
    
    # Pre-calculate Risks
    # Iterate scan results to find Critical/High Vulns, Expired Certs, Public Buckets
    target_ids = [t.id for t in targets]
    target_map = {t.id: t.domain for t in targets} # Map target_id to domain string for node ID
    
    if target_ids:
        results = session.exec(select(ScanResult).where(ScanResult.target_id.in_(target_ids))).all()
        
        for res in results:
            if res.target_id not in target_map: continue
            domain_node_id = target_map[res.target_id]
            
            risk_score = 0
            is_compromised = False
            reasons = []
            
            if res.module_name == 'ssl_scanner':
                 if res.data and res.data.get("expired"):
                      risk_score += 10
                      is_compromised = True
                      reasons.append("Expired SSL Certificate")
            elif res.module_name == 'infrastructure_scanner':
                 if res.data:
                     for b in res.data.get("buckets", []):
                          if b.get("status") == "Public":
                               risk_score += 8
                               is_compromised = True
                               reasons.append("Public Cloud Bucket")
            elif res.module_name == 'web_analyzer':
                 if res.data:
                     cves = res.data.get("cves", [])
                     for cve in cves:
                          try:
                               cvss = float(cve.get("cvss", 0))
                               if cvss >= 9.0:
                                    risk_score += 10
                                    is_compromised = True
                                    reasons.append("Critical Vulnerability")
                               elif cvss >= 7.0:
                                    risk_score += 5
                                    if not is_compromised: reasons.append("High Vulnerability")
                          except: pass

            elif res.module_name == 'deception_detector':
                 if res.data:
                     summary = res.data.get("summary", {})
                     overall_risk = summary.get("overall_risk", "none")
                     total_detections = summary.get("total_detections", 0)

                     if total_detections > 0:
                          # Deception indicates potential hostile or monitored infrastructure
                          if overall_risk == "critical":
                               risk_score += 15
                               is_compromised = True
                               reasons.append("Deception Infrastructure (Critical)")
                          elif overall_risk == "high":
                               risk_score += 10
                               is_compromised = True
                               reasons.append("Deception Infrastructure (High)")
                          elif overall_risk == "medium":
                               risk_score += 5
                               reasons.append("Deception Indicators (Medium)")
                          else:
                               risk_score += 2
                               reasons.append("Deception Indicators (Low)")

            if risk_score > 0:
                 if domain_node_id not in risk_map:
                      risk_map[domain_node_id] = {"is_compromised": False, "risk_score": 0, "reasons": []}
                 
                 risk_map[domain_node_id]["risk_score"] += risk_score
                 risk_map[domain_node_id]["is_compromised"] = risk_map[domain_node_id]["is_compromised"] or is_compromised
                 risk_map[domain_node_id]["reasons"].extend(reasons)

    # 2. Build Nodes for Targets
    for t_id in target_ids:
        domain = target_map[t_id]
        t_risk = get_risk(domain)
        
        nodes[domain] = {
            "data": {
                "id": domain,
                "label": domain,
                "type": "domain",
                "risk_score": t_risk["risk_score"], 
                "compromised": t_risk["is_compromised"],
                "risk_reasons": ", ".join(list(set(t_risk["reasons"])))
            }
        }
    
    # 3. Build Edges & Sub-Nodes
    for t_id in target_ids:
        # Fetch Scan Results for edges
        if not target_ids: break # Safety
        
        # Modules to fetch
        modules = ['dns_scanner', 'subdomain_scanner', 'infrastructure_scanner', 'web_analyzer', 'deception_detector']
        if include_web_links:
            modules.append('crawler')

        results = session.exec(select(ScanResult).where(
            ScanResult.target_id == t_id,
            ScanResult.module_name.in_(modules)
        ).order_by(ScanResult.scanned_at.desc())).all()
        
        latest_res = {}
        for r in results:
             if r.module_name not in latest_res: latest_res[r.module_name] = r
             
        source = target_map[t_id]
        source_risk = get_risk(source)
        
        for mod, res in latest_res.items():
            if not res.data: continue
            
            # DNS Edges
            if mod in ['dns_scanner', 'subdomain_scanner']:
                sub_nodes_to_add = set()

                if mod == 'dns_scanner':
                    # Main domain IPs
                     for ip in res.data.get("records", {}).get("A", []):
                        if ip not in nodes:
                            nodes[ip] = { "data": { "id": ip, "label": ip, "type": "ip", "risk_score": 0, "compromised": False } }
                        edges.append({ "data": { "source": source, "target": ip, "label": "resolves_to", "is_risk": source_risk["is_compromised"] } })
                
                if mod == 'subdomain_scanner':
                    for sub_entry in res.data.get("subdomains", []):
                        sub_name = sub_entry.get("subdomain")
                        if sub_name:
                            sub_nodes_to_add.add(sub_name)
                            # Also add IPs for subdomains
                            for ip in sub_entry.get("ips", []):
                                if ip not in nodes:
                                    nodes[ip] = { "data": { "id": ip, "label": ip, "type": "ip", "risk_score": 0, "compromised": False } }
                                edges.append({ "data": { "source": sub_name, "target": ip, "label": "resolves_to", "is_risk": source_risk["is_compromised"] } })

                for sub_id in sub_nodes_to_add:
                    risk = get_risk(sub_id)
                    is_risk_edge = source_risk["is_compromised"]

                    if sub_id not in nodes:
                        nodes[sub_id] = {
                            "data": {
                                "id": sub_id, 
                                "label": sub_id, 
                                "type": "subdomain",
                                "risk_score": risk["risk_score"], 
                                "compromised": risk["is_compromised"],
                                "risk_reasons": ", ".join(list(set(risk["reasons"])))
                            }
                        }
                    
                    edges.append({
                        "data": {
                            "source": source, 
                            "target": sub_id, 
                            "label": "subdomain",
                            "is_risk": is_risk_edge
                        }
                    })

            # Infra (IPs)
            elif mod == 'infrastructure_scanner':
                ip = res.data.get("ip")
                if ip:
                    is_risk_edge = source_risk["is_compromised"]
                    ip_risk = get_risk(ip)

                    if ip not in nodes:
                         nodes[ip] = {
                             "data": {
                                 "id": ip, "label": ip, "type": "ip",
                                 "risk_score": ip_risk["risk_score"], 
                                 "compromised": ip_risk["is_compromised"],
                                 "risk_reasons": ", ".join(list(set(ip_risk["reasons"])))
                            }
                        }
                    edges.append({
                        "data": {
                            "source": source, "target": ip, "label": "resolves_to",
                            "is_risk": is_risk_edge
                        }
                    })
            
            # Crawler (Links)
            elif mod == 'crawler':
                 edges_list = res.data.get("edges", [])
                 for link_edge in edges_list:
                      dst = link_edge.get("target")
                      if not dst: continue
                      try:
                           parsed = urlparse(dst)
                           if parsed.netloc:
                                dst_node = parsed.netloc
                                if dst_node == source: continue

                                # Filter: Only allow links TO scoped domains (Targets or their subdomains)
                                is_scoped = False
                                for t_obj in targets:
                                    t_domain = t_obj.domain
                                    # Check if dst is target or subdomain of target
                                    if dst_node == t_domain or dst_node.endswith("." + t_domain):
                                        is_scoped = True
                                        break
                                
                                if not is_scoped: continue

                                is_risk_edge = source_risk["is_compromised"]
                                dst_risk = get_risk(dst_node)

                                if dst_node not in nodes:
                                     nodes[dst_node] = {
                                         "data": {
                                             "id": dst_node, "label": dst_node, "type": "external",
                                             "risk_score": dst_risk["risk_score"], 
                                             "compromised": dst_risk["is_compromised"],
                                             "risk_reasons": ", ".join(list(set(dst_risk["reasons"])))
                                        }
                                    }
                                
                                edges.append({
                                    "data": {
                                        "source": source, "target": dst_node, "label": "links_to",
                                        "is_risk": is_risk_edge
                                    }
                                })
                      except: pass

            # Web Analyzer (Redirects)
            elif mod == 'web_analyzer':
                chain = res.data.get("redirect_chain", [])
                if chain:
                    prev_node = source
                    for i, hop_url in enumerate(chain):
                        # Clean URL
                        hop_node = hop_url.replace("https://", "").replace("http://", "").rstrip('/')
                        if hop_node == source: continue # Skip if same as source (e.g. self-redirect)
                        
                        is_risk_edge = source_risk["is_compromised"]
                        hop_risk = get_risk(hop_node)
                        
                        # Node Type
                        ntype = "redirector"
                        if i == len(chain) - 1: ntype = "landing"

                        if hop_node not in nodes:
                             nodes[hop_node] = {
                                 "data": {
                                     "id": hop_node, "label": hop_node, "type": ntype,
                                     "risk_score": hop_risk["risk_score"],
                                     "compromised": hop_risk["is_compromised"],
                                     "risk_reasons": ", ".join(list(set(hop_risk["reasons"])))
                                }
                            }
                        
                        # Add Edge
                        edges.append({
                            "data": {
                                "source": prev_node, "target": hop_node, "label": "redirects_to",
                                "is_risk": is_risk_edge
                            }
                        })
                        
                        prev_node = hop_node

            # Deception Detector (Honeypots, Sinkholes, Tarpits)
            elif mod == 'deception_detector':
                summary = res.data.get("summary", {})
                total_detections = summary.get("total_detections", 0)

                if total_detections > 0:
                    # Add honeypot nodes
                    for hp in res.data.get("honeypots", []):
                        hp_name = hp.get("name", "Unknown")
                        hp_type = hp.get("type", "generic")
                        hp_conf = hp.get("confidence", 0)
                        hp_port = hp.get("port", 0)
                        hp_id = f"honeypot_{source}_{hp_port}"

                        if hp_id not in nodes:
                            nodes[hp_id] = {
                                "data": {
                                    "id": hp_id,
                                    "label": f"Honeypot: {hp_name}",
                                    "type": "honeypot",
                                    "risk_score": hp_conf,
                                    "compromised": hp_conf >= 70,
                                    "risk_reasons": hp.get("indicator", "")
                                }
                            }
                        edges.append({
                            "data": {
                                "source": source,
                                "target": hp_id,
                                "label": f"honeypot:{hp_port}",
                                "is_risk": True
                            }
                        })

                    # Add sinkhole nodes
                    for sh in res.data.get("sinkholes", []):
                        sh_operator = sh.get("sinkhole_operator", "Unknown")
                        sh_ip = sh.get("sinkhole_ip", "")
                        sh_conf = sh.get("confidence", 0)
                        sh_id = f"sinkhole_{source}_{sh_ip}" if sh_ip else f"sinkhole_{source}_{sh_operator}"

                        if sh_id not in nodes:
                            nodes[sh_id] = {
                                "data": {
                                    "id": sh_id,
                                    "label": f"Sinkhole: {sh_operator}",
                                    "type": "sinkhole",
                                    "risk_score": sh_conf,
                                    "compromised": True,
                                    "risk_reasons": sh.get("indicator", "")
                                }
                            }
                        edges.append({
                            "data": {
                                "source": source,
                                "target": sh_id,
                                "label": "sinkholed",
                                "is_risk": True
                            }
                        })

                    # Add tarpit nodes
                    for tp in res.data.get("tarpits", []):
                        tp_type = tp.get("type", "generic")
                        tp_port = tp.get("port", 0)
                        tp_delay = tp.get("response_delay_ms", 0)
                        tp_conf = tp.get("confidence", 0)
                        tp_id = f"tarpit_{source}_{tp_port}"

                        if tp_id not in nodes:
                            nodes[tp_id] = {
                                "data": {
                                    "id": tp_id,
                                    "label": f"Tarpit ({tp_delay}ms)",
                                    "type": "tarpit",
                                    "risk_score": tp_conf,
                                    "compromised": tp_conf >= 60,
                                    "risk_reasons": tp.get("indicator", "")
                                }
                            }
                        edges.append({
                            "data": {
                                "source": source,
                                "target": tp_id,
                                "label": f"tarpit:{tp_port}",
                                "is_risk": tp_conf >= 50
                            }
                        })

    # Filter Empty
    if filter_empty:
        connected_ids = set()
        for e in edges:
            connected_ids.add(e["data"]["source"])
            connected_ids.add(e["data"]["target"])
        nodes = {nid: n for nid, n in nodes.items() if nid in connected_ids}

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "truncated": truncated,
        "total_targets": total_targets,
        "displayed_targets": len(targets)
    }

@app.get("/api/visualizations/network/export")
async def export_network_graph(
    target_id: Optional[int] = None,
    filter_empty: bool = False,
    filter_online: str = "all",
    format: str = "svg", 
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Exports the Network Graph to SVG (Graphviz).
    """
    # Reuse existing logic to get nodes/edges (Cytoscape Format)
    graph_data = await get_network_graph(target_id=target_id, filter_empty=filter_empty, filter_online=filter_online, session=session, user=user)
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    
    if format == "svg":
        # Generate DOT source
        dot_lines = ["digraph NetworkGraph {", "  rankdir=LR;", "  node [shape=circle style=filled];"]
        
        # Add Nodes
        for n in nodes:
            data = n.get("data", {})
            # Map Cytoscape types to Graphviz colors/shapes
            color = "#cccccc"
            shape = "ellipse"
            ctype = data.get('type')
            
            if ctype == 'domain': color = "lightblue"; shape="doublecircle"
            elif ctype == 'subdomain': color = "plum"
            elif ctype == 'ip': color = "orange"; shape="box"
            elif ctype == 'external': color = "gray"
            
            # Risk Highlighting
            if data.get('compromised'):
                color = "red"
            
            nid = data.get('id')
            label = data.get('label', '').replace('"', '\\"')
            dot_lines.append(f'  "{nid}" [label="{label}" fillcolor="{color}" shape="{shape}"];')
            
        # Add Edges
        for e in edges:
            data = e.get("data", {})
            src = data.get("source")
            dst = data.get("target")
            
            color = "black"
            if data.get("is_risk"):
                color = "red"
                
            dot_lines.append(f'  "{src}" -> "{dst}" [color="{color}"];')
            
        dot_lines.append("}")
        dot_source = "\n".join(dot_lines)
        
        # Convert to SVG via subprocess
        import asyncio
        try:
            # Async Subprocess
            proc = await asyncio.create_subprocess_exec(
                'dot', '-Tsvg',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate(input=dot_source.encode())
            
            if proc.returncode != 0:
                print(f"Graphviz Error: {stderr.decode()}")
                return {"error": "Failed to generate graph image"}
                
            return Response(content=stdout, media_type="image/svg+xml")
        except Exception as e:
             logger.error(f"Export Error: {e}")
             return Response(content=f"Export Error: {str(e)}", status_code=500)

    elif format == "excel" or format == "csv":
        # Export for Visio Data Visualizer (Excel)
        import pandas as pd
        from io import BytesIO
        
        # Nodes Sheet
        df_nodes = pd.DataFrame(nodes)
        if not df_nodes.empty:
            # Reorder/Rename if keys exist
            display_cols = ["id", "label", "group"]
            df_nodes = df_nodes[[c for c in display_cols if c in df_nodes.columns]]
            df_nodes.columns = [c.capitalize() for c in df_nodes.columns]
        
        # Edges Sheet
        df_edges = pd.DataFrame(edges)
        if not df_edges.empty:
             display_cols = ["from", "to", "label"]
             df_edges = df_edges[[c for c in display_cols if c in df_edges.columns]]
             df_edges.columns = ["Source", "Target", "Description"]
             
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df_nodes.to_excel(writer, index=False, sheet_name='Nodes')
            df_edges.to_excel(writer, index=False, sheet_name='Edges')
            
        output.seek(0)
        return StreamingResponse(output, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', headers={
            "Content-Disposition": 'attachment; filename="network_graph_data.xlsx"'
        })
        
    elif format == "graphml":
        # GraphML Export
        # Schema: http://graphml.graphdrawing.org/xmlns
        
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
            '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '    xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns',
            '     http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
            '  <!-- Node Attributes -->',
            '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="d1" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="d2" for="node" attr.name="risk_score" attr.type="int"/>',
            '  <key id="d3" for="node" attr.name="compromised" attr.type="boolean"/>',
            '  <key id="d4" for="node" attr.name="r" attr.type="int"/>',
            '  <key id="d5" for="node" attr.name="g" attr.type="int"/>',
            '  <key id="d6" for="node" attr.name="b" attr.type="int"/>',
             # Add position keys if we had them, but we don't.
             
            '  <!-- Edge Attributes -->',
            '  <key id="e0" for="edge" attr.name="label" attr.type="string"/>',
            '  <key id="e1" for="edge" attr.name="is_risk" attr.type="boolean"/>',
            
            '  <graph id="G" edgedefault="directed">'
        ]
        
        # Color helper
        def hex_to_rgb(hex_code):
             hex_code = hex_code.lstrip('#')
             if len(hex_code) == 6:
                 return tuple(int(hex_code[i:i+2], 16) for i in (0, 2, 4))
             return (128, 128, 128)

        # Style Map
        styles = {
             'domain': '#4f46e5',
             'subdomain': '#0ea5e9',
             'ip': '#10b981',
             'external': '#64748b',
             'landing': '#d946ef',
             'default': '#94a3b8',
             'compromised': '#ef4444'
        }
        
        for n in nodes:
            data = n.get("data", {})
            nid = data.get("id")
            label = data.get("label", "")
            ctype = data.get("type", "default")
            risk = int(data.get("risk_score", 0))
            is_comp = str(data.get("compromised", False)).lower()
            
            # Determine Color
            color_hex = styles.get('compromised') if data.get('compromised') else styles.get(ctype, styles['default'])
            r, g, b = hex_to_rgb(color_hex)
            
            # Helper for XML Escaping
            def xml_escape(val):
                return str(val).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;")

            # XML Escape Node Data
            nid_safe = xml_escape(nid)
            label_safe = xml_escape(label)
            
            xml_lines.append(f'    <node id="{nid_safe}">')
            xml_lines.append(f'      <data key="d0">{label_safe}</data>')
            xml_lines.append(f'      <data key="d1">{ctype}</data>')
            xml_lines.append(f'      <data key="d2">{risk}</data>')
            xml_lines.append(f'      <data key="d3">{is_comp}</data>')
            xml_lines.append(f'      <data key="d4">{r}</data>')
            xml_lines.append(f'      <data key="d5">{g}</data>')
            xml_lines.append(f'      <data key="d6">{b}</data>')
            xml_lines.append('    </node>')
            
        edge_id = 0
        for e in edges:
             data = e.get("data", {})
             src = data.get("source")
             dst = data.get("target")
             lbl = data.get("label", "")
             is_risk = str(data.get("is_risk", False)).lower()
             
             src_safe = xml_escape(src)
             dst_safe = xml_escape(dst)
             lbl_safe = xml_escape(lbl)
             
             xml_lines.append(f'    <edge id="e{edge_id}" source="{src_safe}" target="{dst_safe}">')
             xml_lines.append(f'      <data key="e0">{lbl_safe}</data>')
             xml_lines.append(f'      <data key="e1">{is_risk}</data>')
             xml_lines.append('    </edge>')
             edge_id += 1
             
        xml_lines.append('  </graph>')
        xml_lines.append('</graphml>')
        
        output = "\n".join(xml_lines)
        return Response(content=output, media_type="application/xml", headers={
             "Content-Disposition": 'attachment; filename="yads_network_graph.graphml"'
        })

    return {"error": "Invalid format"}

@app.get("/visualizations/redirect-graph", response_class=HTMLResponse)

async def view_redirect_graph(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    # Fetch all targets for the dropdown
    targets = session.exec(select(Target.domain).order_by(Target.domain)).all()
    return templates.TemplateResponse("redirect_graph.html", {"request": request, "domains": targets, "user": user})

@app.get("/visualizations/network-graph", response_class=HTMLResponse)
async def view_network_graph(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    targets = session.exec(select(Target).order_by(Target.domain)).all()
    return templates.TemplateResponse("network_graph.html", {"request": request, "domains": targets, "user": user})


@app.get("/api/visualizations/network/render-image")
async def render_network_graph_image(
    filter_online: str = "all",
    include_labels: bool = True,
    include_edge_labels: bool = True,
    max_label_length: int = 25,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Server-side rendering of network graph as a static PNG image.
    Handles large graphs (100k+ nodes) that can't be rendered in browser.

    Args:
        filter_online: Filter targets by online status
        include_labels: Whether to include node labels (DNS/Web names)
        include_edge_labels: Whether to include edge labels (connection types)
        max_label_length: Maximum length for labels before truncation
    """
    import networkx as nx
    import numpy as np
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for server-side rendering
    import matplotlib.pyplot as plt
    from io import BytesIO
    from datetime import datetime

    logger.info(f"[GraphRender] Starting server-side render for tenant {user.tenant_id}")

    # Filter by user's tenant
    if user.role == "admin" and not user.tenant_id:
        query = select(Target)
    else:
        query = select(Target).where(Target.tenant_id == user.tenant_id)

    targets = session.exec(query).all()
    target_ids = [t.id for t in targets]
    target_map = {t.id: t.domain for t in targets}

    logger.info(f"[GraphRender] Processing {len(targets)} targets...")

    # Build NetworkX graph
    G = nx.DiGraph()

    # Add target nodes with full labels
    for t in targets:
        # User requested full names, so we disable truncation
        display_label = t.domain 
        G.add_node(t.domain, type='domain', label=t.domain, display_label=display_label)
    
    # Fetch scan results for edges
    if target_ids:
        results = session.exec(
            select(ScanResult).where(
                ScanResult.target_id.in_(target_ids),
                ScanResult.module_name.in_(['subdomain_scanner', 'infrastructure_scanner', 'web_analyzer'])
            )
        ).all()
        
        # Group by target and get latest per module
        latest_by_target = {}
        for r in results:
            key = (r.target_id, r.module_name)
            if key not in latest_by_target:
                latest_by_target[key] = r
        
        for (t_id, mod), res in latest_by_target.items():
            if not res.data or t_id not in target_map:
                continue
            source = target_map[t_id]

            if mod == 'subdomain_scanner':
                for sub_entry in res.data.get("subdomains", [])[:50]:  # Limit per target
                    sub = sub_entry.get("subdomain")
                    if sub and sub != source:
                        display_label = sub 
                        G.add_node(sub, type='subdomain', label=sub, display_label=display_label)
                        G.add_edge(source, sub, label='subdomain', connection_type='subdomain')

            elif mod == 'infrastructure_scanner':
                ip = res.data.get("ip")
                if ip:
                    G.add_node(ip, type='ip', label=ip, display_label=ip)
                    G.add_edge(source, ip, label='resolves_to', connection_type='resolves_to')

            elif mod == 'web_analyzer':
                chain = res.data.get("redirect_chain", [])
                prev = source
                for hop in chain[:5]:  # Limit chain depth
                    hop_clean = hop.replace("https://", "").replace("http://", "").split("/")[0]
                    if hop_clean and hop_clean != prev:
                        display_label = hop_clean 
                        G.add_node(hop_clean, type='redirect', label=hop_clean, display_label=display_label)
                        G.add_edge(prev, hop_clean, label='redirects_to', connection_type='redirects_to')
                        prev = hop_clean
    
    logger.info(f"[GraphRender] Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
    
    # Create figure with appropriate size
    node_count = G.number_of_nodes()
    fig_size = min(100, max(20, node_count / 50))  # Scale figure size with nodes
    fig, ax = plt.subplots(figsize=(fig_size, fig_size), facecolor='#0f172a')
    ax.set_facecolor('#0f172a')
    
    # Calculate layout (spring layout for large graphs)
    logger.info(f"[GraphRender] Computing layout...")
    if node_count > 5000:
        pos = nx.spring_layout(G, k=2/np.sqrt(node_count), iterations=20, seed=42)
    elif node_count > 1000:
        pos = nx.spring_layout(G, k=1/np.sqrt(node_count), iterations=50, seed=42)
    else:
        pos = nx.spring_layout(G, seed=42)
    
    # Color nodes by type
    colors = []
    sizes = []
    for node in G.nodes():
        ntype = G.nodes[node].get('type', 'unknown')
        if ntype == 'domain':
            colors.append('#4f46e5')  # Indigo
            sizes.append(100)
        elif ntype == 'subdomain':
            colors.append('#0ea5e9')  # Cyan
            sizes.append(30)
        elif ntype == 'ip':
            colors.append('#10b981')  # Emerald
            sizes.append(50)
        elif ntype == 'redirect':
            colors.append('#8b5cf6')  # Purple
            sizes.append(40)
        else:
            colors.append('#64748b')  # Slate
            sizes.append(20)
    
    logger.info(f"[GraphRender] Drawing graph...")

    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=sizes, ax=ax, alpha=0.9)

    # Draw edges
    nx.draw_networkx_edges(G, pos, edge_color='#475569', alpha=0.3, arrows=True, ax=ax, arrowsize=5)

    # Draw node labels (DNS names, Web names)
    if include_labels:
        # Adaptive font size based on node count
        if node_count < 100:
            label_font_size = 8
        elif node_count < 500:
            label_font_size = 6
        elif node_count < 2000:
            label_font_size = 4
        else:
            label_font_size = 3

        # Use display_label for better readability
        display_labels = {node: G.nodes[node].get('display_label', node) for node in G.nodes()}

        nx.draw_networkx_labels(
            G, pos,
            labels=display_labels,
            font_size=label_font_size,
            font_color='#94a3b8',
            font_weight='normal',
            ax=ax,
            verticalalignment='bottom',
            horizontalalignment='center'
        )

    # Draw edge labels (Connection names: subdomain, resolves_to, redirects_to, etc.)
    if include_edge_labels and node_count < 1000:  # Only for manageable graph sizes
        # Adaptive font size for edge labels
        if node_count < 100:
            edge_font_size = 6
        elif node_count < 500:
            edge_font_size = 5
        else:
            edge_font_size = 4

        edge_labels = {(u, v): data.get('label', '') for u, v, data in G.edges(data=True)}

        nx.draw_networkx_edge_labels(
            G, pos,
            edge_labels=edge_labels,
            font_size=edge_font_size,
            font_color='#64748b',
            font_weight='light',
            ax=ax,
            alpha=0.7,
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#0f172a', edgecolor='none', alpha=0.7)
        )

    ax.axis('off')

    # Add watermark/info with legend
    info_text = f"YADS Network Graph | {datetime.now().strftime('%Y-%m-%d %H:%M')} | {node_count} nodes, {G.number_of_edges()} edges"
    fig.text(0.02, 0.02, info_text, fontsize=10, color='#64748b', ha='left')

    # Add legend for node types
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#4f46e5', label='Domain'),
        Patch(facecolor='#0ea5e9', label='Subdomain'),
        Patch(facecolor='#10b981', label='IP Address'),
        Patch(facecolor='#8b5cf6', label='Redirect')
    ]
    ax.legend(handles=legend_elements, loc='upper right', framealpha=0.8, facecolor='#1e293b', edgecolor='#475569', labelcolor='#94a3b8')
    
    # Save to buffer
    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='#0f172a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    
    logger.info(f"[GraphRender] Render complete!")
    
    return StreamingResponse(
        buf,
        media_type="image/png",
        headers={
            "Content-Disposition": f'attachment; filename="network_graph_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png"'
        }
    )


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


def get_unique_tags(session: Session) -> List[str]:
    """Helper to fetch all unique tags from all targets."""
    # This is a bit brute force for JSONB lists in pure SQLModel without proper func.unnest support easily accessible
    # Raw SQL is best here
    try:
        query = text("SELECT DISTINCT jsonb_array_elements_text(tags) FROM target ORDER BY 1")
        results = session.exec(query).all()
        # We need r[0] because session.exec(text) returns Row objects
        return [r[0] for r in results]
    except Exception:
        return []

@app.get("/api/tags")
async def list_tags(session: Session = Depends(get_session)):
    return get_unique_tags(session)

@app.post("/targets/{target_id}/tags")
async def add_tag(target_id: int, tag: str = Body(..., embed=True), session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    if tag not in target.tags:
        # Create new list to ensure change tracking
        new_tags = list(target.tags)
        new_tags.append(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags

@app.delete("/targets/{target_id}/tags/{tag}")
async def remove_tag(target_id: int, tag: str, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    if tag in target.tags:
        new_tags = list(target.tags)
        new_tags.remove(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags

@app.get("/api/search")
async def search_targets(q: str, session: Session = Depends(get_session)):
    """
    Global search across domains and JSON scan results.
    """
    if not q or len(q) < 2:
        return {"targets": [], "findings": []}
        
    query_str = f"%{q}%"
    
    # 1. Search Domains
    t_query = select(Target).where(Target.domain.ilike(query_str)).limit(10)
    targets = session.exec(t_query).all()
    
    # 2. Search Scan Results (Deep Search) - PostgreSQL JSONB -> Text
    # We select the scan result and the associated target domain
    # Casting JSONB to Text allows simple "contains" text search
    sr_query = text("""
        SELECT sr.id, sr.module_name, sr.data, t.id, t.domain 
        FROM scanresult sr 
        JOIN target t ON sr.target_id = t.id 
        WHERE sr.data::text ILIKE :q 
        LIMIT 20
    """)
    
    findings_raw = session.exec(sr_query, params={"q": query_str}).all()
    
    findings = []
    for row in findings_raw:
        # row: (id, module_name, data, target_id, domain)
        findings.append({
            "module": row[1],
            "target": row[4],
            "target_id": row[3],
            "snippet": "Match found in data" # MVP: Highlighting is complex in JSON
        })
        
    return {
        "targets": [{"id": t.id, "domain": t.domain} for t in targets],
        "findings": findings
    }

@app.get("/search", response_class=HTMLResponse)
async def view_search(request: Request, q: str = ""):
    return templates.TemplateResponse("search.html", {"request": request, "q": q})

@app.post("/targets/bulk/tag", response_class=RedirectResponse)
async def bulk_add_tag(
    target_ids: List[int] = Form(default=[]), 
    tag: str = Form(...),
    session: Session = Depends(get_session)
):
    if not target_ids:
        return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)

    targets = session.exec(select(Target).where(Target.id.in_(target_ids))).all()
    count = 0
    for target in targets:
        curr_tags = target.tags or []
        if tag not in curr_tags:
            new_tags = list(curr_tags)
            new_tags.append(tag)
            target.tags = new_tags
            session.add(target)
            count += 1
    
    session.commit()
    return RedirectResponse(url=f"/targets/table?msg=Added tag '{tag}' to {count} targets", status_code=303)






@app.post("/admin/reset", response_class=HTMLResponse)
async def admin_reset_system(request: Request, session: Session = Depends(get_session)):
    """
    Emergency Stop & Data Wipe:
    1. Purge Redis Queue
    2. Revoke all active tasks
    3. Delete all Targets & Scan Results
    """
    # 1. Purge Queue
    try:
        celery_app.control.purge()
    except Exception as e:
        logger.error(f"Failed to purge queue: {e}")

    # 2. Revoke Active/Reserved Tasks
    i = celery_app.control.inspect()
    active = i.active() if i else None
    reserved = i.reserved() if i else None
    
    if active:
        for worker, tasks in active.items():
            for task in tasks:
                celery_app.control.revoke(task['id'], terminate=True)
                
    if reserved:
        for worker, tasks in reserved.items():
            for task in tasks:
                celery_app.control.revoke(task['id'], terminate=True)

    # 3. Delete Data (Cascade)
    session.exec(text("DELETE FROM scanresult"))
    session.exec(text("DELETE FROM modulestate"))
    session.exec(text("DELETE FROM target"))
    session.commit()
    
    return RedirectResponse(url="/settings?saved=true&msg=System+Reset+Complete", status_code=303)
