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
from yads.core.seeding import seed_changelog, seed_default_report_templates

from yads.config import settings
from yads.models import Target, ScanResult, ModuleState, SystemConfig, Notification, SecurityTrend, HTTPTraffic
from yads.core.logging_config import configure_logging
from yads.core.backup import create_backup_zip, restore_backup_from_zip
from yads.core.scoring import calculate_target_score, get_grade, get_grade_color
from yads.api.routers import auth, analytics, users, tenants, schedules, api_keys, dashboard, targets, graphs, exports, system, tags
from yads.auth.deps import get_current_user_html, RoleChecker, get_current_active_user, PlatformAdminChecker, LoginRequiredException, MFARequiredException
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
            from sqlalchemy import inspect
            inspector = inspect(engine)
            
            with Session(engine) as session:
                # --- User Table ---
                if inspector.has_table("user"):
                    user_columns = [c["name"] for c in inspector.get_columns("user")]
                    if "tenant_id" not in user_columns:
                        logger.info("Migrating schema: Adding tenant_id to user table")
                        session.exec(text("ALTER TABLE \"user\" ADD COLUMN tenant_id INTEGER REFERENCES tenant(id)"))
                    if "last_login" not in user_columns:
                        logger.info("Migrating schema: Adding last_login to user table")
                        session.exec(text("ALTER TABLE \"user\" ADD COLUMN last_login TIMESTAMP WITHOUT TIME ZONE"))
                    if "email" not in user_columns:
                        logger.info("Migrating schema: Adding email to user table")
                        session.exec(text("ALTER TABLE \"user\" ADD COLUMN email VARCHAR"))
                    if "language" not in user_columns:
                        logger.info("Migrating schema: Adding language to user table")
                        session.exec(text("ALTER TABLE \"user\" ADD COLUMN language VARCHAR DEFAULT 'en'"))
                    session.commit()

                # --- Target Table ---
                if inspector.has_table("target"):
                    target_columns = [c["name"] for c in inspector.get_columns("target")]
                    if "tenant_id" not in target_columns:
                        logger.info("Migrating schema: Adding tenant_id to target table")
                        session.exec(text("ALTER TABLE target ADD COLUMN tenant_id INTEGER REFERENCES tenant(id)"))
                    if "scan_priority" not in target_columns:
                        logger.info("Migrating schema: Adding scan_priority to target table")
                        session.exec(text("ALTER TABLE target ADD COLUMN scan_priority INTEGER DEFAULT 5"))
                    session.commit()

                # --- Tenant Table ---
                if inspector.has_table("tenant"):
                    tenant_columns = [c["name"] for c in inspector.get_columns("tenant")]
                    keys = [
                        "shodan_api_key", "censys_api_key", "virustotal_api_key",
                        "hunter_api_key", "github_token", "twitter_bearer_token",
                        "session_timeout_minutes", "report_logo_url", "report_company_name",
                        "report_primary_color", "report_secondary_color",
                        "report_header_text", "report_footer_text"
                    ]
                    for key in keys:
                        if key not in tenant_columns:
                            logger.info(f"Migrating schema: Adding {key} to tenant table")
                            if key == "session_timeout_minutes":
                                session.exec(text("ALTER TABLE tenant ADD COLUMN session_timeout_minutes INTEGER DEFAULT 60"))
                            elif key == "report_primary_color":
                                session.exec(text("ALTER TABLE tenant ADD COLUMN report_primary_color VARCHAR DEFAULT '#3b82f6'"))
                            elif key == "report_secondary_color":
                                session.exec(text("ALTER TABLE tenant ADD COLUMN report_secondary_color VARCHAR DEFAULT '#64748b'"))
                            else:
                                session.exec(text(f"ALTER TABLE tenant ADD COLUMN {key} VARCHAR"))
                    session.commit()

                # --- WorkerNode Table ---
                if inspector.has_table("workernode"):
                    node_columns = [c["name"] for c in inspector.get_columns("workernode")]
                    cols = {
                        "node_id": "VARCHAR",
                        "status": "VARCHAR DEFAULT 'pending'",
                        "capabilities": "JSONB DEFAULT '[]'",
                        "assigned_tenant_ids": "JSONB DEFAULT '[]'",
                        "max_daily_scans": "INTEGER",
                        "description": "VARCHAR",
                        "version": "VARCHAR",
                        "cpu_count": "INTEGER",
                        "memory_mb": "INTEGER"
                    }
                    for col, db_type in cols.items():
                        if col not in node_columns:
                            logger.info(f"Migrating schema: Adding {col} to workernode table")
                            session.exec(text(f"ALTER TABLE workernode ADD COLUMN {col} {db_type}"))
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
            # Priority: YADS_ADMIN_USER/YADS_ADMIN_PASS env vars (set by installer or manual deploy)
            # Fallback: only seed admin/admin if SETUP_COMPLETE=True (existing install upgrading),
            #           never on a fresh install — the Release Manager calls /setup/create-admin.
            with Session(engine) as session:
                from yads.models import User
                from yads.auth.security import get_password_hash
                existing_users = session.exec(select(User)).first()
                if not existing_users:
                    env_user = os.getenv("YADS_ADMIN_USER", "").strip()
                    env_pass = os.getenv("YADS_ADMIN_PASS", "").strip()
                    if env_user and env_pass:
                        logger.info(f"Seeding admin from env: {env_user}")
                        admin = User(
                            username=env_user,
                            password_hash=get_password_hash(env_pass),
                            role="admin",
                            is_active=True,
                            force_password_change=False,
                        )
                        session.add(admin)
                        session.commit()
                    elif settings.SETUP_COMPLETE:
                        # Existing install with no users (edge case) — seed with forced PW change
                        logger.warning("No users found on completed install. Creating default 'admin' user (force_password_change=True).")
                        admin = User(
                            username="admin",
                            password_hash=get_password_hash("admin"),
                            role="admin",
                            force_password_change=True,
                        )
                        session.add(admin)
                        session.commit()
                    else:
                        logger.info("Fresh install — skipping default admin seed. Use /setup/create-admin.")
            
            # --- Seed Changelog ---
            seed_changelog()

            # --- Seed Default Report Templates ---
            seed_default_report_templates()

            # --- Ensure QUEUE_ACTIVE is set (fresh DB after wipe has no entry) ---
            with Session(engine) as session:
                from yads.models import SystemConfig
                if not session.get(SystemConfig, "QUEUE_ACTIVE"):
                    session.add(SystemConfig(key="QUEUE_ACTIVE", value="true"))
                    session.commit()
                    logger.info("Seeded QUEUE_ACTIVE=true into SystemConfig.")

            # --- Send pending installation report (airgapped installs) ---
            with Session(engine) as session:
                from yads.models import SystemConfig as _SC
                import threading as _threading, json as _json
                import requests as _requests
                pending = session.get(_SC, "INSTALL_REPORT_PENDING")
                already_sent = session.get(_SC, "INSTALL_REPORT_SENT")
                if pending and not already_sent:
                    payload_str = pending.value
                    def _send_pending(pstr=payload_str):
                        try:
                            data = _json.loads(pstr)
                            resp = _requests.post(
                                "https://support.yads-security.com/api/installation",
                                json=data,
                                timeout=10,
                            )
                            resp.raise_for_status()
                            # Mark as sent, remove pending
                            from yads.database import engine as _eng
                            from sqlmodel import Session as _Sess
                            from yads.models import SystemConfig as _SC2
                            with _Sess(_eng) as s:
                                pnd = s.get(_SC2, "INSTALL_REPORT_PENDING")
                                if pnd:
                                    s.delete(pnd)
                                if not s.get(_SC2, "INSTALL_REPORT_SENT"):
                                    s.add(_SC2(key="INSTALL_REPORT_SENT", value="1"))
                                s.commit()
                            logger.info("[InstallReport] Pending installation report sent successfully.")
                        except Exception as _exc:
                            logger.info(f"[InstallReport] Still no internet — will retry next start. ({_exc})")
                    _threading.Thread(target=_send_pending, daemon=True).start()

            # --- Reset stuck targets (queued/running but no worker processing them) ---
            with Session(engine) as session:
                from sqlmodel import text as sql_text
                result = session.execute(sql_text(
                    "UPDATE target SET scan_status='idle' WHERE scan_status IN ('queued', 'running')"
                ))
                session.commit()
                stuck = result.rowcount
                if stuck:
                    logger.warning(f"[Startup] Reset {stuck} stuck target(s) from queued/running → idle.")

            # --- Register Default Worker ---
            try:
                from yads.core.worker_manager import worker_manager
                node_id = worker_manager.register_primary_worker()
                if node_id:
                    logger.info(f"Default worker registered: {node_id}")
            except Exception as e:
                logger.warning(f"Could not register default worker: {e}")

            # --- Load custom-installed modules into runtime registry ---
            try:
                from yads.core.custom_modules_loader import load_installed_modules_from_db
                with Session(engine) as _s:
                    load_installed_modules_from_db(_s)
                logger.info("Custom scan modules loaded from DB")
            except Exception as e:
                logger.warning(f"Could not load custom modules: {e}")

            # --- Pre-load module signing private key (validates key path at boot) ---
            try:
                from yads.core.module_signing import load_signing_key
                if load_signing_key() is not None:
                    logger.info("Module signing private key ready for auto-signing.")
                else:
                    logger.debug("No module signing private key configured (MODULE_SIGNING_PRIVATE_KEY_PATH not set).")
            except Exception as e:
                logger.warning(f"Module signing key could not be loaded: {e}")

            break
        except Exception as e:
            if i == max_retries - 1:
                logger.error(f"Could not connect to database after retries. Error: {e}")
                raise
            logger.warning(f"Database/Startup not ready... retrying ({i+1}/{max_retries}). Error: {e}")
            time.sleep(2)

    # --- Start system metrics collector ---
    try:
        from yads.core import system_metrics
        system_metrics.start(settings.REDIS_URL)
    except Exception as e:
        logger.warning(f"Could not start system metrics collector: {e}")

    # --- Start health watcher ---
    try:
        from yads.core import watcher
        watcher.start(settings.REDIS_URL)
    except Exception as e:
        logger.warning(f"Could not start health watcher: {e}")

    yield

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

@app.get("/health")
async def health_check():
    return {"status": "ok"}

# -- Static & Templates --
app.mount("/static", StaticFiles(directory="yads/api/static"), name="static")
from yads.api.templating import templates, csrf_token, csrf_token_value
templates.env.globals['csrf_token'] = csrf_token
templates.env.globals['csrf_token_value'] = csrf_token_value

# Inject Globals
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
from yads.core.i18n import t as _translate
templates.env.globals['_'] = _translate

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

# -- CSRF Protection --
from yads.api.middleware.csrf_middleware import CSRFMiddleware
app.add_middleware(CSRFMiddleware)

# -- CORS Setup --
# Restricted to origins defined in settings
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- TLS Enforcement Middleware --
from yads.core.tls_config import is_https_required

@app.middleware("http")
async def tls_enforcement_middleware(request: Request, call_next):
    """
    Reject non-HTTPS requests if HTTPS_ONLY is enabled (Phase 1).
    """
    if not settings.DEBUG:
        # is_https_required checks DISABLE_HTTPS_ONLY env and DB setting
        with Session(engine) as session:
            if is_https_required(session):
                if request.url.scheme != "https":
                    # Check X-Forwarded-Proto for scenarios behind a reverse proxy
                    if request.headers.get("x-forwarded-proto") != "https":
                        return Response(
                            status_code=426,
                            content="SSL/TLS Required. Please use HTTPS.",
                            headers={
                                "Upgrade": "TLS/1.3, HTTP/1.1",
                                "Connection": "Upgrade"
                            }
                        )
    
    return await call_next(request)

# -- Language Middleware (i18n) --
from yads.core.i18n import set_lang, normalize_lang

@app.middleware("http")
async def language_middleware(request: Request, call_next):
    """Set request-scoped language from yads_lang cookie."""
    lang = request.cookies.get("yads_lang", "en")
    set_lang(normalize_lang(lang))
    try:
        return await call_next(request)
    except Exception as exc:
        # Starlette BaseHTTPMiddleware swallows exceptions before FastAPI's
        # exception_handler can see them — catch here and push to Redis watcher.
        _push_api_error_to_redis(request.url, exc)
        import traceback
        logger.error(f"Unhandled exception at {request.url}: {exc}\n{traceback.format_exc()}")
        from fastapi.responses import HTMLResponse
        return HTMLResponse("Internal Server Error", status_code=500)


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

# -- Routers --
from yads.api.routers import analytics, auth, users, changelog, help, profile, queue, notifications, osint, tenant_settings, compliance, reports, ports, email_security, secrets, tech_drift, cert_timeline, asr, cloud_assets, search, setup, archived, workers, mobile, storage, updates, metrics, report_builder, v1, pqc, security_findings, changes, attack_surface, scan_compare, scan_modules, scanner_import, scan_profiles, integrations, nuclei_suggestions, portfolio, executive_report, attack_path, ai_assistant, module_reports, waf_analysis, developer, onboarding, sysmetrics, discovery, addon_reports
# Include Setup Router FIRST to ensure it handles its requests before others if overlap (though unique prefix avoids this)
app.include_router(setup.router)

@app.get("/scan-modules", response_class=RedirectResponse)
@app.get("/scan-modules/", response_class=RedirectResponse)
async def scan_modules_redirect():
    return RedirectResponse(url="/addons/", status_code=301)

app.include_router(analytics.router)
app.include_router(analytics.ui_router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(tenants.router)
app.include_router(portfolio.router)
app.include_router(portfolio.ui_router)
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
app.include_router(module_reports.router)
app.include_router(executive_report.router)
app.include_router(report_builder.router)
app.include_router(ports.router)
app.include_router(email_security.router)
app.include_router(security_findings.router)
app.include_router(changes.router)
app.include_router(attack_surface.router)
app.include_router(attack_path.router)
app.include_router(scan_compare.router)
app.include_router(scan_modules.router)
app.include_router(addon_reports.router)
app.include_router(scanner_import.router)
app.include_router(scan_profiles.router)
app.include_router(developer.router)
app.include_router(onboarding.router)
app.include_router(discovery.router)
app.include_router(integrations.router)
app.include_router(nuclei_suggestions.router)
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
app.include_router(sysmetrics.router)
app.include_router(sysmetrics.ui_router)
app.include_router(v1.router)
app.include_router(dashboard.router)
app.include_router(graphs.router)
app.include_router(targets.router)
app.include_router(exports.router)
app.include_router(system.router)
app.include_router(tags.router)
app.include_router(ai_assistant.router)
app.include_router(waf_analysis.router)



@app.exception_handler(LoginRequiredException)
async def login_required_handler(request: Request, exc: LoginRequiredException):
    return RedirectResponse(url="/login")

@app.exception_handler(MFARequiredException)
async def mfa_required_handler(request: Request, exc: MFARequiredException):
    return RedirectResponse(url="/mfa/setup")

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Never expose internal details for server errors
    safe_detail = exc.detail if exc.status_code < 500 else "An internal error occurred. Please try again or contact support."

    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "status_code": exc.status_code,
            "detail": safe_detail,
            "user": None
        }, status_code=exc.status_code)

    return JSONResponse(
        {"detail": safe_detail},
        status_code=exc.status_code
    )

def _push_api_error_to_redis(url: str, exc: Exception):
    """Write a brief API 500 error entry to Redis so the watcher can surface it."""
    try:
        import redis as _redis, json as _json, time as _time
        from yads.config import settings
        rc = _redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
        entry = _json.dumps({
            "ts": _time.time(),
            "url": str(url),
            "error": f"{type(exc).__name__}: {str(exc)[:200]}",
        })
        rc.lpush("yads:api_errors", entry)
        rc.ltrim("yads:api_errors", 0, 49)   # keep last 50
        rc.expire("yads:api_errors", 3600)    # 1h TTL
    except Exception:
        pass  # never raise from error handler


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    import traceback
    tb = traceback.format_exc()
    logger.error(f"Unhandled exception at {request.url}: {exc}\n{tb}")
    _push_api_error_to_redis(request.url, exc)

    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "status_code": 500,
            "detail": "An internal error occurred. Please try again or contact support.",
            "user": None
        }, status_code=500)

    return JSONResponse(
        {"detail": "Internal Server Error"},
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








