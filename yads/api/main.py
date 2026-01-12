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
from datetime import datetime
from yads.modules.visual_osint import VisualOSINT
from yads.modules.report_generator import generate_report
from yads.modules.brand_monitor import BrandMonitor

from yads.config import settings
from yads.models import Target, ScanResult, ModuleState, SystemConfig
from yads.core.logging_config import configure_logging
from yads.core.backup import create_backup_zip, restore_backup_from_zip
from yads.api.routers import auth, analytics, users, tenants
from yads.auth.deps import get_current_user_html, RoleChecker, get_current_active_user, PlatformAdminChecker, LoginRequiredException
from yads.models import User

# -- Logging Setup --
logger = configure_logging("yads-api")

# -- DB Setup --
from yads.database import engine, get_session, create_db_and_tables
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
                    
                # Check if Target table has tenant_id column
                try:
                    session.exec(text("SELECT tenant_id FROM target LIMIT 1"))
                except Exception:
                    logger.info("Migrating schema: Adding tenant_id to target table")
                    session.rollback()
                    session.exec(text("ALTER TABLE target ADD COLUMN tenant_id INTEGER REFERENCES tenant(id)"))
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
            
            # Enforce Paused State on Boot (User Request)
            with Session(engine) as session:
                from yads.models import SystemConfig
                config = session.get(SystemConfig, "QUEUE_ACTIVE")
                if not config:
                    config = SystemConfig(key="QUEUE_ACTIVE", value="false")
                    session.add(config)
                    session.commit()
                else:
                    # Ensure it starts as false if we want strict "no auto start on boot" 
                    # even if it was true before? 
                    # The user said: "change the worker in such a way, that he is not autostarting scans after the docker container has been startet"
                    # This implies ALWAYS pausing on boot.
                    if config.value.lower() == "true":
                        config.value = "false"
                        session.add(config)
                        session.commit()
            
            # Broadcast Pause Command
            try:
                from yads.worker import celery_app
                # We must import celery_app here or at top. 
                # Note: importing worker inside main might cause circular import if worker imports main.
                # worker.py imports settings, logging, modules. It does NOT import main. Safe.
                
                # Cancel consumer to stop processing queue
                celery_app.control.cancel_consumer('celery', reply=True)
                logger.info("Auto-start disabled: Queue execution paused.")
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

            # --- Changelog 1.2.7 ---
            with Session(engine) as session:
                from yads.models import ChangelogEntry
                version = "1.2.7"
                if not session.exec(select(ChangelogEntry).where(ChangelogEntry.version == version)).first():
                    entry = ChangelogEntry(
                        title="Tenant-Aware Backup & Restore",
                        version=version,
                        content="""
                        <h3>🔐 Tenant-Aware Backup</h3>
                        <p>We've upgraded the backup system to support multi-tenancy!</p>
                        <ul class="list-disc list-inside mt-2 mb-2">
                            <li><strong>Tenant Selection:</strong> You can now choose specific tenants to backup.</li>
                            <li><strong>Safe Restore:</strong> The restore process now analyzes the backup file and warns you before purging any data.</li>
                            <li><strong>Isolation:</strong> Restoring a partial backup only affects the selected tenants, keeping others safe.</li>
                        </ul>
                        <p class="text-xs text-gray-500">Check the Settings page to try it out.</p>
                        """
                    )
                    session.add(entry)
                    session.commit()
                    logger.info(f"Added changelog entry for {version}")
                
            break
        except OperationalError:
            if i == max_retries - 1:
                logger.error("Could not connect to database after retries.")
                raise
            logger.warning(f"Database not ready... retrying ({i+1}/{max_retries})")
            time.sleep(2)
            
    yield

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# -- Static & Templates --
app.mount("/static", StaticFiles(directory="yads/api/static"), name="static")
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

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

# -- Celery --
from celery import Celery
celery_app = Celery("yads_worker", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

# -- Routers --
# -- Routers --
from yads.api.routers import analytics, auth, users, changelog, help
app.include_router(analytics.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(tenants.router)
app.include_router(changelog.router)
app.include_router(help.router)

@app.exception_handler(LoginRequiredException)
async def login_required_handler(request: Request, exc: LoginRequiredException):
    return RedirectResponse(url="/login")


# -- UI Routes --

# -- Bulk Actions (Must be defined before generic {target_id} routes) --

@app.post("/targets/bulk/scan", response_class=HTMLResponse)
async def bulk_scan_targets(
    request: Request,
    scan_types: List[str] = Form(default=[]), 
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "scanner"]))
):
    form = await request.form()
    target_ids = form.getlist("target_ids") 
    
    if not target_ids:
         return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)
         
    scan_types_selected = form.getlist("scan_types")
    
    valid_types = ["subdomain_scanner", "dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint", "ssl_scanner", "wayback_scanner", "crawler", "cve_scanner", "content_discovery", "tld_scanner", "port_scanner", "full_scan"]
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
                target.scan_status = "queued"
                session.add(target)
                
                # Always dispatch to Redis (even if paused, it waits there).
                # This ensures arguments (scan_types) are preserved.
                # Bulk scan is also a MANUAL action.
                celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, final_types, True])
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
    user: User = Depends(RoleChecker(["admin", "scanner"]))
):
    form = await request.form()
    raw_text = form.get("targets_raw", "")
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
            
        # Create
        new_target = Target(domain=domain, tenant_id=user.tenant_id)
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
    user: User = Depends(RoleChecker(["admin", "scanner"]))
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

@app.post("/targets/{target_id}/scan")
async def trigger_scan(target_id: int, request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Parse form data for scan types
    form = await request.form()
    scan_types = form.getlist("scan_types") # Returns list of values for keys named "scan_types"
    
    # Validation/Default
    valid_types = ["subdomain_scanner", "dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint", "ssl_scanner", "wayback_scanner", "crawler", "cve_scanner", "content_discovery", "tld_scanner", "port_scanner", "full_scan"]
    selected_types = [t for t in scan_types if t in valid_types]
    
    if "full_scan" in selected_types:
        # User explicitly requested EVERYTHING
        # Expand 'full_scan' to all real scanner types
        # Remove 'full_scan' pseudo-type to avoid worker conflict
        real_types = [t for t in valid_types if t != "full_scan"]
        selected_types = real_types
    
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
    # We pass ignore_queue_pause=True because this is a MANUAL action by the user.
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, selected_types, True])
    
    return RedirectResponse(url=f"/targets/{target_id}", status_code=303)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    # Calculate stats (Tenant Scoped)
    total_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Total scans is bit harder to filter if scanresult doesn't have tenant_id. 
    # We have to join.
    total_scans_count = session.exec(select(func.count(ScanResult.id)).join(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Pagination defaults for initial load
    page = 1
    limit = 9
    offset = 0
    
    # Fetch Paginated Targets (Tenant Scoped)
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
    # Fetch Active Scans (Tenant Scoped)
    active_scans = session.exec(select(Target).where(Target.scan_status == "running", Target.tenant_id == user.tenant_id)).all()
    
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
    import redis
    queue_len = 0
    try:
        r = redis.from_url(settings.REDIS_URL)
        queue_len = r.llen('celery')
    except Exception:
        pass
    
    from yads.models import SystemConfig
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = config.value.lower() == "true" if config else False

    return templates.TemplateResponse("index.html", {
        "request": request,
        "targets": targets,
        "active_scans": active_scans,
        "last_scans": last_scans,
        "stats": {
            "active_targets": total_targets,
            "services_monitored": "-",  # Placeholder
            "total_scans": total_scans_count,
            "queue_length": queue_len,
            "queue_active": queue_active
        },
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "total_count": total_targets,
            "start_item": 1,
            "end_item": min(limit, total_targets)
        },
        "user": user # Pass user to context
    })


@app.get("/dashboard/stats", response_class=HTMLResponse)
async def dashboard_stats(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """HTMX endpoint for auto-updating stats"""
    total_targets = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id)).one()
    total_scans_count = session.exec(select(func.count(ScanResult.id)).join(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Queue Stats
    import redis
    queue_len = 0
    try:
        r = redis.from_url(settings.REDIS_URL)
        queue_len = r.llen('celery')
    except Exception:
        pass
    
    from yads.models import SystemConfig
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = config.value.lower() == "true" if config else False

    return templates.TemplateResponse("_dashboard_stats.html", {
        "request": request,
        "stats": {
            "active_targets": total_targets,
            "services_monitored": "-",
            "total_scans": total_scans_count,
            "queue_length": queue_len,
            "queue_active": queue_active
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
    total_count = session.exec(select(func.count()).select_from(Target).where(Target.tenant_id == user.tenant_id)).one()
    
    # Fetch Paginated (Tenant Scoped)
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
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
async def view_logs_page(request: Request, user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """
    Renders the Logs page with a list of available log files.
    """
    log_dir = os.getenv("LOG_DIR", "logs")
    log_files = []
    if os.path.exists(log_dir):
        # List all .log files
        log_files = [f for f in os.listdir(log_dir) if f.endswith('.log')]
        log_files.sort()
    
    # Default to yads-api.log if available, else first one, else yads.log
    default_log = "yads-api.log"
    if default_log not in log_files and log_files:
        default_log = log_files[0]

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "log_files": log_files,
        "current_log": default_log,
        "user": user
    })

@app.get("/api/logs/stream")
async def get_logs_stream(file: str = "yads-api.log", user: User = Depends(RoleChecker(["admin", "scanner"]))):
    """Reads the last 100 lines of the specified log file."""
    log_dir = os.getenv("LOG_DIR", "logs")
    
    # Security: Ensure clean filename (basename only) to prevent traversal
    safe_filename = os.path.basename(file)
    log_file = os.path.join(log_dir, safe_filename)
    
    if not os.path.exists(log_file):
        return {"logs": [f"Log file '{safe_filename}' not found."]}
    
    async with aiofiles.open(log_file, mode='r') as f:
        content = await f.read()
        lines = content.splitlines()
        return {"logs": lines[-100:]}

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
    import redis
    r = redis.from_url(settings.REDIS_URL)
    
    # Check Redis for live status first
    status_msg = r.get(f"scan:status:{target_id}")
    if status_msg:
        return {"status": status_msg.decode("utf-8")}
        
    # Fallback to DB if no live status (e.g. idle or finished)
    with Session(engine) as session:
        t = session.get(Target, target_id)
        if t:
            return {"status": t.scan_progress or t.scan_status}
            
    return {"status": "Unknown"}

@app.get("/api/scans/{target_id}/logs")
async def get_scan_logs(target_id: int):
    """
    Returns the recent log lines from Redis.
    """
    import redis
    import json
    r = redis.from_url(settings.REDIS_URL)
    
    # Fetch List
    logs = r.lrange(f"scan:logs:{target_id}", 0, -1)
    parsed_logs = []
    
    for l in logs:
        try:
            entry = json.loads(l)
            parsed_logs.append(entry)
        except:
            parsed_logs.append({"msg": l.decode('utf-8')})
            
    return {"logs": parsed_logs}

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
    import redis
    import json
    r = redis.from_url(settings.REDIS_URL)
    
    logs = r.lrange(f"scan:logs:{target_id}", 0, -1)
    parsed_logs = []
    for l in logs:
        try:
            entry = json.loads(l)
            parsed_logs.append(entry)
        except:
            parsed_logs.append({"msg": l.decode('utf-8'), "ts": "", "level": "INFO"})
            
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
        port_scan = next((r for r in results if r.module_name == 'port_scanner'), None)
        
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
            "last_scan": results[0].scanned_at if results else None,
            "last_scan": results[0].scanned_at if results else None,
            "modules": list(set([r.module_name for r in results])),
            "is_login_page": web.data.get("is_login_page", False) if (web and web.data) else False
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

@app.get("/api/backup/export")
async def export_data(session: Session = Depends(get_session)):
    """
    Generates and downloads a full system backup (Zip).
    """
    try:
        zip_file = create_backup_zip(session)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"yads_backup_{timestamp}.zip"
        
        return StreamingResponse(
            zip_file, 
            media_type="application/zip", 
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/backup/analyze")
async def analyze_backup(
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin"]))
):
    """
    Analyzes the uploaded backup file and returns a summary for confirmation.
    Used by HTMX to pop up a modal.
    """
    logger.info(f"Received backup upload for analysis: {file.filename}")
    if not file.filename.endswith('.zip'):
        logger.warning("Upload rejected: Not a zip file")
        return HTMLResponse("<div class='text-red-400'>Error: Not a zip file</div>", status_code=400)
    
    contents = await file.read()
    logger.info(f"Read {len(contents)} bytes from upload.")
    
    import zipfile
    import json
    import io
    
    meta = {}
    db_summary = {}
    
    try:
        with zipfile.ZipFile(io.BytesIO(contents), 'r') as zf:
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
        
    # Look up Tenant Names
    tenant_ids = meta.get("tenant_ids", [])
    tenant_names = []
    if tenant_ids:
        from yads.models import Tenant
        for tid in tenant_ids:
            t = session.get(Tenant, tid)
            if t: tenant_names.append(t.name)
            else: tenant_names.append(f"Unknown ID {tid}")
    
    from yads.core.backup import SYSTEM_TABLES
    return templates.TemplateResponse("components/restore_confirmation_modal.html", {
        "request": request,
        "meta": meta,
        "db_summary": db_summary,
        "tenant_names": tenant_names,
        "is_partial": bool(tenant_ids),
        "tmp_path": tmp_path,
        "skipped_tables": SYSTEM_TABLES
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


# -- Queue Management Routes --
import redis

@app.get("/queue", response_class=HTMLResponse)
async def view_queue(request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    # Connect to Redis to peek at the queue
    # Celery default queue key is 'celery'
    try:
        r = redis.from_url(settings.REDIS_URL, decode_responses=True)
        queue_len = r.llen("celery")
        # Peek top 50
        raw_items = r.lrange("celery", 0, 49)
        queue_items = []
        import json
        import base64
        
        for raw in raw_items:
            try:
                item_data = json.loads(raw)
                # Try to get data from argsrepr first (easiest)
                # Format: [1, 'domain', ['type1', 'type2']]
                args_str = item_data.get('headers', {}).get('argsrepr', '')
                
                # If argsrepr exists, try to parse it safely or just format it
                # Converting string representation to list can be risky with eval, 
                # but we can try to parse it if it looks like JSON or just use string manipulation
                
                # Robust fallback: Decode Body
                body_b64 = item_data.get('body')
                if body_b64:
                    # Celery default encoding is base64 for body
                    body_str = base64.b64decode(body_b64).decode('utf-8')
                    body_json = json.loads(body_str)
                    args = body_json[0] # [id, domain, types]
                    
                    domain = args[1] if len(args) > 1 else "?"
                    scan_types = args[2] if len(args) > 2 else ["All"]
                    
                    queue_items.append({
                        "domain": domain,
                        "scan_types": scan_types,
                        "raw_id": item_data.get('headers', {}).get('id', '?')
                    })
                else:
                     # Fallback to raw if body missing
                     queue_items.append({"domain": "Unknown", "scan_types": args_str, "raw_id": "?"})
                     
            except Exception as e:
                queue_items.append({"domain": "Parse Error", "scan_types": str(e), "raw_id": "?"})

    except Exception as e:
        queue_len = "Error connecting to Redis"
        queue_items = []

    # Check Active/Paused Config
    from yads.models import SystemConfig
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    # Default to False (Paused) if not set, as per user request for "no auto start"
    queue_active = False 
    if config:
        queue_active = config.value.lower() == "true"
        
    # Fetch Pending Items from DB (waiting for queue to resume)
    pending_items = session.exec(select(Target).where(Target.scan_status == "queued", Target.tenant_id == user.tenant_id)).all()

    # Fetch Tenants user is allowed to access (For Backup Selection)
    from yads.models import Tenant
    allowed_tenants = []
    if "admin" in user.role:
        allowed_tenants = session.exec(select(Tenant).order_by(Tenant.name)).all()
    else:
        # Assuming M:N is available on user object via Relationship
        allowed_tenants = user.allowed_tenants
        if not allowed_tenants and user.tenant:
             allowed_tenants = [user.tenant]

    return templates.TemplateResponse("queue.html", { # Changed from settings.html to queue.html
        "request": request, 
        "user": user,
        "queue_length": queue_len, # Added back
        "queue_items": queue_items, # Added back
        "pending_items": pending_items, # Added back
        "queue_active": queue_active, # Changed from queue_status to queue_active
        "allowed_tenants": allowed_tenants # New: For Backup UI
    })

@app.post("/queue/control")
async def control_queue(request: Request, action: str = Form(...), session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "scanner"]))):
    
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    if not config:
        config = SystemConfig(key="QUEUE_ACTIVE", value="false")
        session.add(config)
    
    if action == "start":
        # CRITICAL: Update DB to "true" BEFORE enabling consumer.
        # Otherwise, eager workers pick up tasks, check DB, see "false", and abort immediately.
        config.value = "true"
        session.add(config)
        session.commit()
        
        # Enable Consumer
        celery_app.control.add_consumer('celery', reply=True)
        
        msg = "Queue+Processing+Resumed"
        
        # Return early since we committed already
        return RedirectResponse(url=f"/queue?msg={msg}", status_code=303)
    elif action == "clear":
        # 1. Purge Redis Queue
        purged = celery_app.control.purge()
        
        # 2. Clear DB Queue (mark as stopped/cancelled) - Tenant Scoped if we want? 
        # But this is "Control Queue", usually Admin only. 
        # Ideally an Admin clears queue for EVERYONE or just their tenant?
        # If we are strictly multi-tenant, maybe just their tenant. 
        # But queue is shared resource (worker). Clearing it affects all.
        # Let's purge REDIS (global) but update DB for tenant only? That results in mismatch.
        # "Control Queue" is arguably a Super-Admin feature.
        # But for now, let's limit to tenant to be consistent with "Multi-Tenancy".
        # If user is admin of tenant a customer, they shouldn't clear tasks for Sparkasse.
        
        # However, redis.purge() CLEARS EVERYTHING.
        # We can't selectively purge Redis without iterating.
        # For this iteration: Global Purge (Queue is shared infrastructure)
        # But DB updates should probably touch all to match reality?
        # If the queue is empty, ALL tasks are stopped.
        
        statement = select(Target).where(Target.scan_status == "queued")
        # If we want to be nice, we only mark OUR targets as stopped.
        # But if we purged Redis, EVERYONE'S tasks are gone.
        # So we must mark ALL targets as stopped to reflect reality.
        # Queue Control determines the state of the *Worker*, which is a singleton resource here.
        # So we accept this is a "System Admin" generic action?
        # The user's prompt implies "Multi-Tenancy" access control.
        # A tenant admin shouldn't be able to stop the global scanner.
        # But we don't have "Super Admin".
        # Let's leave it global for now but acknowledge the limitation.
        # Or better: Only update OUR targets, but warn that queue was purged.
        
        # Actually, let's do global DB update because the tasks actully died.
        targets = session.exec(statement).all()
        for t in targets:
            t.scan_status = "stopped"
            t.scan_progress = "Cleared from Queue"
            session.add(t)
            
        msg = f"Queue+Cleared+(Purged:+{purged},+DB+Updated:+{len(targets)})"

    elif action == "pause":
         # Disable Consumer
        celery_app.control.cancel_consumer('celery', reply=True)
        config.value = "false"
        msg = "Queue+Processing+Paused"
    elif action == "stop":
        # 1. Disable Consumer
        celery_app.control.cancel_consumer('celery', reply=True)
        config.value = "false"
        
        # 2. Purge Queue
        try:
            celery_app.control.purge()
        except Exception:
            pass
            
        # 3. Revoke Active Tasks
        i = celery_app.control.inspect()
        active = i.active()
        if active:
            for worker, tasks in active.items():
                for task in tasks:
                    celery_app.control.revoke(task['id'], terminate=True)
        
        # 4. Update DB Status
        targets = session.exec(select(Target).where(Target.scan_status.in_(["running", "queued"]))).all()
        for t in targets:
            t.scan_status = "stopped"
            t.scan_progress = "Emergency Stop by User"
            session.add(t)
            
        msg = "System+Full+Stop+Executed"
    else:
        msg = "Invalid+Action"
        
        session.add(config)
    session.commit()
    
    # Check if HTMX request (e.g. from Dashboard)
    if request.headers.get("HX-Request"):
        return await dashboard_stats(request, session, user)
        
    return RedirectResponse(url=f"/queue?msg={msg}", status_code=303)


# -- Graph View --

@app.get("/targets/graph", response_class=HTMLResponse)
async def view_graph_page(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Renders the Graph View page.
    """
    targets = session.exec(select(Target)).all()
    return templates.TemplateResponse("graph.html", {"request": request, "targets": targets, "user": user})


@app.get("/api/graph/{target_id}")
async def get_graph_data(target_id: int, session: Session = Depends(get_session)):
    """
    Returns nodes and edges for the graph visualization.
    """
    target = session.get(Target, target_id)
    if not target:
        return {"error": "Target not found"}

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
        current_results = [r for r in [latest_subdomain, latest_dns, latest_web, latest_typosquat, latest_infra, latest_visual, latest_ssl, latest_wayback, latest_crawler, latest_cd, latest_tld] if r]

    
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
        "history_entries": history_entries, # Pass full history
        "current_history_id": history_id,
        "raw_results": jsonable_encoder([r.model_dump() for r in current_results]),
        "approved_ciphers": approved_ciphers_set
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
    
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain])
    return target

@app.get("/api/targets/", response_model=List[Target])
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target)).all()

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

@app.get("/settings", response_class=HTMLResponse)
async def view_settings(request: Request, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin"]))):
    from yads.models import SystemConfig
    
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
        
    # Custom Wordlist Status
    has_custom_wordlist = False
    custom_wordlist_lines = 0
    try:
        # Assuming run from root or predictable structure
        # yads/api/main.py -> yads/data/wordlists/subdomains.txt
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "subdomains.txt")
        if os.path.exists(wordlist_path):
            has_custom_wordlist = True
            with open(wordlist_path, 'rb') as f:
                custom_wordlist_lines = sum(1 for _ in f)
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

    return templates.TemplateResponse("settings.html", {
        "user": user,
        "request": request,
        "auto_queue": auto_queue,
        "rate_limit": rate_limit,
        "web_request_delay": web_request_delay,
        "web_request_timeout": web_request_timeout,
        "worker_concurrency": worker_concurrency,
        "approved_ciphers": approved_ciphers,
        "custom_dns_servers": custom_dns_servers,
        "has_custom_wordlist": has_custom_wordlist,
        "custom_wordlist_lines": custom_wordlist_lines,
        "session_minutes": session_minutes,
        "otp_window": otp_window,
        "splunk_hec_url": splunk_hec_url,
        "splunk_hec_token": splunk_hec_token,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_password": smtp_password
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
    approved_ciphers: str = Form(None),
    custom_dns_servers: str = Form(None),
    splunk_hec_url: str = Form(None),
    splunk_hec_token: str = Form(None),
    smtp_host: str = Form(None),
    smtp_port: str = Form(None),
    smtp_user: str = Form(None),
    smtp_password: str = Form(None),
    session: Session = Depends(get_session)
):
    from yads.models import SystemConfig
    
    # Update Auto Queue
    aq_conf = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
    if not aq_conf:
        aq_conf = SystemConfig(key="AUTO_QUEUE_SUBDOMAINS", value=str(auto_queue))
        session.add(aq_conf)
    else:
        aq_conf.value = str(auto_queue)
        session.add(aq_conf)
        
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
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Returns graph data (nodes, edges) for the Network Relationship visualization.
    Integrates DNS records and Subdomains.
    """
    from sqlmodel import or_, and_
    
    
    # Filter by user's tenant
    query = select(Target).where(Target.tenant_id == user.tenant_id)
    
    # 1. Online/Offline Filter
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
        
    targets = session.exec(query).all()
    
    nodes = {} # id -> {id, label, group, val}
    edges = [] # {from, to, arrows, label?}
    
    unique_edge_keys = set()
    
    def add_node(nid, label, group, value=1):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "group": group, "value": value}
        else:
            # Maybe upgrade group or increase value?
            if nodes[nid]["group"] == "ip" and group == "server":
                 nodes[nid]["group"] = "server"
            nodes[nid]["value"] = max(nodes[nid]["value"], value)
            
    def add_edge(src, dst, label=""):
        key = f"{src}-{dst}-{label}"
        if key not in unique_edge_keys:
            edges.append({"from": src, "to": dst, "arrows": "to", "label": label, "font": {"align": "middle", "size": 10}})
            unique_edge_keys.add(key)

    for t in targets:
        # 1. Target Node
        tgt_node_id = f"target_{t.id}"
        add_node(tgt_node_id, t.domain, "target", 20)
        
        # 2. Get DNS Scan Results (Includes Subdomain Scanner results usually if merged, but check module name)
        # We check both dns_scanner and subdomain_scanner results
        scans = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name.in_(["dns_scanner", "subdomain_scanner"])
        ).order_by(ScanResult.scanned_at.desc())).all()
        
        # Process latest of each type
        processed_modules = set()
        
        for scan in scans:
            if scan.module_name in processed_modules: continue
            processed_modules.add(scan.module_name)
            
            data = scan.data
            if not data: continue
            
            # A. DNS Records (A, MX, NS, CNAME)
            records = data.get("records", {})
            
            # A Records -> IPs
            for ip in records.get("A", []):
                ip_id = f"ip_{ip}"
                add_node(ip_id, ip, "ip", 5)
                add_edge(tgt_node_id, ip_id, "A")
            
            # MX Records
            for mx in records.get("MX", []):
                # MX often format: "10 mail.example.com"
                parts = mx.split()
                val = parts[-1] if parts else mx
                mx_id = f"mx_{val}"
                add_node(mx_id, val, "resource", 3)
                add_edge(tgt_node_id, mx_id, "MX")
                
            # NS Records
            for ns in records.get("NS", []):
                ns_id = f"ns_{ns}"
                add_node(ns_id, ns, "resource", 3)
                add_edge(tgt_node_id, ns_id, "NS")
                
            # CNAME
            for cn in records.get("CNAME", []):
                cn = cn.rstrip('.')
                cn_id = f"cname_{cn}"
                add_node(cn_id, cn, "resource", 3)
                add_edge(tgt_node_id, cn_id, "CNAME")

            # B. Subdomains
            subdomains = data.get("subdomains", [])
            # Subdomains is a list of dicts: {subdomain, ips}
            for sub in subdomains:
                sub_name = sub.get("subdomain")
                if not sub_name: continue
                
                sub_id = f"sub_{sub_name}"
                add_node(sub_id, sub_name.replace(f".{t.domain}", ""), "subdomain", 2) # Label: sub only
                add_edge(tgt_node_id, sub_id, "")
                
                # Link Subdomain -> IPs
                for ip in sub.get("ips", []):
                    ip_id = f"ip_{ip}"
                    add_node(ip_id, ip, "ip", 5)


                    add_edge(sub_id, ip_id, "A")

    # Filter Empty (Unconnected) Nodes
    if filter_empty:
        connected_ids = set()
        for e in edges:
            connected_ids.add(e["from"])
            connected_ids.add(e["to"])
        
        # Keep only connected nodes
        nodes = {nid: n for nid, n in nodes.items() if nid in connected_ids}

    return {
        "nodes": list(nodes.values()),
        "edges": edges
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
    Exports the Network Graph to SVG (Visio) or Excel (Visio Data Visualizer).
    """
    # Reuse existing logic to get nodes/edges
    graph_data = await get_network_graph(target_id=target_id, filter_empty=filter_empty, filter_online=filter_online, session=session, user=user)
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    
    if format == "svg":
        # Generate DOT source
        dot_lines = ["digraph NetworkGraph {", "  rankdir=LR;", "  node [shape=circle style=filled];"]
        
        # Add Nodes
        for n in nodes:
            # Map Vis.js groups to Graphviz colors/shapes
            color = "#cccccc"
            shape = "ellipse"
            group = n.get('group')
            if group == 'target': color = "lightblue"; shape="doublecircle"
            elif group == 'subdomain': color = "plum"
            elif group == 'ip': color = "orange"; shape="box"
            elif group == 'resource': color = "cyan"; shape="diamond"
            
            label = n.get('label', '').replace('"', '\\"')
            dot_lines.append(f'  "{n["id"]}" [label="{label}" fillcolor="{color}" shape="{shape}"];')
            
        # Add Edges
        for e in edges:
            dot_lines.append(f'  "{e["from"]}" -> "{e["to"]}";')
            
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
            
            svg_out, err = await proc.communicate(input=dot_source.encode('utf-8'))
            
            if proc.returncode != 0:
                logger.error(f"Graphviz Error: {err.decode()}")
                return Response(content=f"Error generating SVG: {err.decode()}", status_code=500)
                
            return Response(content=svg_out, media_type="image/svg+xml", headers={
                "Content-Disposition": 'attachment; filename="network_graph.svg"'
            })
        except FileNotFoundError:
             return Response(content="Graphviz (dot) not found on server.", status_code=500)
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
