from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.encoders import jsonable_encoder
from sqlmodel import Session, select, func, create_engine, text
from contextlib import asynccontextmanager
import os
import aiofiles
from yads.modules.visual_osint import VisualOSINT
from yads.modules.report_generator import generate_report

from yads.config import settings
from yads.models import Target, ScanResult, ModuleState
from yads.core.logging_config import configure_logging

# -- Logging Setup --
logger = configure_logging("yads-api")

# -- DB Setup --
engine = create_engine(settings.DATABASE_URL, echo=False)

def get_session():
    with Session(engine) as session:
        yield session

def create_db_and_tables():
    from yads.models import SQLModel
    SQLModel.metadata.create_all(engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    import time
    from sqlalchemy.exc import OperationalError
    
    max_retries = 10
    for i in range(max_retries):
        try:
            create_db_and_tables()
            logger.info("Database connected and tables created.")
            
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
            from yads.worker import celery_app
            # We must import celery_app here or at top. 
            # Note: importing worker inside main might cause circular import if worker imports main.
            # worker.py imports settings, logging, modules. It does NOT import main. Safe.
            
            try:
                # Cancel consumer to stop processing queue
                celery_app.control.cancel_consumer('celery', reply=True)
                logger.info("Auto-start disabled: Queue execution paused.")
            except Exception as e:
                logger.warning(f"Failed to pause worker on boot: {e}")
                
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


# -- UI Routes --

@app.post("/targets/{target_id}/scan")
async def trigger_scan(target_id: int, request: Request, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # Parse form data for scan types
    form = await request.form()
    scan_types = form.getlist("scan_types") # Returns list of values for keys named "scan_types"
    
    # Validation/Default
    valid_types = ["dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint", "ssl_scanner"]
    selected_types = [t for t in scan_types if t in valid_types]
    
    if not selected_types:
        # Fallback to all if none selected (or if triggered without form)
        selected_types = valid_types

    # Trigger Celery Task
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, selected_types])
    
    return RedirectResponse(url=f"/targets/{target_id}", status_code=303)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: Session = Depends(get_session)):
    # Calculate stats (Total Count)
    total_targets = session.exec(select(func.count()).select_from(Target)).one()
    total_scans_count = session.exec(select(func.count(ScanResult.id))).one()
    
    # Pagination defaults for initial load
    page = 1
    limit = 9
    offset = 0
    
    # Fetch Paginated Targets
    targets = session.exec(select(Target).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
    # Fetch Active Scans
    active_scans = session.exec(select(Target).where(Target.scan_status == "running")).all()
    
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
        }
    })


@app.get("/dashboard/stats", response_class=HTMLResponse)
async def dashboard_stats(request: Request, session: Session = Depends(get_session)):
    """HTMX endpoint for auto-updating stats"""
    total_targets = session.exec(select(func.count()).select_from(Target)).one()
    total_scans_count = session.exec(select(func.count(ScanResult.id))).one()
    
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
        }
    })

@app.get("/dashboard/targets", response_class=HTMLResponse)
async def dashboard_targets(request: Request, page: int = 1, limit: int = 9, session: Session = Depends(get_session)):
    """
    HTMX endpoint to poll for target list updates (status/progress).
    Returns just the table rows/grid.
    """
    offset = (page - 1) * limit
    total_count = session.exec(select(func.count()).select_from(Target)).one()
    
    # Fetch Paginated
    targets = session.exec(select(Target).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
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
            }
        })


@app.get("/logs", response_class=HTMLResponse)
async def view_logs_page(request: Request):
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
        "current_log": default_log
    })

@app.get("/api/logs/stream")
async def get_logs_stream(file: str = "yads-api.log"):
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
async def ui_add_target(request: Request, domain: str = Form(...), session: Session = Depends(get_session)):
    """HTMX endpoint to add a target"""
    domain = domain.lower().strip()
    existing = session.exec(select(Target).where(Target.domain == domain)).first()
    
    if existing:
        target = existing
    else:
        target = Target(domain=domain)
        session.add(target)
        session.commit()
        session.refresh(target)
        
    # Always Trigger Scan (New or Existing)
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain])
    
    # Return standard target list row fragment or redirect
    return await dashboard(request, session) 
    # In a real HTMX app, we'd return just the new row or the updated list fragment.
    # For simplicity, refreshing the page or returning full page is easiest for now.

@app.delete("/targets/{target_id}")
async def delete_target(target_id: int, request: Request, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
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


# -- Table View & Bulk Actions --

@app.get("/targets/table", response_class=HTMLResponse)
async def view_target_table(request: Request, page: int = 1, limit: int = 20, session: Session = Depends(get_session)):
    """
    Renders a detailed table view of all targets with bulk actions.
    Supports pagination.
    """
    # Calculate offset
    offset = (page - 1) * limit
    
    # Get Total Count
    total_count = session.exec(select(func.count()).select_from(Target)).one()
    
    # Fetch Paginated Targets
    targets = session.exec(select(Target).order_by(Target.created_at.desc()).offset(offset).limit(limit)).all()
    
    # Calculate Total Pages
    total_pages = (total_count + limit - 1) // limit
    
    # Prepare table rows with summary data to avoid complex Jinja logic
    table_rows = []
    for t in targets:
        results = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).all()
        
        # Summaries
        dns = next((r for r in results if r.module_name == 'dns_scanner'), None)
        ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
        web = next((r for r in results if r.module_name == 'web_analyzer'), None)
        infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
        
        # Online Status Logic
        is_online = None # Unknown
        if infra or web:
            # Check for IP
            has_ip = False
            if infra and infra.data and infra.data.get("ip"):
                has_ip = True
            
            # Check for HTTP
            has_http = False
            if web and web.data and web.data.get("status_code"):
                code = web.data.get("status_code")
                # Valid explicit response (even 403 or 500 means "online" server)
                if isinstance(code, int) and code > 0:
                    has_http = True
            
            if has_ip or has_http:
                is_online = True
            else:
                 # If we have scans but no IP and no HTTP, likely offline
                is_online = False

        row_data = {
            "target": t,
            "is_online": is_online,
            "dns_ip": dns.data.get("a_records", [""])[0] if (dns and dns.data and dns.data.get("a_records")) else None,
            "dns_count": len(dns.data.get("subdomains", [])) if (dns and dns.data) else 0,
            "ssl_issuer": ssl.data.get("issuer", {}).get("commonName") if (ssl and ssl.data and not ssl.data.get("error")) else None,
            "ssl_expiry": ssl.data.get("notAfter") if (ssl and ssl.data and not ssl.data.get("error")) else None,
            "web_server": web.data.get("server_header") if (web and web.data) else None,
            "asn": infra.data.get("asn", {}).get("asn") if (infra and infra.data) else None,
            "last_scan": results[0].scanned_at if results else None,
            "modules": list(set([r.module_name for r in results]))
        }
        table_rows.append(row_data)

        table_rows.append(row_data)

    return templates.TemplateResponse("target_table.html", {
        "request": request, 
        "rows": table_rows,
        "pagination": {
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "total_count": total_count,
            "start_item": offset + 1,
            "end_item": min(offset + limit, total_count)
        }
    })

@app.post("/targets/bulk/scan", response_class=HTMLResponse)
async def bulk_scan_targets(
    request: Request,
    scan_types: List[str] = Form(default=[]), 
    session: Session = Depends(get_session)
):
    form = await request.form()
    target_ids = form.getlist("target_ids") 
    
    if not target_ids:
         return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)
         
    scan_types_selected = form.getlist("scan_types")
    
    valid_types = ["dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint", "ssl_scanner"]
    final_types = [t for t in scan_types_selected if t in valid_types]
    if not final_types:
        final_types = valid_types

    count = 0
    for tid_str in target_ids:
        try:
            tid = int(tid_str)
            target = session.get(Target, tid)
            if target:
                celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, final_types])
                count += 1
        except:
            continue
            
    return RedirectResponse(url=f"/targets/table?msg=Queued+{count}+scans", status_code=303)

@app.post("/targets/import", response_class=HTMLResponse)
async def bulk_import_targets(
    request: Request,
    session: Session = Depends(get_session)
):
    form = await request.form()
    raw_text = form.get("targets_raw", "")
    next_url = form.get("next", "/dashboard/targets")
    verify_dns = form.get("verify_dns") == "true"
    
    if not raw_text:
        return RedirectResponse(url=f"{next_url}?msg=No+data+provided", status_code=303)
        
    # Split lines and process
    lines = [l.strip() for l in raw_text.splitlines() if l.strip()]
    
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
        
        # Check duplicate
        existing = session.exec(select(Target).where(Target.domain == domain)).first()
        if existing:
            duplicate_count += 1
            continue
            
        # Create
        new_target = Target(domain=domain)
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
    request: Request,
    target_ids: List[int] = Form(...),
    session: Session = Depends(get_session)
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
        
        # 2. Delete Targets
        session.exec(text(f"DELETE FROM target WHERE id IN ({ids_str})"))
        
        session.commit()
    
    count = len(ids_to_delete)
    revoke_count = len(tasks_to_revoke) if 'tasks_to_revoke' in locals() else 0
    msg = f"Deleted+{count}+targets"
    if revoke_count > 0:
        msg += f"+(Stopped+{revoke_count}+scans)"
        
    return RedirectResponse(url=f"/targets/table?msg={msg}", status_code=303)


@app.post("/scans/stop-all")
async def stop_all_scans(session: Session = Depends(get_session)):
    # 1. Purge Pending Queue
    purged_count = celery_app.control.purge()
    
    # 2. Attempt to Revoke Running Tasks
    i = celery_app.control.inspect()
    active = i.active() if i else None
    revoked_count = 0
    
    if active:
        for worker, tasks in active.items():
            for task in tasks:
                 task_id = task.get("id")
                 if task_id:
                     celery_app.control.revoke(task_id, terminate=True)
                     revoked_count += 1
    
    # 3. Update DB Status
    statement = select(Target).where(Target.scan_status.in_(["scanning", "queued"]))
    targets = session.exec(statement).all()
    
    db_updated_count = 0
    for t in targets:
        t.scan_status = "stopped"
        t.scan_progress = "Manually stopped"
        session.add(t)
        db_updated_count += 1
        
    session.commit()
    
    msg = f"Stopped!+Purged:+{purged_count},+Revoked:+{revoked_count},+DB+Updated:+{db_updated_count}"
    return RedirectResponse(url=f"/dashboard/targets?msg={msg}", status_code=303)


# -- Queue Management Routes --
import redis

@app.get("/queue", response_class=HTMLResponse)
async def view_queue(request: Request, session: Session = Depends(get_session)):
    # Connect to Redis to peek at the queue
    # Celery default queue key is 'celery'
    try:
        r = redis.from_url(settings.REDIS_URL, decode_responses=True)
        queue_len = r.llen("celery")
        # Peek top 50
        queue_items = r.lrange("celery", 0, 49) 
    except Exception as e:
        queue_len = "Error connecting to Redis"
        queue_items = [str(e)]

    # Check Active/Paused Config
    from yads.models import SystemConfig
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    # Default to False (Paused) if not set, as per user request for "no auto start"
    queue_active = False 
    if config:
        queue_active = config.value.lower() == "true"
        
    return templates.TemplateResponse("queue.html", {
        "request": request,
        "queue_length": queue_len,
        "queue_items": queue_items,
        "queue_active": queue_active
    })

@app.post("/queue/control")
async def control_queue(request: Request, action: str = Form(...), session: Session = Depends(get_session)):
    from yads.models import SystemConfig
    
    config = session.get(SystemConfig, "QUEUE_ACTIVE")
    if not config:
        config = SystemConfig(key="QUEUE_ACTIVE", value="false")
        session.add(config)
    
    if action == "start":
        # Enable Consumer
        celery_app.control.add_consumer('celery', reply=True)
        config.value = "true"
        msg = "Queue+Processing+Started"
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
        return await dashboard_stats(request, session)
        
    return RedirectResponse(url=f"/queue?msg={msg}", status_code=303)


# -- Graph View --

@app.get("/targets/graph", response_class=HTMLResponse)
async def view_graph_page(request: Request, session: Session = Depends(get_session)):
    """
    Renders the Graph View page.
    """
    targets = session.exec(select(Target)).all()
    return templates.TemplateResponse("graph.html", {"request": request, "targets": targets})


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
async def export_target_pdf(target_id: int, session: Session = Depends(get_session)):
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
async def view_target_detail(request: Request, target_id: int, history_id: Optional[int] = None, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
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
        latest_dns = next((r for r in history_entries if r.module_name == 'dns_scanner'), None)
        latest_web = next((r for r in history_entries if r.module_name == 'web_analyzer'), None)
        latest_typosquat = next((r for r in history_entries if r.module_name == 'typosquat_scanner'), None)
        latest_infra = next((r for r in history_entries if r.module_name == 'infrastructure_scanner'), None)
        latest_visual = next((r for r in history_entries if r.module_name == 'visual_osint'), None)
        latest_ssl = next((r for r in history_entries if r.module_name == 'ssl_scanner'), None)
        current_results = [r for r in [latest_dns, latest_web, latest_typosquat, latest_infra, latest_visual, latest_ssl] if r]

    
    # Extract specific results for template
    dns_result = next((r for r in current_results if r.module_name == 'dns_scanner'), None)
    web_result = next((r for r in current_results if r.module_name == 'web_analyzer'), None)
    typosquat_result = next((r for r in current_results if r.module_name == 'typosquat_scanner'), None)
    infra_result = next((r for r in current_results if r.module_name == 'infrastructure_scanner'), None)
    visual_result = next((r for r in current_results if r.module_name == 'visual_osint'), None)
    ssl_result = next((r for r in current_results if r.module_name == 'ssl_scanner'), None)
    
    return templates.TemplateResponse("target_detail.html", {
        "request": request,
        "target": target,
        "dns_result": dns_result,
        "web_result": web_result,
        "typosquat_result": typosquat_result,
        "infra_result": infra_result,
        "visual_result": visual_result,
        "ssl_result": ssl_result,
        "history_entries": history_entries, # Pass full history
        "current_history_id": history_id,
        "raw_results": jsonable_encoder([r.model_dump() for r in current_results]) 
    })




# -- API Endpoints (Legacy/JSON) --

@app.post("/api/targets/", response_model=Target)
def add_target(domain: str, session: Session = Depends(get_session)):
    domain = domain.lower().strip()
    existing = session.exec(select(Target).where(Target.domain == domain)).first()
    if existing:
        target = existing
    else:
        target = Target(domain=domain)
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

# -- Settings Routes --

@app.get("/settings", response_class=HTMLResponse)
async def view_settings(request: Request, session: Session = Depends(get_session)):
    from yads.models import SystemConfig
    
    # Defaults
    auto_queue = settings.AUTO_QUEUE_SUBDOMAINS
    rate_limit = settings.SCAN_QUEUE_RATE_LIMIT
    worker_concurrency = 4 # Default if not set
    
    # Load from DB
    aq_conf = session.get(SystemConfig, "AUTO_QUEUE_SUBDOMAINS")
    if aq_conf:
        auto_queue = aq_conf.value.lower() == 'true'
        
    rl_conf = session.get(SystemConfig, "SCAN_QUEUE_RATE_LIMIT")
    if rl_conf:
        rate_limit = rl_conf.value

    wc_conf = session.get(SystemConfig, "WORKER_CONCURRENCY")
    if wc_conf:
        try:
            worker_concurrency = int(wc_conf.value)
        except:
            pass
        
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "auto_queue": auto_queue,
        "rate_limit": rate_limit,
        "worker_concurrency": worker_concurrency
    })

@app.post("/settings", response_class=HTMLResponse)
async def update_settings(
    request: Request, 
    auto_queue: bool = Form(False), 
    rate_limit: str = Form(...),
    worker_concurrency: int = Form(4),
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
    
    session.commit()
    
    # Broadcast Updates
    
    # 1. Rate Limit
    if rate_limit:
        try:
             celery_app.control.rate_limit("yads.worker.run_all_scans", rate_limit)
        except Exception:
             pass

    # 2. Worker Concurrency (Autoscale)
    try:
        # Set min=max to force fixed concurrency
        celery_app.control.autoscale(max=worker_concurrency, min=worker_concurrency)
    except Exception:
        pass

    return RedirectResponse(url="/settings?saved=true", status_code=303)

@app.post("/admin/reset", response_class=HTMLResponse)
async def admin_reset(session: Session = Depends(get_session)):
    """
    Resets the system:
    1. Purges Redis Queue
    2. Deletes DB Data (Targets, ScanResults, ModuleStates)
    """
    # 1. Purge Queue
    try:
        celery_app.control.purge()
    except Exception as e:
        logger.error(f"Failed to purge queue: {e}")

    # 2. Delete Data
    # Truncate tables (Cascading usually handles it, but we do explicit delete for safety/clarity)
    session.exec(text("DELETE FROM scanresult"))
    session.exec(text("DELETE FROM modulestate"))
    session.exec(text("DELETE FROM target"))
    
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





