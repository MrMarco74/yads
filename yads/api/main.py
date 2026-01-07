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
    valid_types = ["dns_scanner", "web_analyzer", "typosquat_scanner", "infrastructure_scanner", "visual_osint"]
    selected_types = [t for t in scan_types if t in valid_types]
    
    if not selected_types:
        # Fallback to all if none selected (or if triggered without form)
        selected_types = valid_types

    # Trigger Celery Task
    celery_app.send_task("yads.worker.run_all_scans", args=[target.id, target.domain, selected_types])
    
    return RedirectResponse(url=f"/targets/{target_id}", status_code=303)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: Session = Depends(get_session)):
    # Fetch all targets
    targets = session.exec(select(Target)).all()
    
    # Calculate stats
    total_targets = len(targets)
    total_scans_count = session.exec(select(func.count(ScanResult.id))).one()
    
    # Calculate Last Scan for each target per module
    # Structure: last_scans[target_id] = {'dns_scanner': datetime, 'web_analyzer': datetime}
    last_scans = {}
    
    # Optimized query? For now, simple loop is fine for small scale.
    # We want the max last_scanned_at for each module for each target.
    # session.exec(select(ModuleState).where(...))
    
    # Bulk fetch all module states
    all_states = session.exec(select(ModuleState)).all()
    
    for state in all_states:
        if state.target_id not in last_scans:
            last_scans[state.target_id] = {}
        last_scans[state.target_id][state.module_name] = state.last_scanned_at

    return templates.TemplateResponse("index.html", {
        "request": request,
        "targets": targets,
        "last_scans": last_scans,
        "stats": {
            "active_targets": total_targets,
            "services_monitored": "-",  # Placeholder
            "total_scans": total_scans_count
        }
    })

@app.get("/dashboard/targets", response_class=HTMLResponse)
async def dashboard_targets(request: Request, session: Session = Depends(get_session)):
    """
    HTMX endpoint to poll for target list updates (status/progress).
    Returns just the table rows/grid.
    """
    targets = session.exec(select(Target).order_by(Target.created_at.desc())).all()
    
    # We need to calculate last_scans for the fragment too, or just mock it?
    # Ideally replicate logic or extract it.
    last_scans = {}
    all_states = session.exec(select(ModuleState)).all()
    for state in all_states:
        if state.target_id not in last_scans:
            last_scans[state.target_id] = {}
        last_scans[state.target_id][state.module_name] = state.last_scanned_at

    return templates.TemplateResponse("_target_list.html", {"request": request, "targets": targets, "last_scans": last_scans})


@app.get("/logs", response_class=HTMLResponse)
async def view_logs_page(request: Request):
    return templates.TemplateResponse("logs.html", {"request": request})

@app.get("/api/logs/stream")
async def get_logs_stream():
    """Reads the last 100 lines of the shared log file."""
    log_file = os.path.join(os.getenv("LOG_DIR", "logs"), "yads.log")
    if not os.path.exists(log_file):
        return {"logs": ["Log file not found."]}
    
    async with aiofiles.open(log_file, mode='r') as f:
        content = await f.read()
        lines = content.splitlines()
        return {"logs": lines[-100:]}

@app.post("/targets/add", response_class=HTMLResponse)
async def ui_add_target(request: Request, domain: str = Form(...), session: Session = Depends(get_session)):
    """HTMX endpoint to add a target"""
    domain = domain.lower().strip()
    existing = session.exec(select(Target).where(Target.domain == domain)).first()
    
    if not existing:
        target = Target(domain=domain)
        session.add(target)
        session.commit()
        session.refresh(target)
        # Trigger Scan
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
        current_results = [r for r in [latest_dns, latest_web, latest_typosquat, latest_infra, latest_visual] if r]

    
    # Extract specific results for template
    dns_result = next((r for r in current_results if r.module_name == 'dns_scanner'), None)
    web_result = next((r for r in current_results if r.module_name == 'web_analyzer'), None)
    typosquat_result = next((r for r in current_results if r.module_name == 'typosquat_scanner'), None)
    infra_result = next((r for r in current_results if r.module_name == 'infrastructure_scanner'), None)
    visual_result = next((r for r in current_results if r.module_name == 'visual_osint'), None)
    
    return templates.TemplateResponse("target_detail.html", {
        "request": request,
        "target": target,
        "dns_result": dns_result,
        "web_result": web_result,
        "typosquat_result": typosquat_result,
        "infra_result": infra_result,
        "visual_result": visual_result,
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
