from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from celery import Celery
from datetime import datetime

from yads.database import get_session
from yads.models import User, SystemConfig
from yads.auth.deps import get_current_user_html, RoleChecker
from yads.config import settings
import logging

router = APIRouter(
    prefix="/queue",
    tags=["queue"]
)

templates = Jinja2Templates(directory="yads/api/templates")

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

# Helper: Timestamp to Time Filter
def timestamp_to_time(ts):
    try:
        if not ts: return "-"
        return datetime.fromtimestamp(ts).strftime('%H:%M:%S')
    except:
        return str(ts)

templates.env.filters["timestamp_to_time"] = timestamp_to_time


@router.get("/", response_class=HTMLResponse)
async def view_queue(
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    # Fetch Pause Status
    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = True
    if conf and conf.value.lower() == "false":
        queue_active = False

    try:
        # Inspect Celery (Lazy Init to avoid Uvicorn/Multiprocessing issues)
        celery_app = Celery("yads_inspector", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
        i = celery_app.control.inspect()
        
        if i is None:
            raise Exception("Celery inspector returned None (Connection failed?)")

        # These return dicts of {worker_name: [tasks]} or None
        active_raw = i.active() or {}
        reserved_raw = i.reserved() or {}
        scheduled_raw = i.scheduled() or {}

        # Flatten lists
        active_tasks = []
        for worker, tasks in active_raw.items():
            for t in tasks:
                t['hostname'] = worker
                active_tasks.append(t)
                
        reserved_tasks = []
        for worker, tasks in reserved_raw.items():
            reserved_tasks.extend(tasks)
            
        scheduled_tasks = []
        for worker, tasks in scheduled_raw.items():
            scheduled_tasks.extend(tasks)

    except Exception as e:
        print(f"Error inspecting Celery: {e}")
        return templates.TemplateResponse("queue.html", {
            "request": request,
            "user": user,
            "active_tasks": [],
            "reserved_tasks": [],
            "scheduled_tasks": [],
            "queue_active": queue_active,
            "settings": settings,
            "error": f"Connection Error: {str(e)}"
        })
        
    # Inspect Redis Backlog (Queued items not yet picked up)
    import redis
    import json
    import base64

    queued_tasks = []
    queue_len = 0
    try:
        r = redis.from_url(settings.REDIS_URL, decode_responses=True)
        queue_len = r.llen("celery")
        # Peek top 50
        raw_items = r.lrange("celery", 0, 49)
        
        for raw in raw_items:
            try:
                item_data = json.loads(raw)
                # Helper to extract args safely
                domain = "?"
                scan_types = []
                # Celery Protocol v2: [args, kwargs, embedding]
                # Body is often base64 encoded pickle or json
                
                body_b64 = item_data.get('body')
                if body_b64:
                    try:
                        # Try standard base64 decoding
                        body_str = base64.b64decode(body_b64).decode('utf-8')
                        body_json = json.loads(body_str)
                        # Expecting [args, kwargs, embed]
                        # args: [target_id, domain, [scan_types]]
                        if isinstance(body_json, list) and len(body_json) > 0:
                            args = body_json[0]
                            if len(args) > 1: domain = args[1]
                            if len(args) > 2: scan_types = args[2]
                    except:
                        # Fallback if not base64 or complex body
                        domain = "Raw Data"

                queued_tasks.append({
                    "id": item_data.get('headers', {}).get('id', '?'),
                    "name": item_data.get('headers', {}).get('task', 'Unknown Task'),
                    "args": f"{domain} {scan_types}",
                    "domain": domain, 
                    "scan_types": scan_types
                })
            except Exception as e:
                 queued_tasks.append({"id": "?", "name": "Parse Error", "args": str(e)})

    except Exception as e:
        print(f"Redis Inspection Error: {e}")

    return templates.TemplateResponse("queue.html", {
        "request": request,
        "user": user,
        "active_tasks": active_tasks,
        "reserved_tasks": reserved_tasks,
        "scheduled_tasks": scheduled_tasks,
        "queued_tasks": queued_tasks, # New
        "queue_length": queue_len,    # New
        "queue_active": queue_active,
        "settings": settings
    })

# Admin/Scanner Only for Controls
scanner_only = RoleChecker(["admin", "tenant_admin", "scanner"])



@router.get("/widget", response_class=HTMLResponse)
async def get_queue_widget(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    """
    Returns a small HTML fragment with Queue Status and Controls.
    Used for the global header.
    """
    if user.role not in ["admin", "tenant_admin", "scanner"]:
        return ""

    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = True
    if conf and conf.value.lower() == "false":
        queue_active = False

    return templates.TemplateResponse("components/queue_widget.html", {
        "request": request,
        "queue_active": queue_active
    })

@router.post("/control", dependencies=[Depends(scanner_only)])
async def control_queue(
    request: Request,
    action: str = Form(...),
    session: Session = Depends(get_session)
):
    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    if not conf:
        conf = SystemConfig(key="QUEUE_ACTIVE", value="true")
        session.add(conf)
    
    # Connect to Celery for Control
    celery_app = Celery("yads_control", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

    if action == "pause":
        conf.value = "false"
        celery_app.control.cancel_consumer('celery', reply=True)
    elif action == "resume":
        conf.value = "true"
        celery_app.control.add_consumer('celery', reply=True)
        
    session.add(conf)
    session.commit()
    
    # HTMX Support: Return updated widget if requested
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("components/queue_widget.html", {
            "request": request,
            "queue_active": action == "resume"
        })

    return RedirectResponse(url="/queue", status_code=303)



@router.post("/purge", dependencies=[Depends(scanner_only)])
async def purge_queue(
    request: Request,
    session: Session = Depends(get_session)
):
    """
    Panic: Clear the queue.
    """
    import redis
    scan_logger = logging.getLogger("yads-api")
    
    try:
        # 1. Purge via Celery Control (Broker)
        celery_app = Celery("yads_purge", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
        purged_count = celery_app.control.purge()
        
        # 2. Force Clear Redis List 'celery' (just in case)
        r = redis.from_url(settings.REDIS_URL, decode_responses=True)
        r_count = r.delete("celery")
        
        # 3. REVOKE All Active & Reserved Tasks (The "Everything" part)
        scan_logger.warning("Revoking all active and reserved tasks...")
        # 3. REVOKE All Active & Reserved Tasks (The "Everything" part)
        scan_logger.warning("Revoking all active and reserved tasks...")
        i = celery_app.control.inspect()
        
        # Inspector can be None or return None types if no workers responding
        if i:
             # Stop Reserved (Pre-fetched but not started)
             reserved = i.reserved()
             if reserved:
                for worker, tasks in reserved.items():
                    if not tasks: continue
                    for task in tasks:
                        t_id = task.get("id")
                        scan_logger.info(f"Revoking RESERVED task: {t_id}")
                        celery_app.control.revoke(t_id, terminate=True)

             # Stop Active (Currently running)
             active = i.active()
             if active:
                for worker, tasks in active.items():
                    if not tasks: continue
                    for task in tasks:
                        t_id = task.get("id")
                        scan_logger.info(f"Revoking ACTIVE task: {t_id}")
                        # terminate=True kills the worker process executing the task
                        celery_app.control.revoke(t_id, terminate=True)
        else:
            scan_logger.warning("Celery Inspector failed/timed out. Could not revoke running tasks (ghosts may remain until worker restart).")
        
        scan_logger.warning(f"Queue Purged! Celery Purged: {purged_count}, Redis Deleted: {r_count}")
        
        # 4. RESET Database Status (The Missing Link)
        # Fixes "Zombie" statuses in the UI for tasks that were just deleted
        from yads.models import Target
        from sqlmodel import or_
        
        # Reset all 'queued' or 'running' targets to 'idle'
        # or_() needs col expression
        statement = select(Target).where(or_(Target.scan_status == "queued", Target.scan_status == "running"))
        zombies = session.exec(statement).all()
        
        reset_count = 0
        for z in zombies:
            z.scan_status = "idle" 
            z.scan_progress = "Stopped by Queue Purge"
            session.add(z)
            reset_count += 1
            
        session.commit()
        scan_logger.warning(f"Reset {reset_count} zombie targets in DB.")

    except Exception as e:
        scan_logger.error(f"Failed to purge queue: {e}")
        # Even on error, we might want to return the widget if HTMX, but let's stick to redirect for error visibility or handle IT
        # For simplicity, if HTMX, we just return the widget and maybe log to console/toast?
        # The user wants the layout fixed. 
        if request.headers.get("HX-Request"):
             # Get current state for widget re-render
             conf = session.get(SystemConfig, "QUEUE_ACTIVE")
             queue_active = True
             if conf and conf.value.lower() == "false":
                 queue_active = False
                 
             return templates.TemplateResponse("components/queue_widget.html", {
                "request": request,
                "queue_active": queue_active
             })

        return RedirectResponse(url=f"/queue?error=Purge+Failed:+{e}", status_code=303)

    # HTMX Support: Return updated widget
    if request.headers.get("HX-Request"):
         # Get current state for widget re-render
         conf = session.get(SystemConfig, "QUEUE_ACTIVE")
         queue_active = True
         if conf and conf.value.lower() == "false":
             queue_active = False
             
         return templates.TemplateResponse("components/queue_widget.html", {
            "request": request,
            "queue_active": queue_active
         })

    return RedirectResponse(url="/queue?msg=Queue+Cleared", status_code=303)
