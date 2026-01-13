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

router = APIRouter(
    prefix="/queue",
    tags=["queue"]
)

templates = Jinja2Templates(directory="yads/api/templates")

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

@router.post("/control", dependencies=[Depends(scanner_only)])
async def control_queue(
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
        # Stop Consumer
        celery_app.control.cancel_consumer('celery', reply=True)
    elif action == "resume":
        conf.value = "true"
        # Start Consumer - CRITICAL for processing
        celery_app.control.add_consumer('celery', reply=True)
        
    session.add(conf)
    session.commit()
    
    return RedirectResponse(url="/queue", status_code=303)
