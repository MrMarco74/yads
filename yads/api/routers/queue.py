from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from celery import Celery
from datetime import datetime

from yads.database import get_session, redis_client
from yads.models import User, SystemConfig
from yads.auth.deps import get_current_user_html, RoleChecker
from yads.config import settings
import logging

scan_logger = logging.getLogger(__name__)

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


def extract_tenant_from_task(task: dict) -> int | None:
    """
    Extract tenant_id from a Celery task dict.
    Task args are: [target_id, domain, scan_types, tenant_id]
    """
    try:
        args = task.get('args', [])
        if isinstance(args, (list, tuple)) and len(args) > 3:
            return args[3]  # tenant_id is at position 3
    except:
        pass
    return None


def filter_tasks_by_tenant(tasks: list, tenant_id: int) -> list:
    """Filter task list to only include tasks belonging to specified tenant."""
    if tenant_id is None:
        return tasks  # Platform admin without tenant sees all
    
    filtered = []
    for task in tasks:
        task_tenant = extract_tenant_from_task(task)
        # Include task if:
        # 1. task_tenant matches user's tenant, OR
        # 2. task_tenant is None (legacy tasks without tenant_id - show to admin only)
        if task_tenant == tenant_id:
            filtered.append(task)
    return filtered


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

        # Filter by tenant (unless platform admin with no tenant)
        active_tasks = filter_tasks_by_tenant(active_tasks, user.tenant_id)
        reserved_tasks = filter_tasks_by_tenant(reserved_tasks, user.tenant_id)
        scheduled_tasks = filter_tasks_by_tenant(scheduled_tasks, user.tenant_id)

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
    import json
    import base64

    queued_tasks = []
    queue_len = 0  # Total global queue length
    tenant_queue_len = 0  # Tenant-filtered queue length
    try:
        r = redis_client
        queue_len = r.llen("celery")
        # Peek top 100 to allow for filtering
        raw_items = r.lrange("celery", 0, 99)
        
        for raw in raw_items:
            try:
                item_data = json.loads(raw)
                # Helper to extract args safely
                domain = "?"
                scan_types = []
                task_tenant_id = None
                # Celery Protocol v2: [args, kwargs, embedding]
                # Body is often base64 encoded pickle or json
                
                body_b64 = item_data.get('body')
                if body_b64:
                    try:
                        # Try standard base64 decoding
                        body_str = base64.b64decode(body_b64).decode('utf-8')
                        body_json = json.loads(body_str)
                        # Expecting [args, kwargs, embed]
                        # args: [target_id, domain, scan_types, tenant_id]
                        if isinstance(body_json, list) and len(body_json) > 0:
                            args = body_json[0]
                            if len(args) > 1: domain = args[1]
                            if len(args) > 2: scan_types = args[2]
                            if len(args) > 3: task_tenant_id = args[3]
                    except:
                        # Fallback if not base64 or complex body
                        domain = "Raw Data"

                # Filter by tenant
                if user.tenant_id is not None and task_tenant_id != user.tenant_id:
                    continue  # Skip tasks from other tenants

                tenant_queue_len += 1
                queued_tasks.append({
                    "id": item_data.get('headers', {}).get('id', '?'),
                    "name": item_data.get('headers', {}).get('task', 'Unknown Task'),
                    "args": f"{domain} {scan_types}",
                    "domain": domain, 
                    "scan_types": scan_types,
                    "tenant_id": task_tenant_id
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
        "queued_tasks": queued_tasks,
        "queue_length": tenant_queue_len,  # Show tenant-filtered count
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
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """
    Clear queue for current tenant only.
    Does NOT affect other tenants' tasks.
    """
    import json
    import base64
    
    try:
        celery_app = Celery("yads_purge", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
        r = redis_client
        
        # 1. Selectively remove from Redis queue (only tenant's tasks)
        # Instead of purging all, we need to:
        # - Read all items from queue
        # - Keep items NOT belonging to this tenant
        # - Remove items belonging to this tenant
        purged_count = 0
        
        queue_len = r.llen("celery")
        if queue_len > 0:
            # Get all items
            all_items = r.lrange("celery", 0, -1)
            items_to_keep = []
            
            for raw in all_items:
                try:
                    item_data = json.loads(raw)
                    task_tenant_id = None
                    
                    body_b64 = item_data.get('body')
                    if body_b64:
                        try:
                            body_str = base64.b64decode(body_b64).decode('utf-8')
                            body_json = json.loads(body_str)
                            if isinstance(body_json, list) and len(body_json) > 0:
                                args = body_json[0]
                                if len(args) > 3:
                                    task_tenant_id = args[3]
                        except:
                            pass
                    
                    # Keep if NOT this tenant's task
                    if task_tenant_id != user.tenant_id:
                        items_to_keep.append(raw)
                    else:
                        purged_count += 1
                        
                except:
                    # If we can't parse, keep it to be safe
                    items_to_keep.append(raw)
            
            # Atomically replace queue with filtered items
            if purged_count > 0:
                pipe = r.pipeline()
                pipe.delete("celery")
                for item in items_to_keep:
                    pipe.rpush("celery", item)
                pipe.execute()
        
        # 2. REVOKE Active & Reserved Tasks (Tenant-Filtered)
        scan_logger.warning(f"Revoking active and reserved tasks for tenant {user.tenant_id}...")
        i = celery_app.control.inspect()
        revoked_count = 0
        
        if i:
            # Stop Reserved (Pre-fetched but not started)
            reserved = i.reserved()
            if reserved:
                for worker, tasks in reserved.items():
                    if not tasks: continue
                    for task in tasks:
                        task_tenant = extract_tenant_from_task(task)
                        if task_tenant == user.tenant_id:
                            t_id = task.get("id")
                            scan_logger.info(f"Revoking RESERVED task: {t_id}")
                            celery_app.control.revoke(t_id, terminate=True)
                            revoked_count += 1

            # Stop Active (Currently running)
            active = i.active()
            if active:
                for worker, tasks in active.items():
                    if not tasks: continue
                    for task in tasks:
                        task_tenant = extract_tenant_from_task(task)
                        if task_tenant == user.tenant_id:
                            t_id = task.get("id")
                            scan_logger.info(f"Revoking ACTIVE task: {t_id}")
                            celery_app.control.revoke(t_id, terminate=True)
                            revoked_count += 1
        else:
            scan_logger.warning("Celery Inspector failed/timed out.")
        
        scan_logger.warning(f"Tenant Queue Purged! Removed: {purged_count}, Revoked: {revoked_count}")
        
        # 3. RESET Database Status - TENANT AWARE
        from yads.models import Target
        from sqlmodel import or_, and_
        
        statement = select(Target).where(
            and_(
                Target.tenant_id == user.tenant_id,
                or_(Target.scan_status == "queued", Target.scan_status == "running")
            )
        )
        zombies = session.exec(statement).all()
        
        reset_count = 0
        for z in zombies:
            z.scan_status = "idle" 
            z.scan_progress = "Stopped by Queue Purge"
            session.add(z)
            reset_count += 1
            
        session.commit()
        scan_logger.warning(f"Reset {reset_count} zombie targets in DB for tenant {user.tenant_id}.")

    except Exception as e:
        scan_logger.error(f"Failed to purge queue: {e}")
        if request.headers.get("HX-Request"):
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
        conf = session.get(SystemConfig, "QUEUE_ACTIVE")
        queue_active = True
        if conf and conf.value.lower() == "false":
            queue_active = False
             
        return templates.TemplateResponse("components/queue_widget.html", {
            "request": request,
            "queue_active": queue_active
        })

    return RedirectResponse(url="/queue?msg=Queue+Cleared", status_code=303)

