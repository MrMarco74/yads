from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from celery import Celery
from datetime import datetime

from yads.database import get_session, redis_client
from yads.models import User, SystemConfig, Target
from yads.auth.deps import get_current_user_html, RoleChecker
from yads.config import settings
from yads.api.utils.celery_inspect import get_celery_worker_nodes
from yads.core.module_status import get_rate_limited_module_count
import logging

scan_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/queue",
    tags=["queue"]
)

# from fastapi.templating import Jinja2Templates
from yads.api.templating import templates

def mark_task_cancelled(task_id: str):
    """
    Persist cancellation in Redis (independent of Celery's in-memory revoke
    state) so a redelivered copy of an acks_late task aborts on startup even
    if it lands on a worker process that never received the revoke broadcast
    (e.g. a child freshly spawned by --autoscale after the original was
    SIGTERM'd). See run_all_scans' cancellation check in worker_tasks.py.
    """
    if not task_id:
        return
    try:
        redis_client.setex(f"yads:cancelled_task:{task_id}", 3600, "1")
    except Exception as e:
        scan_logger.warning(f"Failed to persist cancellation for task {task_id}: {e}")


def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

# Helper: Timestamp to Time Filter
# (Moved to templating.py)

# Helper: Prettify Task Name
def prettify_task_name(name):
    if not name: return "Unknown"
    if name == "yads.worker.run_all_scans":
        return "Standard Scan"
    return name.split('.')[-1]

templates.env.filters["prettify_task"] = prettify_task_name


def extract_tenant_from_task(task: dict) -> int | None:
    """
    Extract tenant_id from a Celery task dict.
    Task args are: [target_id, domain, scan_types, tenant_id]
    """
    try:
        args = task.get('args', [])
        if isinstance(args, (list, tuple)) and len(args) > 3:
            return args[3]  # tenant_id is at position 3
    except Exception as e:
        scan_logger.debug(f"Could not extract tenant from task: {e}")
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

    active_tasks = []
    reserved_tasks = []
    scheduled_tasks = []
    worker_nodes = []
        
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
                    except Exception as e:
                        scan_logger.debug(f"Failed to decode item body: {e}")
                        # Fallback if not base64 or complex body
                        domain = "Raw Data"

                # Filter by tenant
                if user.tenant_id is not None and task_tenant_id != user.tenant_id:
                    continue  # Skip tasks from other tenants

                tenant_queue_len += 1
                queued_tasks.append({
                    "id": item_data.get('headers', {}).get('id', '?'),
                    "name": prettify_task_name(item_data.get('headers', {}).get('task', 'Unknown Task')),
                    "args": f"{domain} {scan_types}",
                    "domain": domain, 
                    "scan_types": scan_types,
                    "tenant_id": task_tenant_id
                })
            except Exception as e:
                 queued_tasks.append({"id": "?", "name": "Parse Error", "args": str(e)})

    except Exception as e:
        print(f"Redis Inspection Error: {e}")

    # --- Database Fallback/Sync ---
    # Fetch targets marked as 'queued' in DB that aren't already decoded from Redis.
    # This covers items when the worker is paused/down (tasks in DB but not yet dispatched to Redis).
    from yads.models import Target
    from sqlmodel import func as sqlfunc
    db_queued = []
    db_queued_total = 0
    try:
        redis_domains = {q['domain'] for q in queued_tasks}
        stmt = select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.scan_status == "queued",
            Target.is_archived == False,
        ).limit(100)
        results = session.exec(stmt).all()
        for t in results:
            if t.domain not in redis_domains:
                db_queued.append({
                    "id": f"db-{t.id}",
                    "name": "Standard Scan",
                    "args": t.domain,
                    "domain": t.domain,
                    "scan_types": [],
                    "tenant_id": t.tenant_id,
                    "source": "database"
                })
        # Authoritative count from DB (all statuses, not just top-100)
        db_queued_total = session.exec(
            select(sqlfunc.count()).select_from(Target).where(
                Target.tenant_id == user.tenant_id,
                Target.scan_status == "queued",
                Target.is_archived == False,
            )
        ).one()
    except Exception as e:
        print(f"DB Queue Fetch Error: {e}")

    all_queued = queued_tasks + db_queued

    # queue_length: use DB as authoritative total (avoids Redis top-100 cap)
    # db_queued_total already covers everything; Redis-decoded tasks are a subset of those.
    queue_length = db_queued_total

    return templates.TemplateResponse("queue.html", {
        "request": request,
        "user": user,
        "active_tasks": active_tasks,
        "reserved_tasks": reserved_tasks,
        "scheduled_tasks": scheduled_tasks,
        "queued_tasks": all_queued,
        "queue_length": queue_length,
        "queue_active": queue_active,
        "worker_nodes": worker_nodes,
        "settings": settings
    })

@router.get("/celery-live", response_class=HTMLResponse)
async def queue_celery_live(
    request: Request,
    user: User = Depends(get_current_user_html),
):
    """HTMX partial — Celery live data (worker nodes + active/reserved/scheduled)."""
    worker_nodes = get_celery_worker_nodes()
    active_tasks, reserved_tasks, scheduled_tasks = [], [], []
    try:
        celery_app = Celery("yads_inspector", broker=settings.BROKER_URL, backend=settings.REDIS_URL)
        i = celery_app.control.inspect(timeout=5.0)
        if i:
            active_raw    = i.active()    or {}
            reserved_raw  = i.reserved()  or {}
            scheduled_raw = i.scheduled() or {}
            for worker, tasks in active_raw.items():
                for t in tasks:
                    t['hostname'] = worker.split("@", 1)[-1] if "@" in worker else worker
                    t['name'] = prettify_task_name(t.get('name', ''))
                    active_tasks.append(t)
            for tasks in reserved_raw.values():
                for t in tasks:
                    t['name'] = prettify_task_name(t.get('name', ''))
                reserved_tasks.extend(tasks)
            for tasks in scheduled_raw.values():
                for t in tasks:
                    t['name'] = prettify_task_name(t.get('name', ''))
                scheduled_tasks.extend(tasks)
        active_tasks    = filter_tasks_by_tenant(active_tasks,    user.tenant_id)
        reserved_tasks  = filter_tasks_by_tenant(reserved_tasks,  user.tenant_id)
        scheduled_tasks = filter_tasks_by_tenant(scheduled_tasks, user.tenant_id)
    except Exception as e:
        scan_logger.debug(f"Celery inspect failed: {e}")

    return templates.TemplateResponse("_queue_celery_live.html", {
        "request": request,
        "worker_nodes":     worker_nodes,
        "active_tasks":     active_tasks,
        "reserved_tasks":   reserved_tasks,
        "scheduled_tasks":  scheduled_tasks,
    })


# Admin/Scanner Only for Controls
scanner_only = RoleChecker(["admin", "tenant_admin", "scanner"])



def _widget_context(request, session, user, queue_active: bool) -> dict:
    """Build context dict for queue_widget.html including live counts.

    Uses DB as source of truth so the count is:
    - tenant-scoped
    - correct even when the queue is paused (tasks stuck as 'queued' in DB, not in Redis)
    - consistent with the dashboard counter
    """
    from yads.models import Target
    from sqlmodel import func
    queued_count = 0
    active_count = 0
    try:
        where_clause = [Target.scan_status.in_(["queued", "running"]), Target.is_archived == False]
        if user.tenant_id:
            where_clause.append(Target.tenant_id == user.tenant_id)
        stmt = select(func.count()).select_from(Target).where(*where_clause)
        total = session.exec(stmt).one()

        active_where = [Target.scan_status == "running", Target.is_archived == False]
        if user.tenant_id:
            active_where.append(Target.tenant_id == user.tenant_id)
        active_count = session.exec(
            select(func.count()).select_from(Target).where(*active_where)
        ).one()

        queued_count = total - active_count
    except Exception:
        pass

    rate_limited_count = get_rate_limited_module_count()

    return {
        "request": request,
        "queue_active": queue_active,
        "queue_length": queued_count,
        "active_count": active_count,
        "rate_limited_count": rate_limited_count,
    }


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

    return templates.TemplateResponse("components/queue_widget.html",
        _widget_context(request, session, user, queue_active)
    )

@router.post("/control", dependencies=[Depends(scanner_only)])
async def control_queue(
    request: Request,
    action: str = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    if not conf:
        conf = SystemConfig(key="QUEUE_ACTIVE", value="true")
        session.add(conf)

    # Connect to Celery for Control
    celery_app = Celery("yads_control", broker=settings.BROKER_URL, backend=settings.REDIS_URL)

    if action == "pause":
        conf.value = "false"
        session.add(conf)
        session.commit()

        # Stop workers from fetching new tasks from both queues
        celery_app.control.cancel_consumer('celery', reply=False)
        celery_app.control.cancel_consumer('discovery', reply=False)

        # Purge the ready backlog from the broker. Without this, pausing only
        # stopped consumption — the already-published messages stayed in
        # RabbitMQ and drained later (re-running modules never selected for the
        # newer targets), and every resume re-dispatched queued targets on top
        # of them. Resume rebuilds the working set from DB 'queued' status, so
        # discarding the broker backlog here is safe. (See broker-backlog
        # incident 2026-08-25.)
        from yads.core.broker_ops import purge_broker_queues
        purged = purge_broker_queues(settings.BROKER_URL)
        if purged:
            scan_logger.warning(f"[Pause] Purged {purged} pending broker messages.")

        # Revoke + terminate all prefetched (reserved) and actively running tasks
        import threading
        def _hard_stop():
            import logging
            import time
            log = logging.getLogger("yads.queue")
            try:
                i = celery_app.control.inspect(timeout=5.0)
                reserved = i.reserved() or {}
                active   = i.active()   or {}
                for tasks in list(reserved.values()) + list(active.values()):
                    for task in tasks:
                        # terminate=True sends SIGTERM to the worker subprocess
                        mark_task_cancelled(task["id"])
                        celery_app.control.revoke(task["id"], terminate=True, signal="SIGTERM")
            except Exception as exc:
                log.warning(f"[Stop] revoke broadcast failed: {exc}")
            # After workers stop, reset any 'running' targets → 'queued' so they
            # restart cleanly when the queue is resumed.
            time.sleep(3)
            try:
                from sqlalchemy import text as _sql
                from yads.database import engine as _engine
                from sqlmodel import Session as _Sess
                with _Sess(_engine) as s:
                    result = s.execute(_sql(
                        "UPDATE target SET scan_status='queued' WHERE scan_status='running'"
                    ))
                    s.commit()
                    if result.rowcount:
                        log.info(
                            f"[Stop] Reset {result.rowcount} running targets → queued"
                        )
            except Exception as exc:
                log.warning(f"[Stop] DB reset failed: {exc}")

        threading.Thread(target=_hard_stop, daemon=True).start()

    elif action == "resume":
        conf.value = "true"
        session.add(conf)
        session.commit()
        celery_app.control.add_consumer('celery', reply=False)
        celery_app.control.add_consumer('discovery', reply=False)

        # Re-dispatch targets that are marked 'queued' in DB but not in Redis.
        # These accumulate when the queue is paused (running → queued) or after
        # an API restart where Redis was flushed but DB retained status.
        try:
            queued_targets = session.exec(
                select(Target).where(Target.scan_status == "queued")
            ).all()
            redispatched = 0
            for t in queued_targets:
                celery_app.send_task(
                    "yads.worker.run_all_scans",
                    args=[t.id, t.domain, None, t.tenant_id],
                )
                redispatched += 1
            if redispatched:
                scan_logger.info(f"[Resume] Re-dispatched {redispatched} queued targets to Redis.")
        except Exception as exc:
            scan_logger.warning(f"[Resume] Re-dispatch failed: {exc}")
    else:
        session.add(conf)
        session.commit()

    # HTMX Support: Return updated widget if requested
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("components/queue_widget.html",
            _widget_context(request, session, user, action == "resume")
        )

    return RedirectResponse(url="/queue", status_code=303)



@router.post("/tasks/{task_id}/cancel", dependencies=[Depends(scanner_only)])
async def cancel_single_task(
    task_id: str,
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    """
    Cancel a single queued/active/reserved task.
    Verifies tenant ownership before cancellation.
    """
    import json
    import base64
    from yads.models import Target

    try:
        celery_app = Celery("yads_cancel", broker=settings.BROKER_URL, backend=settings.REDIS_URL)
        r = redis_client

        task_found = False
        task_tenant_id = None
        target_id = None
        task_state = None  # 'queued', 'reserved', 'active'

        # 1. Check if task is in Redis queue (queued but not picked up)
        queue_items = r.lrange("celery", 0, -1)
        item_to_remove = None

        for raw in queue_items:
            try:
                item_data = json.loads(raw)
                item_task_id = item_data.get('headers', {}).get('id')

                if item_task_id == task_id:
                    task_found = True
                    task_state = 'queued'
                    item_to_remove = raw

                    # Extract tenant_id and target_id for verification
                    body_b64 = item_data.get('body')
                    if body_b64:
                        try:
                            body_str = base64.b64decode(body_b64).decode('utf-8')
                            body_json = json.loads(body_str)
                            if isinstance(body_json, list) and len(body_json) > 0:
                                args = body_json[0]
                                if len(args) > 0: target_id = args[0]
                                if len(args) > 3: task_tenant_id = args[3]
                        except Exception as e:
                            scan_logger.debug(f"Failed to decode task body: {e}")
                    break
            except Exception as e:
                scan_logger.debug(f"Error parsing queue item: {e}")
                continue

        # 2. Check if task is reserved or active (via Celery inspect)
        if not task_found:
            i = celery_app.control.inspect(timeout=5.0)
            if i:
                # Check reserved tasks
                reserved = i.reserved() or {}
                for worker, tasks in reserved.items():
                    for task in tasks:
                        if task.get('id') == task_id:
                            task_found = True
                            task_state = 'reserved'
                            task_tenant_id = extract_tenant_from_task(task)
                            args = task.get('args', [])
                            if len(args) > 0: target_id = args[0]
                            break
                    if task_found: break

                # Check active tasks
                if not task_found:
                    active = i.active() or {}
                    for worker, tasks in active.items():
                        for task in tasks:
                            if task.get('id') == task_id:
                                task_found = True
                                task_state = 'active'
                                task_tenant_id = extract_tenant_from_task(task)
                                args = task.get('args', [])
                                if len(args) > 0: target_id = args[0]
                                break
                        if task_found: break

        if not task_found:
            scan_logger.warning(f"Task {task_id} not found in queue")
            if request.headers.get("HX-Request"):
                return HTMLResponse(
                    '<span class="text-yellow-400 text-xs">Not found</span>',
                    status_code=200
                )
            return {"status": "not_found", "message": "Task not found in queue"}

        # 3. Verify tenant ownership (unless platform admin)
        if user.role != "admin" and task_tenant_id != user.tenant_id:
            scan_logger.warning(f"User {user.id} attempted to cancel task {task_id} from tenant {task_tenant_id}")
            if request.headers.get("HX-Request"):
                return HTMLResponse(
                    '<span class="text-red-400 text-xs">Access denied</span>',
                    status_code=200
                )
            return {"status": "forbidden", "message": "Not authorized to cancel this task"}

        # 4. Perform cancellation based on state
        if task_state == 'queued' and item_to_remove:
            # Remove from Redis queue
            r.lrem("celery", 1, item_to_remove)
            scan_logger.info(f"Removed task {task_id} from Redis queue")

        # Always send revoke signal (works for reserved/active, harmless for already-removed)
        mark_task_cancelled(task_id)
        celery_app.control.revoke(task_id, terminate=True)
        scan_logger.info(f"Revoked task {task_id} (state: {task_state})")

        # 5. Reset target status if we have target_id
        if target_id:
            try:
                target = session.get(Target, target_id)
                if target and target.scan_status in ("queued", "running"):
                    target.scan_status = "idle"
                    target.scan_progress = "Cancelled by user"
                    session.add(target)
                    session.commit()
                    scan_logger.info(f"Reset target {target_id} status to idle")
            except Exception as e:
                scan_logger.error(f"Failed to reset target status: {e}")

        # 6. Return response
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                '<span class="text-emerald-400 text-xs">Cancelled</span>',
                status_code=200
            )

        return {
            "status": "cancelled",
            "task_id": task_id,
            "task_state": task_state,
            "target_id": target_id
        }

    except Exception as e:
        scan_logger.error(f"Failed to cancel task {task_id}: {e}")
        if request.headers.get("HX-Request"):
            return HTMLResponse(
                f'<span class="text-red-400 text-xs">Error</span>',
                status_code=200
            )
        return {"status": "error", "message": str(e)}


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
        celery_app = Celery("yads_purge", broker=settings.BROKER_URL, backend=settings.REDIS_URL)
        r = redis_client
        
        # 1. Selectively remove this tenant's pending tasks from the broker.
        # This used to manipulate a Redis list named "celery", which is a no-op
        # against the RabbitMQ broker actually in use — so "Clear Queue" never
        # cleared anything. Purge the real broker queue instead (drain ready
        # messages, drop this tenant's, requeue the rest). undo_tasks mirrors
        # the dropped tasks' args for the 60s undo window (#79).
        from yads.core.broker_ops import purge_broker_queue_for_tenant
        purged_count, undo_tasks = purge_broker_queue_for_tenant(
            settings.BROKER_URL, user.tenant_id
        )

        # 2. REVOKE Active & Reserved Tasks (Tenant-Filtered)
        scan_logger.warning(f"Revoking active and reserved tasks for tenant {user.tenant_id}...")
        i = celery_app.control.inspect(timeout=5.0)
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
                            mark_task_cancelled(t_id)
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
                            mark_task_cancelled(t_id)
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

        # Cache purged (queued-but-not-started) tasks for the undo window.
        undo_batch_id = None
        if undo_tasks:
            import uuid as _uuid
            undo_batch_id = _uuid.uuid4().hex[:12]
            try:
                r.setex(f"yads:undo_purge:{undo_batch_id}", 60, json.dumps(undo_tasks))
            except Exception as e:
                scan_logger.warning(f"Failed to cache purge-undo snapshot: {e}")
                undo_batch_id = None

    except Exception as e:
        scan_logger.error(f"Failed to purge queue: {e}")
        if request.headers.get("HX-Request"):
            conf = session.get(SystemConfig, "QUEUE_ACTIVE")
            queue_active = not (conf and conf.value.lower() == "false")
            return templates.TemplateResponse("components/queue_widget.html",
                _widget_context(request, session, user, queue_active)
            )
        return RedirectResponse(url=f"/queue?error=Purge+Failed:+{e}", status_code=303)

    # HTMX Support: Return updated widget
    if request.headers.get("HX-Request"):
        conf = session.get(SystemConfig, "QUEUE_ACTIVE")
        queue_active = not (conf and conf.value.lower() == "false")
        return templates.TemplateResponse("components/queue_widget.html",
            _widget_context(request, session, user, queue_active)
        )

    redirect_url = "/queue?msg=Queue+Cleared"
    if undo_batch_id:
        redirect_url += f"&undo_batch={undo_batch_id}"
    return RedirectResponse(url=redirect_url, status_code=303)


@router.post("/undo-purge")
async def undo_purge_queue(
    user: User = Depends(get_current_user_html),
    undo_batch: str = Form(...),
):
    """Re-dispatches the queued-but-not-yet-started tasks captured by the
    last purge, within the 60s undo window (#79). Tasks that were already
    ACTIVE when purged (mid-scan) are not restorable — only the ones that
    hadn't started yet."""
    import json
    key = f"yads:undo_purge:{undo_batch}"
    raw = redis_client.get(key)
    if not raw:
        return RedirectResponse(url="/queue?error=Undo+window+expired", status_code=303)

    tasks = json.loads(raw)
    requeued = 0
    celery_app = Celery("yads_undo_purge", broker=settings.BROKER_URL, backend=settings.REDIS_URL)
    for t in tasks:
        if t.get("tenant_id") != user.tenant_id:
            continue
        celery_app.send_task(
            "yads.worker.run_all_scans",
            args=[t["target_id"], t["domain"], t["scan_types"], t["tenant_id"]],
        )
        requeued += 1
    redis_client.delete(key)

    return RedirectResponse(url=f"/queue?msg=Re-queued+{requeued}+task(s)", status_code=303)

