"""API-key-authenticated queue control surface for yads-mcp and other
machine clients. Mirrors the tenant-scoped subset of the cookie-session
queue.py routes -- see docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md
section 5.1.
"""

import json
import uuid as _uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, and_, func as sqlfunc, or_, select

from yads.api.routers.queue import (
    extract_tenant_from_task,
    filter_tasks_by_tenant,
    mark_task_cancelled,
    prettify_task_name,
)
from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.config import settings
from yads.core.module_status import get_rate_limited_module_count
from yads.database import get_session, redis_client
from yads.models import APIKey, SystemConfig, Target
from yads.worker import celery_app

router = APIRouter(prefix="/api/v1", tags=["API v1 — Queue"])


@router.get("/queue/status", dependencies=[Depends(RequireScope("read"))])
async def queue_status(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    queue_active = not (conf and conf.value.lower() == "false")

    queued_count = session.exec(
        select(sqlfunc.count()).select_from(Target).where(
            Target.tenant_id == api_key.tenant_id,
            Target.scan_status == "queued",
            Target.is_archived == False,
        )
    ).one()
    running_count = session.exec(
        select(sqlfunc.count()).select_from(Target).where(
            Target.tenant_id == api_key.tenant_id,
            Target.scan_status == "running",
            Target.is_archived == False,
        )
    ).one()

    active_tasks = []
    reserved_tasks = []
    try:
        i = celery_app.control.inspect(timeout=5.0)
        for worker, tasks in (i.active() or {}).items():
            for task in filter_tasks_by_tenant(tasks, api_key.tenant_id):
                active_tasks.append({"id": task.get("id"), "name": prettify_task_name(task.get("name", "")), "args": task.get("args", [])})
        for worker, tasks in (i.reserved() or {}).items():
            for task in filter_tasks_by_tenant(tasks, api_key.tenant_id):
                reserved_tasks.append({"id": task.get("id"), "name": prettify_task_name(task.get("name", "")), "args": task.get("args", [])})
    except Exception:
        pass

    # The authoritative pending-scan count lives in the broker, not in the DB:
    # queued_count only sees targets this tenant marked 'queued', while the
    # messages actually waiting for a worker sit in RabbitMQ. Fleet-wide and
    # not tenant-scoped (a broker queue carries every tenant's messages), same
    # as the depth the cookie-session queue page shows.
    from yads.core.broker_ops import get_broker_queue_depth
    broker_depth = get_broker_queue_depth(settings.BROKER_URL)

    return {
        "queue_active": queue_active,
        "queued_count": queued_count,
        "running_count": running_count,
        "active_tasks": active_tasks,
        "reserved_tasks": reserved_tasks,
        "rate_limited_module_count": get_rate_limited_module_count(),
        "broker_depth": broker_depth,
        "broker_pending": sum(broker_depth.values()),
    }


class QueueControlRequest(BaseModel):
    action: str


@router.post("/queue/control", dependencies=[Depends(RequireScope("write"))])
async def queue_control(
    payload: QueueControlRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if payload.action not in ("pause", "resume"):
        raise HTTPException(status_code=400, detail="action must be 'pause' or 'resume'")

    conf = session.get(SystemConfig, "QUEUE_ACTIVE")
    if not conf:
        conf = SystemConfig(key="QUEUE_ACTIVE", value="true")

    # Note: this action is fleet-wide, not tenant-scoped, matching the
    # existing cookie-session control_queue behavior exactly -- see
    # spec section 6, item 1. A key with only "write" (not "destructive")
    # can pause every tenant's scans; this is an inherited inconsistency,
    # not a new one introduced here.
    broker_purged = 0
    if payload.action == "pause":
        conf.value = "false"
        session.add(conf)
        session.commit()
        celery_app.control.cancel_consumer("celery", reply=False)
        celery_app.control.cancel_consumer("discovery", reply=False)

        # Cancelling the consumers only stops workers from fetching; the
        # already-published messages stay in RabbitMQ and drain on the next
        # resume, re-running modules never selected for the newer targets.
        # The cookie-session handler (queue.py) has purged them since the
        # 2026-08-25 broker-backlog incident -- this path never did, so an
        # API-driven pause left the backlog behind. Resume rebuilds the
        # working set from the DB 'queued' status, so discarding it is safe.
        from yads.core.broker_ops import purge_broker_queues
        broker_purged = purge_broker_queues(settings.BROKER_URL)
    else:
        conf.value = "true"
        session.add(conf)
        session.commit()
        celery_app.control.add_consumer("celery", reply=False)
        celery_app.control.add_consumer("discovery", reply=False)

    return {
        "queue_active": payload.action == "resume",
        "broker_purged_count": broker_purged,
    }


@router.post("/queue/tasks/{task_id}/cancel", dependencies=[Depends(RequireScope("write"))])
async def cancel_task(
    task_id: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    i = celery_app.control.inspect(timeout=5.0)
    task_tenant_id: Optional[int] = None
    target_id: Optional[int] = None
    task_state: Optional[str] = None

    if i:
        for state_name, getter in (("reserved", i.reserved), ("active", i.active)):
            for worker, tasks in (getter() or {}).items():
                for task in tasks:
                    if task.get("id") == task_id:
                        task_state = state_name
                        task_tenant_id = extract_tenant_from_task(task)
                        args = task.get("args", [])
                        target_id = args[0] if args else None
                        break
                if task_state:
                    break
            if task_state:
                break

    if task_state is None:
        raise HTTPException(status_code=404, detail="Task not found in queue")

    if task_tenant_id != api_key.tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized to cancel this task")

    mark_task_cancelled(task_id)
    celery_app.control.revoke(task_id, terminate=True)

    if target_id:
        target = session.get(Target, target_id)
        if target and target.scan_status in ("queued", "running"):
            target.scan_status = "idle"
            target.scan_progress = "Cancelled via API"
            session.add(target)
            session.commit()

    return {"status": "cancelled", "task_id": task_id, "task_state": task_state, "target_id": target_id}


class ConfirmRequest(BaseModel):
    confirm: bool


@router.post("/queue/purge", dependencies=[Depends(RequireScope("destructive"))])
async def purge_queue(
    payload: ConfirmRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to purge the queue")

    # Selectively remove this tenant's pending tasks from the real broker.
    # This used to walk a Redis list named "celery", which is a no-op against
    # the RabbitMQ broker actually in use -- so an API purge never cleared the
    # backlog and it drained on the next resume (the 2026-08-25 broker-backlog
    # incident, fixed in the cookie-session handler but not here).
    # purge_broker_queue_for_tenant drains the ready messages, drops this
    # tenant's and requeues the rest; undo_tasks mirrors the dropped tasks'
    # args for the 60s undo window.
    from yads.core.broker_ops import purge_broker_queue_for_tenant
    purged_count, undo_tasks = purge_broker_queue_for_tenant(
        settings.BROKER_URL, api_key.tenant_id
    )

    revoked_count = 0
    i = celery_app.control.inspect(timeout=5.0)
    if i:
        for tasks in list((i.reserved() or {}).values()) + list((i.active() or {}).values()):
            for task in tasks:
                if extract_tenant_from_task(task) == api_key.tenant_id:
                    mark_task_cancelled(task.get("id"))
                    celery_app.control.revoke(task.get("id"), terminate=True)
                    revoked_count += 1

    zombies = session.exec(
        select(Target).where(
            and_(
                Target.tenant_id == api_key.tenant_id,
                or_(Target.scan_status == "queued", Target.scan_status == "running"),
            )
        )
    ).all()
    for z in zombies:
        z.scan_status = "idle"
        z.scan_progress = "Stopped by API purge"
        session.add(z)
    session.commit()

    undo_batch_id = None
    if undo_tasks:
        undo_batch_id = _uuid.uuid4().hex[:12]
        redis_client.setex(f"yads:undo_purge:{undo_batch_id}", 60, json.dumps(undo_tasks))

    return {
        "purged_count": purged_count,
        "revoked_count": revoked_count,
        "reset_count": len(zombies),
        "undo_batch": undo_batch_id,
    }


class UndoPurgeRequest(BaseModel):
    undo_batch: str


@router.post("/queue/undo-purge", dependencies=[Depends(RequireScope("write"))])
async def undo_purge_queue(
    payload: UndoPurgeRequest,
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    key = f"yads:undo_purge:{payload.undo_batch}"
    raw = redis_client.get(key)
    if not raw:
        raise HTTPException(status_code=404, detail="Undo window expired or batch not found")

    tasks = json.loads(raw)
    requeued = 0
    for t in tasks:
        if t.get("tenant_id") != api_key.tenant_id:
            continue
        celery_app.send_task(
            "yads.worker.run_all_scans",
            args=[t["target_id"], t["domain"], t["scan_types"], t["tenant_id"]],
        )
        requeued += 1
    redis_client.delete(key)

    return {"requeued": requeued}
