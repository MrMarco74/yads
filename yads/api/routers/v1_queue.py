"""API-key-authenticated queue control surface for yads-mcp and other
machine clients. Mirrors the tenant-scoped subset of the cookie-session
queue.py routes -- see docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md
section 5.1.
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, func as sqlfunc, select

from yads.api.routers.queue import (
    extract_tenant_from_task,
    filter_tasks_by_tenant,
    mark_task_cancelled,
    prettify_task_name,
)
from yads.auth.deps import get_api_key
from yads.core.module_status import get_rate_limited_module_count
from yads.database import get_session
from yads.models import APIKey, SystemConfig, Target
from yads.worker import celery_app

router = APIRouter(prefix="/api/v1", tags=["API v1 — Queue"])


@router.get("/queue/status")
async def queue_status(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
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

    return {
        "queue_active": queue_active,
        "queued_count": queued_count,
        "running_count": running_count,
        "active_tasks": active_tasks,
        "reserved_tasks": reserved_tasks,
        "rate_limited_module_count": get_rate_limited_module_count(),
    }


class QueueControlRequest(BaseModel):
    action: str


@router.post("/queue/control")
async def queue_control(
    payload: QueueControlRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
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
    if payload.action == "pause":
        conf.value = "false"
        session.add(conf)
        session.commit()
        celery_app.control.cancel_consumer("celery", reply=False)
        celery_app.control.cancel_consumer("discovery", reply=False)
    else:
        conf.value = "true"
        session.add(conf)
        session.commit()
        celery_app.control.add_consumer("celery", reply=False)
        celery_app.control.add_consumer("discovery", reply=False)

    return {"queue_active": payload.action == "resume"}


@router.post("/queue/tasks/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
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
