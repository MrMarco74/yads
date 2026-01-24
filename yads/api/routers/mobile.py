"""
Mobile Dashboard Router

Lightweight mobile-friendly interface for monitoring and queue control.
Designed for quick status checks during long-running scans.
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.api.deps import get_session, get_current_user, RoleChecker
from yads.models import User, Target, SystemConfig, Notification
from yads.worker import celery_app
from yads.config import templates
import redis
import json
import os

router = APIRouter(prefix="/mobile", tags=["mobile"])


def get_redis_client():
    """Get Redis connection for queue inspection."""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return redis.from_url(redis_url, decode_responses=True)


def get_queue_stats(session: Session, tenant_id: Optional[int] = None) -> dict:
    """Get queue statistics for mobile dashboard."""
    stats = {
        "active": 0,
        "pending": 0,
        "reserved": 0,
        "is_paused": False,
        "active_tasks": [],
        "running_targets": []
    }

    # Check if queue is paused
    config = session.exec(
        select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")
    ).first()
    stats["is_paused"] = config is None or config.value != "true"

    # Get active tasks from Celery
    try:
        inspector = celery_app.control.inspect()
        active = inspector.active() or {}
        reserved = inspector.reserved() or {}

        for worker_name, tasks in active.items():
            for task in tasks:
                if task.get("name") == "yads.worker.run_all_scans":
                    args = task.get("args", [])
                    if len(args) >= 4:
                        task_tenant_id = args[3] if len(args) > 3 else None
                        # Filter by tenant if specified
                        if tenant_id is None or task_tenant_id == tenant_id:
                            stats["active"] += 1
                            stats["active_tasks"].append({
                                "target_id": args[0],
                                "domain": args[1],
                                "scan_types": args[2] if len(args) > 2 else [],
                                "worker": worker_name.split("@")[-1] if "@" in worker_name else worker_name
                            })

        for worker_name, tasks in reserved.items():
            for task in tasks:
                if task.get("name") == "yads.worker.run_all_scans":
                    args = task.get("args", [])
                    if len(args) >= 4:
                        task_tenant_id = args[3] if len(args) > 3 else None
                        if tenant_id is None or task_tenant_id == tenant_id:
                            stats["reserved"] += 1

    except Exception:
        pass  # Celery might not be available

    # Get pending tasks from Redis backlog
    try:
        r = get_redis_client()
        backlog = r.lrange("celery", 0, -1)
        for item in backlog:
            try:
                task_data = json.loads(item)
                body = task_data.get("body")
                if body:
                    import base64
                    decoded = json.loads(base64.b64decode(body))
                    args = decoded[0] if decoded else []
                    if len(args) >= 4:
                        task_tenant_id = args[3] if len(args) > 3 else None
                        if tenant_id is None or task_tenant_id == tenant_id:
                            stats["pending"] += 1
            except Exception:
                stats["pending"] += 1  # Count it anyway
    except Exception:
        pass

    # Get currently running targets
    running = session.exec(
        select(Target).where(Target.scan_status == "running")
    ).all()
    for target in running:
        if tenant_id is None or target.tenant_id == tenant_id:
            stats["running_targets"].append({
                "id": target.id,
                "domain": target.domain,
                "progress": target.scan_progress or 0
            })

    return stats


def get_recent_alerts(session: Session, limit: int = 5) -> list:
    """Get recent notifications/alerts."""
    notifications = session.exec(
        select(Notification)
        .order_by(Notification.created_at.desc())
        .limit(limit)
    ).all()

    return [
        {
            "id": n.id,
            "title": n.title,
            "text": n.text,
            "type": n.type,
            "color": n.color,
            "created_at": n.created_at.strftime("%H:%M") if n.created_at else ""
        }
        for n in notifications
    ]


@router.get("/", response_class=HTMLResponse)
async def mobile_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """Main mobile dashboard view."""
    tenant_id = user.tenant_id if user.tenant_id else None

    stats = get_queue_stats(session, tenant_id)
    alerts = get_recent_alerts(session)

    return templates.TemplateResponse("mobile/dashboard.html", {
        "request": request,
        "user": user,
        "stats": stats,
        "alerts": alerts,
        "now": datetime.now().strftime("%H:%M:%S")
    })


@router.get("/stats", response_class=HTMLResponse)
async def mobile_stats_fragment(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """HTMX fragment for live stats update."""
    tenant_id = user.tenant_id if user.tenant_id else None
    stats = get_queue_stats(session, tenant_id)
    alerts = get_recent_alerts(session)

    return templates.TemplateResponse("mobile/stats_fragment.html", {
        "request": request,
        "stats": stats,
        "alerts": alerts,
        "now": datetime.now().strftime("%H:%M:%S")
    })


@router.post("/queue/pause", response_class=HTMLResponse)
async def mobile_pause_queue(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """Pause the queue."""
    config = session.exec(
        select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")
    ).first()

    if config:
        config.value = "false"
    else:
        config = SystemConfig(key="QUEUE_ACTIVE", value="false")
        session.add(config)

    session.commit()

    # Cancel Celery consumer
    try:
        celery_app.control.cancel_consumer("celery")
    except Exception:
        pass

    return HTMLResponse(content="""
        <div class="control-feedback success">Queue paused</div>
    """)


@router.post("/queue/resume", response_class=HTMLResponse)
async def mobile_resume_queue(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """Resume the queue."""
    config = session.exec(
        select(SystemConfig).where(SystemConfig.key == "QUEUE_ACTIVE")
    ).first()

    if config:
        config.value = "true"
    else:
        config = SystemConfig(key="QUEUE_ACTIVE", value="true")
        session.add(config)

    session.commit()

    # Re-add Celery consumer
    try:
        celery_app.control.add_consumer("celery")
    except Exception:
        pass

    return HTMLResponse(content="""
        <div class="control-feedback success">Queue resumed</div>
    """)


@router.post("/queue/clear", response_class=HTMLResponse)
async def mobile_clear_queue(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    """Clear pending queue items for current tenant."""
    tenant_id = user.tenant_id
    cleared = 0

    try:
        r = get_redis_client()
        backlog = r.lrange("celery", 0, -1)

        for item in backlog:
            try:
                task_data = json.loads(item)
                body = task_data.get("body")
                if body:
                    import base64
                    decoded = json.loads(base64.b64decode(body))
                    args = decoded[0] if decoded else []
                    if len(args) >= 4:
                        task_tenant_id = args[3] if len(args) > 3 else None
                        # Only remove tasks for this tenant (or all if platform admin)
                        if tenant_id is None or task_tenant_id == tenant_id:
                            r.lrem("celery", 1, item)
                            cleared += 1
            except Exception:
                pass

        # Reset queued targets to idle
        queued_targets = session.exec(
            select(Target).where(Target.scan_status == "queued")
        ).all()

        for target in queued_targets:
            if tenant_id is None or target.tenant_id == tenant_id:
                target.scan_status = "idle"

        session.commit()

    except Exception as e:
        return HTMLResponse(content=f"""
            <div class="control-feedback error">Error: {str(e)}</div>
        """)

    return HTMLResponse(content=f"""
        <div class="control-feedback success">Cleared {cleared} tasks</div>
    """)


@router.get("/api/stats")
async def mobile_api_stats(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user)
):
    """JSON API endpoint for stats (for potential native app integration)."""
    tenant_id = user.tenant_id if user.tenant_id else None
    stats = get_queue_stats(session, tenant_id)
    alerts = get_recent_alerts(session)

    return {
        "queue": {
            "active": stats["active"],
            "pending": stats["pending"],
            "reserved": stats["reserved"],
            "is_paused": stats["is_paused"],
            "total": stats["active"] + stats["pending"] + stats["reserved"]
        },
        "running": stats["running_targets"],
        "alerts": alerts,
        "timestamp": datetime.now().isoformat()
    }
