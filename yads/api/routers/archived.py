"""
Router for Archived Targets report and management.
"""

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select, func
from yads.database import get_session
from yads.models import Target, User
from yads.auth.deps import get_current_user_html
from yads.api.main import templates
import logging

router = APIRouter(prefix="/reports/archived", tags=["Reports"])
logger = logging.getLogger(__name__)

@router.get("/", response_class=HTMLResponse)
async def view_archived_targets(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """View all archived targets for the current tenant"""
    targets = session.exec(
        select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.is_archived == True
        ).order_by(Target.archived_at.desc())
    ).all()
    
    dns_dead_count = sum(1 for t in targets if t.archived_reason == "dns_dead")
    manual_count = sum(1 for t in targets if t.archived_reason == "manual")
    
    return templates.TemplateResponse("archived_targets.html", {
        "request": request,
        "targets": targets,
        "dns_dead_count": dns_dead_count,
        "manual_count": manual_count,
        "user": user
    })

@router.post("/{target_id}/restore", response_class=HTMLResponse)
async def restore_target(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """Restore an archived target"""
    target = session.get(Target, target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Target not found")
        
    target.is_archived = False
    target.archived_at = None
    target.archived_reason = None
    session.add(target)
    session.commit()
    
    logger.info(f"Target {target.domain} restored by user {user.username}")
    
    # Return empty string or something that HTMX can use to remove the row
    return ""

@router.post("/cleanup-scan")
async def trigger_cleanup_scan(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """Trigger a cleanup scan for all targets in the tenant"""
    from yads.worker import celery_app
    
    # Fetch all non-archived targets for the tenant
    targets = session.exec(
        select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.is_archived == False
        )
    ).all()
    
    for t in targets:
        celery_app.send_task("yads.worker.run_all_scans", args=[t.id, t.domain, ["dns_cleanup"], user.tenant_id])
        
    return {"status": "success", "message": f"Queued cleanup scan for {len(targets)} targets."}
