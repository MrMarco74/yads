"""
Router for Archived Targets report and management.
"""

from fastapi import APIRouter, Depends, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, func
from typing import Optional
from yads.database import get_session
from yads.models import Target, User
from yads.auth.deps import get_current_user_html
from yads.api.main import templates
from yads.api.utils.date_filter import parse_date_range, get_date_range_display
import logging

router = APIRouter(prefix="/reports/archived", tags=["Reports"])
logger = logging.getLogger(__name__)

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def view_archived_targets(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    """View all archived targets for the current tenant"""
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    query = select(Target).where(
        Target.tenant_id == user.tenant_id,
        Target.is_archived == True
    )

    # Apply date filtering on archived_at field
    if from_dt:
        query = query.where(Target.archived_at >= from_dt)
    if to_dt:
        query = query.where(Target.archived_at <= to_dt)

    targets = session.exec(query.order_by(Target.archived_at.desc())).all()

    dns_dead_count = sum(1 for t in targets if t.archived_reason == "dns_dead")
    manual_count = sum(1 for t in targets if t.archived_reason == "manual")

    return templates.TemplateResponse("archived_targets.html", {
        "request": request,
        "targets": targets,
        "dns_dead_count": dns_dead_count,
        "manual_count": manual_count,
        "user": user,
        "date_range_display": date_range_display
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
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    next: str = "/reports/archived"
):
    """Trigger a quick web probe for all non-archived targets in the tenant"""
    from yads.worker import celery_app
    from urllib.parse import quote

    targets = session.exec(
        select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.is_archived == False
        )
    ).all()

    for t in targets:
        t.scan_status = "queued"
        session.add(t)
        celery_app.send_task("yads.worker.run_all_scans", args=[t.id, t.domain, ["quick_web_probe"], user.tenant_id])

    session.commit()

    msg = quote(f"Quick Web Probe queued for {len(targets)} targets")
    return RedirectResponse(url=f"{next}?msg={msg}", status_code=303)

@router.post("/bulk-delete-dead")
async def bulk_delete_dead(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """Permanently delete all targets archived due to dead DNS"""
    dead_targets = session.exec(
        select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.is_archived == True,
            Target.archived_reason == "dns_dead"
        )
    ).all()
    
    count = 0
    for t in dead_targets:
        session.delete(t)
        count += 1
        
    session.commit()
    
    # Redirect back to archived list so HTMX refreshes the page
    return RedirectResponse(url=f"/reports/archived?msg=Deleted {count} dead DNS targets", status_code=303)
