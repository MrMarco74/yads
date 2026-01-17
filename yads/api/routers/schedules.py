from fastapi import APIRouter, Depends, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from datetime import datetime, timedelta
from typing import Optional
import logging

from yads.database import get_session
from yads.models import User, Target, ScanSchedule
from yads.auth.deps import RoleChecker
from yads.core.tenant_logger import TenantLogger

router = APIRouter(prefix="/schedule", tags=["schedule"])
base_logger = logging.getLogger("yads.api.schedules")
templates = Jinja2Templates(directory="yads/api/templates")
# Inject Globals
from yads.config import settings
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

@router.get("/", response_class=HTMLResponse)
async def list_schedules(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    query = select(ScanSchedule, Target).join(Target)
    
    if user.role != "admin":
        query = query.where(Target.tenant_id == user.tenant_id)
        
    results = session.exec(query).all()
    
    # Format for template: list of dicts or objects with .schedule and .target
    schedules_list = [{"schedule": s, "target": t} for s, t in results]
    
    return templates.TemplateResponse("schedules.html", {
        "request": request,
        "user": user,
        "schedules": schedules_list
    })

@router.post("/set", response_class=HTMLResponse)
async def set_schedule(
    request: Request,
    target_id: int = Form(...),
    frequency: str = Form(...), # "daily", "weekly", "custom", "none"
    cron_expression: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"]))
):
    # Verify Access
    target = session.exec(select(Target).where(Target.id == target_id)).first()
    if not target:
        return "<div class='text-red-500'>Target not found</div>"
        
    if user.role != "admin" and target.tenant_id != user.tenant_id:
        return "<div class='text-red-500'>Unauthorized</div>"

    logger = TenantLogger(base_logger, user.tenant_id)

    # Check Existing
    schedule = session.exec(select(ScanSchedule).where(ScanSchedule.target_id == target_id)).first()
    
    if frequency == "none":
        if schedule:
            session.delete(schedule)
            session.commit()
            logger.info(f"Schedule removed for target {target_id} by {user.username}")
        return "<span class='text-slate-400'>Not Scheduled</span>"

    now = datetime.utcnow()
    next_run = now + timedelta(days=1) # Default fallback
    
    if frequency == "weekly":
        next_run = now + timedelta(weeks=1)
    elif frequency == "custom":
        if not cron_expression:
            return "<div class='text-red-500'>Missing Cron Expression</div>"
        try:
            from croniter import croniter
            iter = croniter(cron_expression, now)
            next_run = iter.get_next(datetime)
        except Exception as e:
            return f"<div class='text-red-500'>Invalid Cron: {str(e)}</div>"

    if not schedule:
        schedule = ScanSchedule(
            target_id=target_id,
            frequency=frequency,
            cron_expression=cron_expression if frequency == "custom" else None,
            next_run_at=next_run,
            is_active=True
        )
        session.add(schedule)
        logger.info(f"New schedule created for target {target_id} ({frequency}) by {user.username}")
    else:
        schedule.frequency = frequency
        schedule.cron_expression = cron_expression if frequency == "custom" else None
        schedule.is_active = True
        schedule.next_run_at = next_run
        session.add(schedule)
        logger.info(f"Schedule updated for target {target_id} ({frequency}) by {user.username}")
        
    session.commit()
    
    icon = "📅"
    if frequency == "daily": icon = "🌞"
    elif frequency == "weekly": icon = "📆"
    elif frequency == "custom": icon = "⚙️"
    
    return f"<span class='text-emerald-400 font-medium' title='Next: {next_run.strftime('%Y-%m-%d %H:%M UTC')}'>{icon} {frequency.title()}</span>"
