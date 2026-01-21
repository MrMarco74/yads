from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select
from datetime import datetime, timedelta

from yads.database import get_session
from yads.models import User, Target, ScanSchedule, Tenant
from yads.auth.deps import get_current_user_html, RoleChecker
from fastapi.templating import Jinja2Templates
from yads.utils.license_deps import require_feature

router = APIRouter(prefix="/schedules", tags=["schedules"], dependencies=[Depends(require_feature("scheduled_scans"))])
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals (Standard Pattern)
from yads.config import settings
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def get_all_tenants():
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()
templates.env.globals['get_available_tenants'] = get_all_tenants

# Permissions: Only Admin/Tenant Admin/Scanner can manage schedules
manager_only = RoleChecker(["admin", "tenant_admin", "scanner"])

@router.get("/", response_class=HTMLResponse)
async def list_schedules(
    request: Request, 
    session: Session = Depends(get_session), 
    user: User = Depends(get_current_user_html)
):
    # 1. Fetch Schedules
    # Filter by tenant if not admin
    query = select(ScanSchedule, Target).join(Target)
    
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
        
    results = session.exec(query).all()
    
    # 2. Format for Template
    # Template expects item.schedule and item.target
    schedules_data = []
    for schedule, target in results:
        schedules_data.append({
            "schedule": schedule,
            "target": target
        })
        
    # 3. Fetch Candidates for "Add Schedule" (Targets without active schedules?)
    # Or just all targets for the dropdown
    t_query = select(Target)
    if user.tenant_id:
        t_query = t_query.where(Target.tenant_id == user.tenant_id)
        
    candidates = session.exec(t_query).all()

    return templates.TemplateResponse("schedules.html", {
        "request": request,
        "user": user,
        "schedules": schedules_data,
        "targets": candidates
    })

@router.post("/add")
async def add_schedule(
    request: Request,
    target_id: int = Form(...),
    frequency: str = Form(...), # daily, weekly
    session: Session = Depends(get_session),
    user: User = Depends(manager_only) # Permission Check
):
    # Validate Target ownership
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    if user.tenant_id and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access Denied to this Target")
        
    # Create Schedule
    now = datetime.utcnow()
    next_run = now + timedelta(days=1)
    if frequency == "weekly":
         next_run = now + timedelta(weeks=1)
         
    schedule = ScanSchedule(
        target_id=target_id,
        frequency=frequency,
        next_run_at=next_run,
        is_active=True
    )
    session.add(schedule)
    session.commit()
    
    return RedirectResponse(url="/schedules", status_code=303)

@router.post("/delete/{id}")
async def delete_schedule(
    id: int,
    session: Session = Depends(get_session),
    user: User = Depends(manager_only)
):
    schedule = session.get(ScanSchedule, id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
        
    # Check ownership via target
    target = session.get(Target, schedule.target_id)
    if user.tenant_id and target.tenant_id != user.tenant_id:
         raise HTTPException(status_code=403, detail="Access Denied")
         
    session.delete(schedule)
    session.commit()
    
    return RedirectResponse(url="/schedules", status_code=303)

@router.post("/set")
async def set_schedule(
    request: Request,
    target_id: int = Form(...),
    frequency: str = Form(...),
    cron_expression: str = Form(None),
    session: Session = Depends(get_session),
    user: User = Depends(manager_only)
):
    # Tenant Scope Check
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    if user.tenant_id and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access Denied")
        
    # Check existing
    schedule = session.exec(select(ScanSchedule).where(ScanSchedule.target_id == target_id)).first()
    
    if frequency == "none":
        if schedule:
            session.delete(schedule)
            session.commit()
        # Return HTML for badge
        return HTMLResponse('<span class="text-slate-400">Not Scheduled</span>')
        
    # Calculate Next Run
    now = datetime.utcnow()
    next_run = now + timedelta(days=1)
    
    if frequency == "weekly":
        next_run = now + timedelta(weeks=1)
    elif frequency == "custom" and cron_expression:
        # For now, just set next run to tomorrow + store cron
        # Real cron parsing would happen in worker scheduler
        next_run = now + timedelta(days=1) 
    
    if schedule:
        schedule.frequency = frequency
        schedule.cron_expression = cron_expression
        schedule.next_run_at = next_run # Reset timer on update? Yes.
        schedule.is_active = True
        session.add(schedule)
    else:
        schedule = ScanSchedule(
            target_id=target_id,
            frequency=frequency,
            cron_expression=cron_expression,
            next_run_at=next_run,
            is_active=True
        )
        session.add(schedule)
        
    session.commit()
    session.refresh(schedule)
    
    # Return Badge HTML
    icon = "📅"
    if frequency == "daily": icon = "🌞 Daily"
    elif frequency == "weekly": icon = "📆 Weekly"
    else: icon = f"📅 {frequency.title()}"
    
    html = f'''
    <span class="text-emerald-400 font-medium" title="Next: {next_run.strftime('%Y-%m-%d')}">
        {icon}
    </span>
    '''
    return HTMLResponse(html)
