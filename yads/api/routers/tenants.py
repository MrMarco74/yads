
from fastapi import APIRouter, Depends, Query, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, func, text

from yads.database import get_session as get_db_session
from yads.models import Tenant, User, Target
from yads.auth.deps import PlatformAdminChecker, get_current_user_html, RoleChecker

router = APIRouter(prefix="/tenants", tags=["tenants"])
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals from main setup usually, but we need settings
from yads.config import settings
from datetime import datetime
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

@router.get("/", response_class=HTMLResponse, dependencies=[Depends(PlatformAdminChecker())])
async def list_tenants(request: Request, session: Session = Depends(get_db_session), user: User = Depends(get_current_user_html)):
    tenants = session.exec(select(Tenant).order_by(Tenant.id)).all()
    
    # Enrich with counts (optional, but good for admin)
    # This might be N+1 if not careful, but for tenants list (usually small) it's okay.
    # Better: Join to get counts.
    # For MVP, eager loading or simple iteration is fine if < 100 tenants.
    
    return templates.TemplateResponse("tenants.html", {
        "request": request,
        "tenants": tenants,
        "user": user
    })

@router.post("/add", dependencies=[Depends(PlatformAdminChecker())])
async def add_tenant(request: Request, name: str = Form(...), session: Session = Depends(get_db_session)):
    name = name.strip()
    if not name:
        return RedirectResponse(url="/tenants/?error=Name+required", status_code=303)
        
    existing = session.exec(select(Tenant).where(Tenant.name == name)).first()
    if existing:
        return RedirectResponse(url="/tenants/?error=Tenant+exists", status_code=303)
        
    tenant = Tenant(name=name)
    session.add(tenant)
    session.commit()
    return RedirectResponse(url="/tenants/?msg=Tenant+created", status_code=303)

@router.post("/delete", dependencies=[Depends(PlatformAdminChecker())])
async def delete_tenant(tenant_id: int = Form(...), session: Session = Depends(get_db_session)):
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        return RedirectResponse(url="/tenants/?error=Not+found", status_code=303)
        
    # Cascade Delete?
    # Delete users, targets, results linked to tenant.
    # WARN: Destructive.
    
    # 1. Delete Results & States & Targets
    session.exec(text(f"DELETE FROM scanresult WHERE target_id IN (SELECT id FROM target WHERE tenant_id = {tenant_id})"))
    session.exec(text(f"DELETE FROM modulestate WHERE target_id IN (SELECT id FROM target WHERE tenant_id = {tenant_id})"))
    session.exec(text(f"DELETE FROM target WHERE tenant_id = {tenant_id}"))
    
    # 2. Delete Users
    session.exec(text(f"DELETE FROM \"user\" WHERE tenant_id = {tenant_id}"))
    
    # 3. Delete Tenant
    session.delete(tenant)
    session.commit()
    
    return RedirectResponse(url="/tenants/?msg=Tenant+deleted", status_code=303)

