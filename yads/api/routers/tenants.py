
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import selectinload
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

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

@router.get("/", response_class=HTMLResponse, dependencies=[Depends(RoleChecker(["admin"]))])
async def list_tenants(request: Request, session: Session = Depends(get_db_session), user: User = Depends(get_current_user_html)):
    tenants = session.exec(
        select(Tenant)
        .options(selectinload(Tenant.users), selectinload(Tenant.targets), selectinload(Tenant.allowed_users))
        .order_by(Tenant.id)
    ).all()
    
    all_users = session.exec(select(User).order_by(User.username)).all()
    
    return templates.TemplateResponse("tenants.html", {
        "request": request, 
        "tenants": tenants, 
        "user": user,
        "all_users": all_users
    })

@router.post("/add", dependencies=[Depends(RoleChecker(["admin"]))])
async def add_tenant(request: Request, name: str = Form(...), session: Session = Depends(get_db_session)):
    try:
        tenant = Tenant(name=name)
        session.add(tenant)
        session.commit()
        return RedirectResponse(url="/tenants?msg=Tenant created", status_code=303)
    except Exception as e:
        session.rollback()
        return RedirectResponse(url=f"/tenants?error={str(e)}", status_code=303)

@router.post("/update", dependencies=[Depends(RoleChecker(["admin"]))])
async def update_tenant(tenant_id: int = Form(...), name: str = Form(...), session: Session = Depends(get_db_session)):
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        return RedirectResponse(url="/tenants/?error=Not+found", status_code=303)
    tenant.name = name
    session.add(tenant)
    session.commit()
    return RedirectResponse(url="/tenants/?msg=Tenant+renamed", status_code=303)

@router.post("/users/update", dependencies=[Depends(RoleChecker(["admin"]))])
async def update_tenant_users(
    tenant_id: int = Form(...),
    user_ids: List[int] = Form(default=[]),
    session: Session = Depends(get_db_session)
):
    tenant = session.get(Tenant, tenant_id)
    if not tenant:
        return RedirectResponse(url="/tenants/?error=Not+found", status_code=303)
    
    # Get users
    if user_ids:
        users = session.exec(select(User).where(User.id.in_(user_ids))).all()
    else:
        users = []
        
    tenant.allowed_users = users
    session.add(tenant)
    session.commit()
    
    return RedirectResponse(url=f"/tenants/?msg=Users+assigned+to+{tenant.name}", status_code=303)

@router.post("/delete", dependencies=[Depends(RoleChecker(["admin"]))])
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

