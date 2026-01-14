from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from typing import Optional

from yads.database import get_session
from yads.models import User, Tenant
from yads.auth.deps import RoleChecker, get_current_user
from yads.config import settings

router = APIRouter(prefix="/tenant-settings", tags=["tenant-settings"])
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals (similar to other routers)
from datetime import datetime
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def get_all_tenants(): # Helper for context switching if needed
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()
templates.env.globals['get_available_tenants'] = get_all_tenants


@router.get("/", response_class=HTMLResponse)
async def tenant_settings_page(
    request: Request,
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    # Ensure user has a tenant
    if not user.tenant_id:
         # If admin, maybe redirect or show error? 
         # Platform admins might not have a tenant context selected.
         # For now, require tenant context.
         if user.role == 'admin':
             # Check if they have switched context?
             # If tenant_id is None, show warning "Select a tenant first"
             return templates.TemplateResponse("tenant_settings.html", {
                 "request": request,
                 "error": "Please select a Tenant context from the sidebar/topbar to manage its settings.",
                 "no_context": True
             })
         else:
             # Should practically never happen for tenant_admin with required tenant
             return RedirectResponse("/", status_code=303)

    # Reload tenant from DB to confirm fresh data
    tenant = session.get(Tenant, user.tenant_id)
    
    return templates.TemplateResponse("tenant_settings.html", {
        "request": request,
        "tenant": tenant,
        "user": user
    })


@router.post("/", response_class=HTMLResponse)
async def update_tenant_settings(
    request: Request,
    google_api_key: Optional[str] = Form(None),
    google_cse_cx: Optional[str] = Form(None),
    user: User = Depends(RoleChecker(["tenant_admin", "admin"])),
    session: Session = Depends(get_session)
):
    if not user.tenant_id:
        return RedirectResponse("/tenant-settings", status_code=303)
        
    tenant = session.get(Tenant, user.tenant_id)
    if not tenant:
        return RedirectResponse("/", status_code=303)
        
    # Update fields
    tenant.google_api_key = google_api_key if google_api_key and google_api_key.strip() else None
    tenant.google_cse_cx = google_cse_cx if google_cse_cx and google_cse_cx.strip() else None
    
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    
    return templates.TemplateResponse("tenant_settings.html", {
        "request": request,
        "tenant": tenant,
        "user": user,
        "success": "Settings updated successfully."
    })
