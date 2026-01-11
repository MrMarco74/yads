from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from typing import Optional, List

from yads.auth.security import get_password_hash
from yads.models import User, SystemConfig, Tenant, UserTenantLink
from yads.auth.deps import get_db_session, get_current_user, RoleChecker
from yads.config import settings

router = APIRouter(prefix="/users")
templates = Jinja2Templates(directory="yads/api/templates")
# Inject Globals
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

# Only Admins can access these routes
admin_only = RoleChecker(["admin"])

@router.get("/", response_class=HTMLResponse, dependencies=[Depends(admin_only)])
async def list_users(request: Request, session: Session = Depends(get_db_session), current_user: User = Depends(get_current_user)):
    # Tenant Scope: List only users in same tenant
    # IF Platform Admin (tenant_id is None): List ALL users?
    if current_user.tenant_id is None:
        users = session.exec(select(User)).all()
        # We might want to eager load tenants
        # users = session.exec(select(User).options(joinedload(User.tenant))).all() # SQLModel support?
    else:
        users = session.exec(select(User).where(User.tenant_id == current_user.tenant_id)).all()
    
    # Get Session Timeout
    timeout_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    timeout_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
    if timeout_conf:
        try:
            timeout_minutes = int(timeout_conf.value)
        except:
            pass
            
    # Also fetch tenants list for the dropdown if Platform Admin
    tenants = []
    if current_user.tenant_id is None:
        tenants = session.exec(select(Tenant)).all()

    return templates.TemplateResponse("users.html", {
        "request": request, 
        "users": users, 
        "user": current_user, 
        "tenants": tenants,
        "session_minutes": timeout_minutes
    })

@router.post("/set_session", dependencies=[Depends(admin_only)])
async def set_session_timeout(
    duration: int = Form(...),
    unit: str = Form(...),
    session: Session = Depends(get_db_session)
):
    # Convert to minutes
    minutes = duration
    if unit == "hours":
        minutes = duration * 60
    elif unit == "days":
        minutes = duration * 60 * 24
        
    conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
    if not conf:
        conf = SystemConfig(key="ACCESS_TOKEN_EXPIRE_MINUTES", value=str(minutes))
        session.add(conf)
    else:
        conf.value = str(minutes)
        session.add(conf)
        
    session.commit()
    return RedirectResponse(url="/users/?msg=Session+timeout+updated", status_code=303)

@router.post("/create", dependencies=[Depends(admin_only)])
async def create_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
    target_tenant_id: Optional[int] = Form(None), # From Dropdown
    force_change: bool = Form(False),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    # Determine correct tenant_id (Active Context)
    final_tenant_id = current_user.tenant_id
    if current_user.tenant_id is None:
        # Platform Admin can assign anyone
        # If target_tenant_id is provided (int), use it.
        # If None, it creates a new Platform Admin! (Be careful)
        final_tenant_id = target_tenant_id
    else:
        # Regular Tenant Admin MUST NOT be able to change tenant
        pass
        
    # Check duplicate (Global? Or Tenant? Unique constraint is global on username)
    existing = session.exec(select(User).where(User.username == username)).first()
    if existing:
        return RedirectResponse(url="/users/?error=Username+exists", status_code=303)
        
    hash_pw = get_password_hash(password)
    new_user = User(
        username=username, 
        password_hash=hash_pw, 
        role=role,
        force_password_change=force_change,
        tenant_id=final_tenant_id
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    
    # Multi-Tenant Logic:
    # If a tenant is assigned as Active, also ensure it's in the allowed list
    if final_tenant_id:
        link = UserTenantLink(user_id=new_user.id, tenant_id=final_tenant_id)
        session.add(link)
        session.commit()
    
    return RedirectResponse(url="/users/?msg=User+created", status_code=303)

@router.post("/delete", dependencies=[Depends(admin_only)])
async def delete_user(user_id: int = Form(...), session: Session = Depends(get_db_session), current_user: User = Depends(get_current_user)):
    # Ensure target user belongs to admin's tenant
    user = session.exec(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)).first()
    if user:
        if user.username == "admin": 
             return RedirectResponse(url="/users/?error=Cannot+delete+admin", status_code=303)
        session.delete(user)
        session.commit()
    return RedirectResponse(url="/users/?msg=User+deleted", status_code=303)

@router.post("/reset_password", dependencies=[Depends(admin_only)])
async def reset_password(
    user_id: int = Form(...), 
    new_password: str = Form(...),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    user = session.exec(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)).first()
    if user:
        user.password_hash = get_password_hash(new_password)
        session.add(user)
        session.commit()
    return RedirectResponse(url="/users/?msg=Password+reset", status_code=303)

@router.post("/reset_mfa", dependencies=[Depends(admin_only)])
async def reset_mfa(user_id: int = Form(...), session: Session = Depends(get_db_session), current_user: User = Depends(get_current_user)):
    user = session.exec(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)).first()
    if user:
        user.mfa_enabled = False
        user.mfa_secret = None
        session.add(user)
        session.commit()
    return RedirectResponse(url="/users/?msg=MFA+reset", status_code=303)

@router.get("/{user_id}/edit", response_class=HTMLResponse, dependencies=[Depends(admin_only)])
async def edit_user_form(
    request: Request, 
    user_id: int, 
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    # Platform Admin Only (for editing tenants) or Tenant Admin (limited)
    if current_user.tenant_id is not None:
         # Restrict to own tenant
         user = session.exec(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id)).first()
         tenants = []
    else:
         # Platform Admin
         user = session.get(User, user_id)
         tenants = session.exec(select(Tenant).order_by(Tenant.name)).all()
         
    if not user:
        return RedirectResponse(url="/users/?error=User+not+found", status_code=303)

    return templates.TemplateResponse("user_edit.html", {
        "request": request,
        "user_to_edit": user, # user object
        "user": current_user, # current admin
        "tenants": tenants
    })

@router.post("/{user_id}/edit", dependencies=[Depends(admin_only)])
async def edit_user(
    user_id: int,
    role: str = Form(...),
    active_tenant_id: Optional[int] = Form(None),
    allowed_tenant_ids: List[int] = Form([]),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    # Authorization Check
    user = session.get(User, user_id)
    if not user:
         return RedirectResponse(url="/users/?error=User+not+found", status_code=303)
         
    if current_user.tenant_id is not None:
        # Tenant Admin trying to edit
        if user.tenant_id != current_user.tenant_id:
             return RedirectResponse(url="/users/?error=Permission+denied", status_code=303)
        # Prevent changing tenant things
        user.role = role
        session.add(user)
        session.commit()
        return RedirectResponse(url="/users/?msg=User+updated", status_code=303)
        
    # Platform Admin Logic
    
    # SAFETY CHECK: Prevent Platform Admin from locking themselves out
    is_self_edit = (user.id == current_user.id)
    if is_self_edit and current_user.tenant_id is None and active_tenant_id is not None:
         return RedirectResponse(url=f"/users/{user_id}/edit?error=Cannot+assign+tenant+to+Platform+Admin+(Self)", status_code=303)

    user.role = role
    user.tenant_id = active_tenant_id # Change context
    
    # Update Allowed Tenants (Link Table)
    # delete existing
    links = session.exec(select(UserTenantLink).where(UserTenantLink.user_id == user.id)).all()
    for l in links:
        session.delete(l)
    
    # add new
    # Always include active tenant if set
    ids_to_add = set(allowed_tenant_ids)
    if active_tenant_id:
        ids_to_add.add(active_tenant_id)
        
    for tid in ids_to_add:
        link = UserTenantLink(user_id=user.id, tenant_id=tid)
        session.add(link)
        
    session.add(user)
    session.commit()
    
    return RedirectResponse(url="/users/?msg=User+updated", status_code=303)
