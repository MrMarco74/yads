from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from datetime import timedelta
from typing import Optional

from yads.auth.security import verify_password, create_access_token, get_password_hash
from yads.models import User, SystemConfig
from yads.auth.deps import get_db_session, get_current_user
from yads.config import settings

import pyotp

router = APIRouter()
templates = Jinja2Templates(directory="yads/api/templates")

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants
# Inject Globals
from datetime import datetime
templates.env.globals['settings'] = settings
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...),
    otp_code: Optional[str] = Form(None),
    response: Response = None,
    session: Session = Depends(get_db_session)
):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Invalid username or password"
        })
        
    if not user.is_active:
         return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "User is inactive"
        })

    # MFA Check
    if user.mfa_enabled:
        # Determine Window
        window = 1
        window_conf = session.get(SystemConfig, "OTP_VALID_WINDOW")
        if window_conf:
             try:
                 window = int(window_conf.value)
             except:
                 pass
                 
        if not otp_code:
            return templates.TemplateResponse("login.html", {
                "request": request, 
                "mfa_required": True, 
                "username": username, 
                "password": password # In prod, don't echo password back, but here we need it for resubmission or store in temp session
                # Better: Don't echo password, make user re-enter or use a signed temp token. 
                # For this MVP, we will ask user to enter Code + Password again or just Code if we handle it differently (HTMX).
                # The current template expects user to submit everything again.
            })
        else:
             totp = pyotp.TOTP(user.mfa_secret)
             if not totp.verify(otp_code, valid_window=window):
                 return templates.TemplateResponse("login.html", {
                     "request": request,
                     "error": "Invalid MFA Code",
                     "mfa_required": True,
                     "username": username
                 })

    # Success    # Create Token
    token_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    
    # 1. Tenant-Specific Override (Prioritize User's Tenant)
    if user.tenant_id:
         # Need to fetch tenant settings. 
         # user.tenant might be lazy loaded or not loaded.
         from yads.models import Tenant
         tenant_ctx = session.get(Tenant, user.tenant_id)
         if tenant_ctx and tenant_ctx.session_timeout_minutes:
             token_minutes = tenant_ctx.session_timeout_minutes
    
    # 2. System Level Override (Only if Tenant didn't set it? Or maybe System overrides Tenant?)
    # Usually System Admin Config > Default, but Tenant Config > System Default?
    # Logic: Tenant Config > System Config (if we want tenant specific) OR System Config > Tenant Config.
    # Requirement: "Give tenant admin the possibility to choose". So Tenant Config wins.
    # But if Tenant Config is default (60) and System Config is changed?
    # We'll assume if user.tenant_id is set, use tenant specific.
    # If not (Platform Admin), use System Config.
    
    if not user.tenant_id:
        tm_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
        if tm_conf:
            try:
                token_minutes = int(tm_conf.value)
            except:
                pass


             
    access_token = create_access_token(
        subject=user.username, 
        expires_delta=timedelta(minutes=token_minutes)
    )
    
    redirect_url = "/"
    if user.force_password_change:
        redirect_url = "/auth/change-password"
    elif not user.mfa_enabled:
        redirect_url = "/mfa/setup"
        
    # Update Last Login
    user.last_login = datetime.utcnow()
    session.add(user)
    session.commit()

    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True, 
        max_age=token_minutes * 60,
        samesite="lax",
        secure=False # Set to True in HTTPS
    )
    return response

@router.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("access_token")
    return resp

# MFA Setup Routes (Protected)
@router.get("/mfa/setup", response_class=HTMLResponse)
async def mfa_setup_page(request: Request, user: User = Depends(get_current_user)):
    if user.mfa_enabled:
        return templates.TemplateResponse("mfa_setup.html", {"request": request, "message": "MFA is already enabled."})

    # Generate Secret
    if not user.mfa_secret:
        # Assuming Session is also injected via Depends in get_current_user or we need a fresh one to save?
        # get_current_user returns a detached object usually if session closed? 
        # Actually get_current_user uses a session dependency, but that session closes after the request.
        # We need a new session to write to DB here or pass session to get_current_user differently?
        # Standard Pattern: In route, get session, get user by ID from session.
        pass

    # We need to save the secret to DB temporarily or permanently?
    # Usually: Generate secret -> Show QR -> Verify -> Save/Enable.
    
    # For simplicity: Generate fresh secret now, pass to template. 
    # User must Scan and Enter Code to Confirm.
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="YADS")
    
    return templates.TemplateResponse("mfa_setup.html", {
        "request": request, 
        "secret": secret,
        "otp_uri": uri
    })

@router.post("/mfa/verify")
async def mfa_verify(
    request: Request, 
    first_code: str = Form(...),
    secret: str = Form(...),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user)
):
    totp = pyotp.TOTP(secret)
    if totp.verify(first_code):
        # Valid! Save secret and enable MFA
        # Re-fetch user from this session to attach properties
        db_user = session.get(User, user.id)
        db_user.mfa_secret = secret
        db_user.mfa_enabled = True
        session.add(db_user)
        session.commit()
        return RedirectResponse(url="/?msg=MFA+Enabled", status_code=303)
    else:
        return templates.TemplateResponse("mfa_setup.html", {
            "request": request, 
            "secret": secret,
            "otp_uri": totp.provisioning_uri(name=user.username, issuer_name="YADS"),
            "error": "Invalid Code. Try again."
        })

@router.get("/auth/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

@router.post("/auth/change-password")
async def change_password_action(
    request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user)
):
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request, 
            "error": "Passwords do not match."
        })
        
    db_user = session.get(User, user.id)
    db_user.password_hash = get_password_hash(new_password)
    db_user.force_password_change = False
    session.add(db_user)
    session.commit()
    
    # Check if MFA needs setup next
    if not db_user.mfa_enabled:
        return RedirectResponse(url="/mfa/setup", status_code=303)
        
    return RedirectResponse(url="/?msg=Password+Updated", status_code=303)

@router.post("/auth/switch-tenant")
async def switch_tenant(
    request: Request,
    tenant_id: str = Form(...), # str because it needs parsing to int or checking for empty
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    # Determine Referer to redirect back
    referer = request.headers.get("referer", "/")
    # Prevent redirect loops if referer causes issues? Usually fine.
    
    # Check if tenant_id is valid
    # Logic:
    # 1. Platform Admin can switch to ANY tenant (if we want that? Or just rely on admin dashboard?)
    #    User said: "make the tenant selectable (global)" for Platform Admin?
    #    Actually current request is for mrmarco who is in multiple tenants.
    #    So general logic: User can switch to any tenant in their allowed_tenants list.
    
    # Case: Platform Admin switching back to "Platform View" (No Tenant)
    if tenant_id == "":
        if current_user.role == 'admin': # Only admin role can be platform admin
             # Check if they are truly platform admin?
             # If they were assigned a tenant temporarily, they are still admin role.
             # We should allow them to clear tenant_id if they are intended to be platform admins?
             # Or only if they have no allowed_tenants? 
             # Let's assume anyone with role 'admin' can try to go to Platform Mode, 
             # but we might restrict later. For now, if passed "", set to None.
             current_user.tenant_id = None
             session.add(current_user)
             session.commit()
             return RedirectResponse(url=referer, status_code=303)
        else:
             return RedirectResponse(url=referer + "?error=Not+authorized", status_code=303)

    try:
        tid = int(tenant_id)
    except ValueError:
        return RedirectResponse(url=referer + "?error=Invalid+Tenant+ID", status_code=303)

    # Check authorization
    # Platform Admin (temporarily in a tenant context) should be able to switch to any tenant?
    # Or should we require them to be in allowed_tenants? 
    # Current implementation of link table: Platform Admin usually doesn't need link table.
    # But if they are in context, they might need a way out or to another.
    
    # Simplest safe logic:
    # 1. Is user Platform Admin (current tenant is None)? -> Can switch to any tenant? 
    #    No, usually we want them to enter a context.
    # 2. Check allowed_tenants list.
    
    # Fetch User with allowed tenants loaded?
    # get_current_user might not load them eagerly but SQLModel handles lazy loading often?
    # Better to key query.
    
    from yads.models import UserTenantLink
    # Check if link exists
    link = session.exec(select(UserTenantLink).where(
        UserTenantLink.user_id == current_user.id,
        UserTenantLink.tenant_id == tid
    )).first()
    
    # Special Case: Platform Admin (who might not have links but has superpower?)
    # If I am a Platform Admin (tenant_id is None), I can switch to ANY tenant.
    is_platform_admin = (current_user.role == 'admin' and current_user.tenant_id is None)
    # BUT wait, the request is for mrmarco who is NOT platform admin but has multiple tenants.
    
    if link or is_platform_admin:
        current_user.tenant_id = tid
        session.add(current_user)
        session.commit()
        return RedirectResponse(url=referer, status_code=303)
        
    # Also handle Case where Admin is currently in a tenant (so tenant_id is NOT None)
    # but wants to switch to another. They might not have a link if they "impersonated" it?
    # For now, stay strict: Must have link OR be currently NULL tenant (Platform Root).
    # If they are stuck in a tenant, they rely on the link.
    
    return RedirectResponse(url=referer + "?error=Access+Denied+to+Tenant", status_code=303)
