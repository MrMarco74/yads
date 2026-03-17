import secrets
from datetime import timedelta
from typing import Optional
from urllib.parse import urlparse

import pyotp
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Response, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from yads.auth.security import verify_password, create_access_token, get_password_hash
from yads.models import User, SystemConfig
from yads.auth.deps import get_db_session, get_current_user
from yads.config import settings
from yads.database import redis_client
from yads.core.security_audit import (
    log_login_success, log_login_failure, log_logout,
    log_password_change, log_mfa_event, log_tenant_switch
)

router = APIRouter()
from yads.api.templating import templates

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

def _safe_redirect(url: Optional[str], default: str = "/") -> str:
    """Reject absolute or protocol-relative URLs to prevent open redirect."""
    if not url:
        return default
    parsed = urlparse(url)
    if parsed.scheme or parsed.netloc or url.startswith("//"):
        return default
    return url


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "auth_mode": settings.AUTH_MODE,
    })

def _get_otp_window(session: Session) -> int:
    conf = session.get(SystemConfig, "OTP_VALID_WINDOW")
    if conf:
        try:
            return int(conf.value)
        except ValueError:
            pass
    return 1


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: Optional[str] = Form(None, max_length=150),
    password: Optional[str] = Form(None, max_length=1024),
    otp_code: Optional[str] = Form(None),
    mfa_token: Optional[str] = Form(None),
    response: Response = None,
    session: Session = Depends(get_db_session)
):
    import logging as _log
    _logger = _log.getLogger(__name__)

    # ── MFA second step: token-based (password never leaves the server) ──
    if mfa_token:
        pending_key = f"yads:mfa_pending:{mfa_token}"
        stored = redis_client.get(pending_key)
        if not stored:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "MFA session expired. Please log in again."
            })
        pending_username = stored.decode()
        user = session.exec(select(User).where(User.username == pending_username)).first()
        if not user or not user.is_active:
            redis_client.delete(pending_key)
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Invalid session."
            })
        if not otp_code or not pyotp.TOTP(user.mfa_secret).verify(
            otp_code, valid_window=_get_otp_window(session)
        ):
            log_login_failure(request, pending_username, "mfa_invalid", session)
            session.commit()
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Invalid MFA Code",
                "mfa_required": True,
                "username": pending_username,
                "mfa_token": mfa_token,
            })
        redis_client.delete(pending_key)

    # ── First step: username + password ──
    else:
        # Rate limiting: 10 attempts per IP per 5 minutes
        client_ip = (request.client.host if request.client else "unknown")
        rate_key = f"yads:login_rate:{client_ip}"
        attempts = redis_client.incr(rate_key)
        if attempts == 1:
            redis_client.expire(rate_key, 300)
        if attempts > 10:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Too many login attempts. Please try again later."
            })

        if not username or not password:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Invalid username or password"
            })

        user = session.exec(select(User).where(User.username == username)).first()
        if not user:
            log_login_failure(request, username, "invalid_user", session)
            session.commit()
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Invalid username or password"
            })

        if not verify_password(password, user.password_hash):
            log_login_failure(request, username, "invalid_password", session)
            session.commit()
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Invalid username or password"
            })

        if not user.is_active:
            log_login_failure(request, username, "inactive", session)
            session.commit()
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "User is inactive"
            })

        if user.mfa_enabled and settings.MFA_ENABLED:
            # Issue a short-lived token — password stays on the server
            token = secrets.token_urlsafe(32)
            redis_client.setex(f"yads:mfa_pending:{token}", 300, user.username)
            log_login_failure(request, username, "mfa_required", session)
            session.commit()
            return templates.TemplateResponse("login.html", {
                "request": request,
                "mfa_required": True,
                "username": username,
                "mfa_token": token,
            })

    # ── Success ──
    token_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    if user.tenant_id:
        from yads.models import Tenant
        tenant_ctx = session.get(Tenant, user.tenant_id)
        if tenant_ctx and tenant_ctx.session_timeout_minutes:
            token_minutes = tenant_ctx.session_timeout_minutes
    if not user.tenant_id:
        tm_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
        if tm_conf:
            try:
                token_minutes = int(tm_conf.value)
            except ValueError:
                _logger.warning("Failed to parse ACCESS_TOKEN_EXPIRE_MINUTES")

    access_token = create_access_token(
        subject=user.username,
        expires_delta=timedelta(minutes=token_minutes)
    )

    redirect_url = "/"
    if user.force_password_change:
        redirect_url = "/auth/change-password"
    elif not user.mfa_enabled and settings.MFA_ENABLED:
        redirect_url = "/mfa/setup"

    user.last_login = datetime.utcnow()
    session.add(user)
    log_login_success(request, user, session)
    session.commit()

    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=token_minutes * 60,
        samesite="lax",
        secure=not settings.DEBUG,
    )
    return response

@router.get("/logout")
async def logout(
    request: Request,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    # Log logout event
    log_logout(request, current_user, session)
    session.commit()

    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("access_token")
    return resp

# MFA Setup Routes (Protected)
@router.get("/mfa/setup", response_class=HTMLResponse)
async def mfa_setup_page(
    request: Request,
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    if user.mfa_enabled:
        return templates.TemplateResponse("mfa_setup.html", {"request": request, "message": "MFA is already enabled."})

    # Generate secret server-side and persist it — never rely on client to send it back
    secret = pyotp.random_base32()
    db_user = session.get(User, user.id)
    db_user.pending_mfa_secret = secret
    session.add(db_user)
    session.commit()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="YADS")

    return templates.TemplateResponse("mfa_setup.html", {
        "request": request,
        "secret": secret,
        "otp_uri": uri,
    })

@router.post("/mfa/verify")
async def mfa_verify(
    request: Request,
    first_code: str = Form(...),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
):
    # Read secret from DB — never trust client-submitted secret
    db_user = session.get(User, user.id)
    secret = db_user.pending_mfa_secret
    if not secret:
        raise HTTPException(
            status_code=400,
            detail="No MFA enrollment in progress. Please restart MFA setup.",
        )

    totp = pyotp.TOTP(secret)
    if totp.verify(first_code):
        db_user.mfa_secret = secret
        db_user.mfa_enabled = True
        db_user.pending_mfa_secret = None  # Clear enrollment secret
        session.add(db_user)
        log_mfa_event(request, db_user, "enabled", by_admin=False, session=session)
        session.commit()
        return RedirectResponse(url="/?msg=MFA+Enabled", status_code=303)
    else:
        return templates.TemplateResponse("mfa_setup.html", {
            "request": request,
            "secret": secret,
            "otp_uri": totp.provisioning_uri(name=db_user.username, issuer_name="YADS"),
            "error": "Invalid Code. Try again.",
        })

@router.get("/auth/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    return templates.TemplateResponse("change_password.html", {"request": request})

@router.post("/auth/change-password")
async def change_password_action(
    request: Request,
    new_password: str = Form(..., max_length=1024),
    confirm_password: str = Form(..., max_length=1024),
    session: Session = Depends(get_db_session),
    user: User = Depends(get_current_user)
):
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request, 
            "error": "Passwords do not match."
        })
        
    db_user = session.get(User, user.id)
    was_forced = db_user.force_password_change
    db_user.password_hash = get_password_hash(new_password)
    db_user.force_password_change = False
    session.add(db_user)

    # Log password change event
    log_password_change(request, db_user, changed_by_admin=False, session=session)
    session.commit()

    # Check if MFA needs setup next
    if not db_user.mfa_enabled and settings.MFA_ENABLED:
        return RedirectResponse(url="/mfa/setup", status_code=303)

    return RedirectResponse(url="/?msg=Password+Updated", status_code=303)

@router.get("/auth/switch-tenant")
async def switch_tenant_get(
    next_url: Optional[str] = Query(None, alias="next"),
):
    """GET fallback — redirect to next or home (avoids JSON 422 on direct navigation)."""
    return RedirectResponse(url=_safe_redirect(next_url), status_code=303)


@router.post("/auth/switch-tenant")
async def switch_tenant(
    request: Request,
    tenant_id: str = Form(default=""),  # empty string = switch to Platform Admin (no tenant)
    next_url: Optional[str] = Query(None, alias="next"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    # Sanitize redirect target — reject absolute/external URLs
    referer = request.headers.get("referer", "/")
    redirect_target = _safe_redirect(next_url or referer)
    
    # Check if tenant_id is valid
    # Logic:
    # 1. Platform Admin can switch to ANY tenant (if we want that? Or just rely on admin dashboard?)
    #    User said: "make the tenant selectable (global)" for Platform Admin?
    #    Actually current request is for mrmarco who is in multiple tenants.
    #    So general logic: User can switch to any tenant in their allowed_tenants list.
    
    # Case: Platform Admin switching back to "Platform View" (No Tenant)
    if tenant_id == "":
        if current_user.role == 'admin':  # Only admin role can be platform admin
            old_tenant_id = current_user.tenant_id
            current_user.tenant_id = None
            session.add(current_user)

            # Log tenant switch event
            log_tenant_switch(request, current_user, old_tenant_id, None, session)
            session.commit()
            return RedirectResponse(url=redirect_target, status_code=303)
        else:
             return RedirectResponse(url=redirect_target + "?error=Not+authorized", status_code=303)

    try:
        tid = int(tenant_id)
    except ValueError:
        return RedirectResponse(url=redirect_target + "?error=Invalid+Tenant+ID", status_code=303)

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
    # UPDATE: User requested that any 'admin' role user can switch to any tenant, 
    # even if they are currently inside a tenant context.
    is_platform_admin = (current_user.role == 'admin')
    
    if link or is_platform_admin:
        old_tenant_id = current_user.tenant_id
        current_user.tenant_id = tid
        session.add(current_user)

        # Log tenant switch event
        log_tenant_switch(request, current_user, old_tenant_id, tid, session)
        session.commit()
        return RedirectResponse(url=redirect_target, status_code=303)
        
    # Also handle Case where Admin is currently in a tenant (so tenant_id is NOT None)
    # but wants to switch to another. They might not have a link if they "impersonated" it?
    # For now, stay strict: Must have link OR be currently NULL tenant (Platform Root).
    # If they are stuck in a tenant, they rely on the link.
    
    return RedirectResponse(url=redirect_target + "?error=Access+Denied+to+Tenant", status_code=303)


# ── OIDC / Keycloak Login ──────────────────────────────────────────────────

import logging
logger = logging.getLogger(__name__)


@router.get("/auth/oidc/login")
async def oidc_login(realm: Optional[str] = None):
    """
    Startet OIDC-Login-Flow. Redirectet zu Keycloak.
    Optional: ?realm=frischkorn für tenant-spezifischen Realm.
    """
    from yads.auth.oidc import get_authorization_url

    if settings.AUTH_MODE != "oidc":
        raise HTTPException(status_code=400, detail="OIDC not enabled (AUTH_MODE=local)")

    url = get_authorization_url(realm=realm)
    return RedirectResponse(url=url)


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    code: Optional[str] = None,
    error: Optional[str] = None,
    session: Session = Depends(get_db_session),
):
    """
    Keycloak Callback-Endpoint.
    Tauscht Authorization Code gegen Token, erstellt Session.
    """
    from yads.auth.oidc import exchange_code_for_token, decode_token_claims, get_or_create_user
    from yads.auth.security import create_access_token

    if error:
        logger.warning(f"OIDC callback error: {error}")
        return RedirectResponse(url="/login?error=oidc_error")

    if not code:
        return RedirectResponse(url="/login?error=no_code")

    # Token austauschen
    token_response = exchange_code_for_token(code)
    if not token_response:
        return RedirectResponse(url="/login?error=token_exchange_failed")

    # Claims dekodieren
    claims = decode_token_claims(token_response)
    if not claims:
        return RedirectResponse(url="/login?error=invalid_token")

    # User erstellen/aktualisieren
    user = get_or_create_user(session, claims)
    if not user:
        return RedirectResponse(url="/login?error=user_creation_failed")

    # YADS Session-Cookie setzen (gleicher Mechanismus wie lokaler Login)
    access_token = create_access_token(subject=user.username)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=not settings.DEBUG,
    )
    logger.info(f"OIDC login successful: {user.email} (role={user.role})")
    return response
