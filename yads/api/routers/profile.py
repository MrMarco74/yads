from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from typing import Optional

from yads.database import get_session
from yads.models import User, SystemConfig
from yads.auth.deps import get_current_user_html, get_current_user
from yads.auth.security import get_password_hash
from yads.config import settings
from yads.core.security_audit import log_password_change, log_mfa_event, log_user_modified
from yads.core.i18n import normalize_lang

router = APIRouter(
    prefix="/profile",
    tags=["profile"]
)

templates = Jinja2Templates(directory="yads/api/templates")

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

@router.get("/", response_class=HTMLResponse)
async def view_profile(
    request: Request,
    user: User = Depends(get_current_user_html),
    session: Session = Depends(get_session)
):
    # Fetch session timeout for admin display if needed
    timeout_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    if user.role == 'admin':
        timeout_conf = session.get(SystemConfig, "ACCESS_TOKEN_EXPIRE_MINUTES")
        if timeout_conf:
            try:
                timeout_minutes = int(timeout_conf.value)
            except ValueError as e:
                import logging
                logging.getLogger(__name__).warning(f"Failed to parse ACCESS_TOKEN_EXPIRE_MINUTES: {e}")

    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "session_minutes": timeout_minutes,
        "settings": settings
    })

@router.post("/update")
async def update_profile(
    request: Request,
    email: str = Form(...),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # Track old email for logging
    old_email = user.email

    # Update Email
    new_email = email.lower().strip() if email else None
    user.email = new_email
    session.add(user)

    # Log profile update if email changed
    if old_email != new_email:
        log_user_modified(request, user, user, {"email": {"old": old_email, "new": new_email}}, session)
    session.commit()
    return RedirectResponse(url="/profile/?msg=Profile+updated", status_code=303)

@router.post("/password")
async def change_password(
    request: Request,
    password: str = Form(...),
    password_confirm: str = Form(...),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    if password != password_confirm:
        return RedirectResponse(url="/profile/?error=Passwords+do+not+match", status_code=303)

    if len(password) < 8:
        return RedirectResponse(url="/profile/?error=Password+too+short", status_code=303)

    user.password_hash = get_password_hash(password)
    session.add(user)

    # Log password change event
    log_password_change(request, user, changed_by_admin=False, session=session)
    session.commit()

    return RedirectResponse(url="/profile/?msg=Password+changed+successfully", status_code=303)

@router.post("/language")
async def set_language(
    request: Request,
    language: str = Form(...),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    lang = normalize_lang(language)
    user.language = lang
    session.add(user)
    session.commit()
    response = RedirectResponse(url="/profile/?msg=Language+updated", status_code=303)
    response.set_cookie("yads_lang", lang, max_age=60 * 60 * 24 * 365, httponly=False, samesite="lax")
    return response


@router.post("/mfa/reset")
async def reset_mfa(
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    user.mfa_enabled = False
    user.mfa_secret = None
    session.add(user)

    # Log MFA reset by user
    log_mfa_event(request, user, "reset_by_user", by_admin=False, session=session)
    session.commit()
    return RedirectResponse(url="/profile/?msg=MFA+disabled", status_code=303)
