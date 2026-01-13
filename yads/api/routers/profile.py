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

router = APIRouter(
    prefix="/profile",
    tags=["profile"]
)

templates = Jinja2Templates(directory="yads/api/templates")

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
            except:
                pass

    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "session_minutes": timeout_minutes,
        "settings": settings
    })

@router.post("/update")
async def update_profile(
    email: str = Form(...),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    # Update Email
    user.email = email.lower().strip() if email else None
    session.add(user)
    session.commit()
    return RedirectResponse(url="/profile/?msg=Profile+updated", status_code=303)

@router.post("/password")
async def change_password(
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
    session.commit()
    
    return RedirectResponse(url="/profile/?msg=Password+changed+successfully", status_code=303)

@router.post("/mfa/reset")
async def reset_mfa(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    user.mfa_enabled = False
    user.mfa_secret = None
    session.add(user)
    session.commit()
    return RedirectResponse(url="/profile/?msg=MFA+disabled", status_code=303)
