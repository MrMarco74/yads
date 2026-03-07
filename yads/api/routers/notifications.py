from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select
from datetime import datetime

from yads.database import get_session
from yads.models import Notification, User
from yads.auth.deps import get_current_user_html, RoleChecker
from yads.config import settings

router = APIRouter(prefix="/notifications", tags=["notifications"])

from yads.api.templating import templates
templates.env.globals['settings'] = settings

def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants

# Allow admins to manage notifications
allow_admin = RoleChecker(["admin"])

@router.get("/", response_model=List[Notification])
async def list_notifications(session: Session = Depends(get_session)):
    """
    List all active notifications.
    Intended to be public or at least accessible to all authenticated users.
    Order by created_at desc.
    """
    statement = select(Notification).order_by(Notification.created_at.desc())
    return session.exec(statement).all()

# --- Admin UI Routes ---

@router.get("/admin", response_class=HTMLResponse)
async def admin_notifications(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    _: bool = Depends(allow_admin)
):
    """
    Admin UI for managing notifications.
    """
    notifications = session.exec(select(Notification).order_by(Notification.created_at.desc())).all()
    templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    
    return templates.TemplateResponse("admin/notifications.html", {
        "request": request,
        "user": user,
        "notifications": notifications,
        "settings": settings
    })

@router.post("/admin/create", response_class=RedirectResponse)
async def admin_create_notification(
    request: Request,
    title: str = Form(...),
    text: str = Form(...),
    type: str = Form(...),
    color: str = Form("blue"),
    icon: str = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    _: bool = Depends(allow_admin)
):
    """
    Form handler for creating notifications.
    """
    notification = Notification(
        title=title,
        text=text,
        type=type,
        color=color,
        icon=icon,
        created_at=datetime.utcnow()
    )
    session.add(notification)
    session.commit()
    return RedirectResponse(url="/notifications/admin", status_code=303)

@router.post("/admin/delete/{notification_id}", response_class=RedirectResponse)
async def admin_delete_notification(
    notification_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    _: bool = Depends(allow_admin)
):
    """
    Form handler for deleting notifications (e.g. via direct POST form).
    """
    notification = session.get(Notification, notification_id)
    if notification:
        session.delete(notification)
        session.commit()
    return RedirectResponse(url="/notifications/admin", status_code=303)

# --- API Routes ---

@router.post("/", response_model=Notification)
async def create_notification(
    notification: Notification, 
    session: Session = Depends(get_session),
    _: bool = Depends(allow_admin)
):
    """
    Create a new system notification (API).
    """
    notification.created_at = datetime.utcnow()
    session.add(notification)
    session.commit()
    session.refresh(notification)
    return notification

@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: int, 
    session: Session = Depends(get_session),
    _: bool = Depends(allow_admin)
):
    """
    Delete a notification by ID (API).
    """
    notification = session.get(Notification, notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
        
    session.delete(notification)
    session.commit()
    return {"ok": True}
