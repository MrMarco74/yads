"""
Onboarding Wizard — shown to new tenants with zero targets.

GET  /onboarding                       → wizard page (5 steps)
POST /onboarding/target                → create first target, redirect to step 3
POST /onboarding/installation-report  → opt-in anonymous telemetry, redirect to step 5
POST /onboarding/dismiss               → store ONBOARDING_DONE, redirect to /
"""
import logging
import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, func

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import SystemConfig, Target, User

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _onboarding_done(session: Session, tenant_id: Optional[int]) -> bool:
    key = f"ONBOARDING_DONE_{tenant_id}" if tenant_id else "ONBOARDING_DONE_admin"
    conf = session.get(SystemConfig, key)
    return conf is not None and conf.value == "1"


def _set_onboarding_done(session: Session, tenant_id: Optional[int]):
    key = f"ONBOARDING_DONE_{tenant_id}" if tenant_id else "ONBOARDING_DONE_admin"
    existing = session.get(SystemConfig, key)
    if existing:
        existing.value = "1"
        session.add(existing)
    else:
        session.add(SystemConfig(key=key, value="1"))
    session.commit()


@router.get("/onboarding", response_class=HTMLResponse)
async def onboarding_wizard(
    request: Request,
    step: int = 1,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    # Redirect platform admins or users who completed onboarding
    if _onboarding_done(session, user.tenant_id):
        return RedirectResponse("/", status_code=302)

    # Count targets for this tenant
    if user.tenant_id is not None:
        target_count = session.exec(
            select(func.count()).where(Target.tenant_id == user.tenant_id)
        ).one()
    else:
        target_count = session.exec(select(func.count()).select_from(Target)).one()

    # For step 4, build the telemetry preview data
    telemetry_preview = None
    if step == 4:
        telemetry_preview = _build_telemetry_payload(session)

    return templates.TemplateResponse("onboarding.html", {
        "request": request,
        "user": user,
        "step": step,
        "target_count": target_count,
        "telemetry_preview": telemetry_preview,
    })


@router.post("/onboarding/dismiss", response_class=HTMLResponse)
async def dismiss_onboarding(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    _set_onboarding_done(session, user.tenant_id)
    return RedirectResponse("/", status_code=303)


@router.post("/onboarding/target", response_class=HTMLResponse)
async def onboarding_add_target(
    request: Request,
    domain: str = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")
    if not domain or not _DOMAIN_RE.match(domain):
        return RedirectResponse("/onboarding?step=2&error=invalid", status_code=303)

    existing = session.exec(
        select(Target).where(Target.domain == domain, Target.tenant_id == user.tenant_id)
    ).first()
    if not existing:
        target = Target(domain=domain, tenant_id=user.tenant_id)
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id
    else:
        target_id = existing.id

    return RedirectResponse(f"/onboarding?step=3&target_id={target_id}", status_code=303)


def _get_or_create_instance_uuid(session: Session) -> str:
    """Return the stable anonymous instance UUID (create on first call)."""
    conf = session.get(SystemConfig, "INSTANCE_UUID")
    if conf:
        return conf.value
    new_uuid = str(uuid.uuid4())
    session.add(SystemConfig(key="INSTANCE_UUID", value=new_uuid))
    session.commit()
    return new_uuid


def _build_telemetry_payload(session: Session) -> dict:
    """Build the anonymous telemetry payload shown as preview to the user."""
    from datetime import datetime, timezone
    from yads.config import settings
    return {
        "instance_uuid": _get_or_create_instance_uuid(session),
        "version": settings.VERSION,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@router.post("/onboarding/installation-report", response_class=HTMLResponse)
async def send_installation_report(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """Mark the onboarding installation-report step as acknowledged."""
    from yads.models import SystemConfig as _SC
    existing_flag = session.get(_SC, "INSTALL_REPORT_SENT")
    if not existing_flag:
        session.add(_SC(key="INSTALL_REPORT_SENT", value="1"))
        session.commit()

    return RedirectResponse("/onboarding?step=5", status_code=303)
