"""
Onboarding Wizard — shown to new tenants with zero targets.

GET  /onboarding        → wizard page (redirects away if targets exist + wizard dismissed)
POST /onboarding/dismiss → store ONBOARDING_DONE in SystemConfig, redirect to /
POST /onboarding/target  → create first target, redirect to wizard step 3
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, func

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import SystemConfig, Target, User

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

    return templates.TemplateResponse("onboarding.html", {
        "request": request,
        "user": user,
        "step": step,
        "target_count": target_count,
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
    if not domain:
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
