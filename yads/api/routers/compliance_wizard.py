import logging
from types import SimpleNamespace
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from yads.database import get_session
from yads.auth.deps import RoleChecker
from yads.models import User, Target, Tenant, ComplianceScanRun, BrandWatch, ShadowDomainCandidate
from yads.api.templating import templates
from yads.api.routers.targets import _build_bulk_criteria_query, _audit_scan_trigger

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance-wizard", tags=["compliance"])

_ALLOWED_ROLES = ["admin", "tenant_admin", "scanner"]


def _effective_tenant_id(session: Session, user: User) -> Optional[int]:
    """Resolve the tenant this wizard run/dashboard should be scoped to.

    Tenant-bound users just use their own tenant_id. A platform admin with no
    tenant selected (user.tenant_id is None -- see the tenant-switch flow in
    yads/api/routers/auth.py) has no single tenant to scope a
    ComplianceScanRun row to (its tenant_id column is NOT NULL), so this is a
    new fallback introduced for this wizard, not reused prior art: if the
    deployment is unambiguous (exactly one Tenant row exists), auto-resolve
    to that tenant; otherwise return None so the caller can ask the admin to
    select a tenant first (see start_run's 400 response below). Note this
    differs from the "admin with tenant_id is None -> unscoped query across
    all tenants" pattern used elsewhere (e.g. attack_surface.py,
    scan_compare.py) -- that pattern works for read-only, multi-row views,
    but doesn't apply here since a ComplianceScanRun needs exactly one
    tenant_id to be written.
    """
    if user.tenant_id is not None:
        return user.tenant_id
    tenant_ids = session.exec(select(Tenant.id)).all()
    if len(tenant_ids) == 1:
        return tenant_ids[0]
    return None


def _latest_run(session: Session, user: User) -> Optional[ComplianceScanRun]:
    tenant_id = _effective_tenant_id(session, user)
    if tenant_id is None:
        return None
    return session.exec(
        select(ComplianceScanRun)
        .where(ComplianceScanRun.tenant_id == tenant_id)
        .order_by(ComplianceScanRun.id.desc())
    ).first()


@router.get("", response_class=HTMLResponse)
async def wizard_or_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    run = _latest_run(session, user)
    tenant_id = _effective_tenant_id(session, user)
    watches = session.exec(
        select(BrandWatch).where(BrandWatch.tenant_id == tenant_id)
    ).all() if tenant_id is not None else []

    return templates.TemplateResponse("compliance_wizard.html", {
        "request": request,
        "user": user,
        "run": run,
        "watches": watches,
    })


@router.post("/start", response_class=HTMLResponse)
async def start_run(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    form = await request.form()
    criteria = form.get("criteria", "all")
    only_roots = criteria == "only_roots"
    online_only = criteria == "online_only"

    tenant_id = _effective_tenant_id(session, user)
    if tenant_id is None:
        return HTMLResponse(
            "<p class=\"text-red-400\">Select a tenant before starting a compliance run.</p>",
            status_code=400,
        )

    # _build_bulk_criteria_query only ever reads user.tenant_id, so for a
    # platform admin (user.tenant_id is None) resolved to a single tenant
    # above, pass a stand-in exposing the resolved tenant_id instead of
    # mutating the live `user` ORM object (which would risk persisting a
    # tenant-context change on the next commit).
    query_user = user if user.tenant_id is not None else SimpleNamespace(tenant_id=tenant_id)
    query = _build_bulk_criteria_query(session, query_user, only_roots=only_roots, online_only=online_only)
    target_ids = list(session.exec(query).all())

    run = ComplianceScanRun(
        tenant_id=tenant_id,
        criteria=criteria,
        current_step=2,
        target_ids=target_ids,
        targets_total=len(target_ids),
    )
    session.add(run)
    session.commit()
    session.refresh(run)

    _audit_scan_trigger(
        session, user,
        [str(tid) for tid in target_ids[:50]],
        ["web_analyzer"], "compliance_wizard_start", request,
    )

    return RedirectResponse(url="/compliance-wizard", status_code=303)
