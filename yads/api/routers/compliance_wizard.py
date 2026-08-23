import logging
from datetime import datetime
from types import SimpleNamespace
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, or_, and_, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from yads.database import get_session
from yads.auth.deps import RoleChecker
from yads.models import User, Target, Tenant, ComplianceScanRun, BrandWatch, ShadowDomainCandidate, ScanResult, SecurityAuditLog
from yads.api.templating import templates
from yads.api.routers.targets import _build_bulk_criteria_query, _audit_scan_trigger, _queue_single_bulk_target

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


def _latest_run(session: Session, user: User, tenant_id: Optional[int] = None) -> Optional[ComplianceScanRun]:
    """tenant_id may be passed in by a caller that has already resolved it
    (e.g. wizard_or_dashboard, to avoid a second _effective_tenant_id query
    per dashboard load) -- otherwise it's resolved here as before."""
    if tenant_id is None:
        tenant_id = _effective_tenant_id(session, user)
    if tenant_id is None:
        return None
    return session.exec(
        select(ComplianceScanRun)
        .where(ComplianceScanRun.tenant_id == tenant_id)
        .order_by(ComplianceScanRun.id.desc())
    ).first()


def _webserver_confirmed_ids(session: Session, target_ids: list[int]) -> list[int]:
    if not target_ids:
        return []
    rows = session.exec(
        select(ScanResult.target_id)
        .where(
            ScanResult.target_id.in_(target_ids),
            ScanResult.module_name == 'web_analyzer',
            text("(data->>'status_code')::int > 0"),
        )
        .distinct()
    ).all()
    return list(rows)


def _compute_step3_progress(session: Session, run: ComplianceScanRun) -> int:
    if not run.target_ids:
        return 0
    crawled = session.exec(
        select(func.count(func.distinct(ScanResult.target_id)))
        .where(ScanResult.target_id.in_(run.target_ids), ScanResult.module_name == 'crawler')
    ).one()
    return crawled or 0


def _compute_step2_progress(session: Session, run: ComplianceScanRun) -> tuple[int, int]:
    if not run.target_ids:
        return (0, 0)

    reachable_criteria = or_(
        and_(ScanResult.module_name == 'infrastructure_scanner', text("data->>'ip' IS NOT NULL")),
        and_(ScanResult.module_name == 'web_analyzer', text("(data->>'status_code')::int > 0")),
        and_(ScanResult.module_name == 'port_scanner', text("data->>'is_active' = 'true'")),
    )
    reachable = session.exec(
        select(func.count(func.distinct(ScanResult.target_id)))
        .where(ScanResult.target_id.in_(run.target_ids), reachable_criteria)
    ).one()

    webserver_ids = _webserver_confirmed_ids(session, run.target_ids)
    webserver = len(webserver_ids)

    return (reachable or 0, webserver or 0)


@router.get("", response_class=HTMLResponse)
async def wizard_or_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    tenant_id = _effective_tenant_id(session, user)
    run = _latest_run(session, user, tenant_id=tenant_id)
    if run and run.current_step >= 2:
        reachable, webserver_confirmed = _compute_step2_progress(session, run)
        if reachable != run.targets_reachable or webserver_confirmed != run.targets_webserver_confirmed:
            run.targets_reachable = reachable
            run.targets_webserver_confirmed = webserver_confirmed
            session.add(run)
            session.commit()
    if run and run.current_step >= 4:
        crawled = _compute_step3_progress(session, run)
        if crawled != run.targets_crawled:
            run.targets_crawled = crawled
            session.add(run)
            session.commit()
    watches = session.exec(
        select(BrandWatch).where(BrandWatch.tenant_id == tenant_id)
    ).all() if tenant_id is not None else []

    pending_candidates = []
    if watches:
        pending_candidates = session.exec(
            select(ShadowDomainCandidate)
            .where(
                ShadowDomainCandidate.tenant_id == tenant_id,
                ShadowDomainCandidate.status == "new",
            )
            .order_by(ShadowDomainCandidate.first_seen_at.desc())
        ).all()

    return templates.TemplateResponse("compliance_wizard.html", {
        "request": request,
        "user": user,
        "run": run,
        "watches": watches,
        "pending_candidates": pending_candidates,
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
        created_by_user_id=user.id,
    )
    session.add(run)
    session.commit()
    session.refresh(run)

    # _audit_scan_trigger reads user.tenant_id directly to stamp the audit
    # row's tenant_id, which is None for a platform admin -- pass a stand-in
    # exposing the resolved tenant_id instead (same pattern as query_user
    # above), so the wizard's own audit trail isn't left with tenant_id=NULL
    # for exactly the admin user who most needs it resolved.
    audit_user = user if user.tenant_id is not None else SimpleNamespace(tenant_id=tenant_id, username=user.username, id=user.id)
    _audit_scan_trigger(
        session, audit_user,
        [str(tid) for tid in target_ids[:50]],
        ["web_analyzer"], "compliance_wizard_start", request,
    )

    return RedirectResponse(url="/compliance-wizard", status_code=303)


@router.post("/{run_id}/step2", response_class=HTMLResponse)
async def dispatch_step2(
    run_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    tenant_id = _effective_tenant_id(session, user)
    run = session.exec(
        select(ComplianceScanRun).where(
            ComplianceScanRun.id == run_id,
            ComplianceScanRun.tenant_id == tenant_id,
        )
    ).first()
    if not run:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    # _queue_single_bulk_target only ever reads user.tenant_id, so for a
    # platform admin (user.tenant_id is None) resolved to a single tenant
    # above, pass a stand-in exposing the resolved tenant_id -- same pattern
    # as start_run's query_user, for the same reason.
    query_user = user if user.tenant_id is not None else SimpleNamespace(tenant_id=tenant_id)
    for tid in run.target_ids:
        _queue_single_bulk_target(session, query_user, str(tid), ["web_analyzer"])

    run.current_step = 3
    run.step2_completed_at = datetime.utcnow()
    session.add(run)
    session.commit()

    # See start_run's audit_user comment: _audit_scan_trigger reads
    # user.tenant_id directly, so resolve it for a platform admin here too.
    audit_user = user if user.tenant_id is not None else SimpleNamespace(tenant_id=tenant_id, username=user.username, id=user.id)
    _audit_scan_trigger(session, audit_user, [str(t) for t in run.target_ids[:50]], ["web_analyzer"], "compliance_wizard_step2", request)

    return RedirectResponse(url="/compliance-wizard", status_code=303)


@router.post("/{run_id}/step3", response_class=HTMLResponse)
async def dispatch_step3(
    run_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    tenant_id = _effective_tenant_id(session, user)
    run = session.exec(
        select(ComplianceScanRun).where(
            ComplianceScanRun.id == run_id,
            ComplianceScanRun.tenant_id == tenant_id,
        )
    ).first()
    if not run:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    # _queue_single_bulk_target only ever reads user.tenant_id, so for a
    # platform admin (user.tenant_id is None) resolved to a single tenant
    # above, pass a stand-in exposing the resolved tenant_id -- same pattern
    # as start_run's/dispatch_step2's query_user, for the same reason.
    query_user = user if user.tenant_id is not None else SimpleNamespace(tenant_id=tenant_id)
    confirmed_ids = _webserver_confirmed_ids(session, run.target_ids)
    for tid in confirmed_ids:
        _queue_single_bulk_target(session, query_user, str(tid), ["crawler"])

    run.current_step = 4
    run.step3_completed_at = datetime.utcnow()
    session.add(run)
    session.commit()

    # See start_run's audit_user comment: _audit_scan_trigger reads
    # user.tenant_id directly, so resolve it for a platform admin here too.
    audit_user = user if user.tenant_id is not None else SimpleNamespace(tenant_id=tenant_id, username=user.username, id=user.id)
    _audit_scan_trigger(session, audit_user, [str(t) for t in confirmed_ids[:50]], ["crawler"], "compliance_wizard_step3", request)

    return RedirectResponse(url="/compliance-wizard", status_code=303)


@router.post("/{run_id}/step4", response_class=HTMLResponse)
async def create_brand_watch(
    run_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    tenant_id = _effective_tenant_id(session, user)
    if tenant_id is None:
        return HTMLResponse(
            "<p class=\"text-red-400\">Select a tenant before starting a compliance run.</p>",
            status_code=400,
        )

    run = session.exec(
        select(ComplianceScanRun).where(
            ComplianceScanRun.id == run_id,
            ComplianceScanRun.tenant_id == tenant_id,
        )
    ).first()
    if not run:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    form = await request.form()
    keyword = (form.get("keyword") or "").strip().lower()
    if not keyword:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    # Guard against duplicate BrandWatch rows from a double-submit (double
    # click, retry) -- one active watch per tenant+keyword is enough; a
    # second submission should just advance the run, not create a sibling
    # watch that would double every future crt.sh query and candidate set.
    existing_watch = session.exec(
        select(BrandWatch).where(
            BrandWatch.tenant_id == tenant_id,
            BrandWatch.keyword == keyword,
            BrandWatch.active == True,
        )
    ).first()
    if not existing_watch:
        watch = BrandWatch(tenant_id=tenant_id, keyword=keyword, created_by_user_id=user.id)
        session.add(watch)

    # Step 4 has no further wizard steps -- advance past current_step 4 so
    # the step-4 form stops rendering once a watch exists for this run.
    if run.current_step == 4:
        run.current_step = 5
        session.add(run)
    session.commit()

    return RedirectResponse(url="/compliance-wizard", status_code=303)


@router.post("/shadow-domains/{candidate_id}/confirm", response_class=HTMLResponse)
async def confirm_shadow_domain(
    candidate_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    tenant_id = _effective_tenant_id(session, user)
    candidate = session.exec(
        select(ShadowDomainCandidate).where(
            ShadowDomainCandidate.id == candidate_id,
            ShadowDomainCandidate.tenant_id == tenant_id,
        )
    ).first()
    if not candidate:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    # Target.domain has a GLOBAL unique constraint (not per-tenant), but
    # run_brand_watch_scan only diffs discovered domains against Targets for
    # the SAME tenant as the watch -- so a domain already owned by a
    # DIFFERENT tenant can surface here as a "new" candidate. Check first
    # rather than let the insert raise an uncaught IntegrityError.
    existing_target = session.exec(
        select(Target).where(Target.domain == candidate.discovered_domain)
    ).first()

    if existing_target and existing_target.tenant_id != tenant_id:
        return HTMLResponse(
            "<p class=\"text-red-400\">This domain is already tracked as a target by another tenant "
            "and cannot be confirmed here. Please investigate before proceeding.</p>",
            status_code=409,
        )

    if existing_target:
        # Already a Target for THIS tenant (e.g. added out-of-band since the
        # scan ran) -- reuse it instead of inserting a duplicate.
        new_target = existing_target
    else:
        new_target = Target(domain=candidate.discovered_domain, tenant_id=tenant_id)
        session.add(new_target)
        try:
            session.commit()
        except IntegrityError:
            # Lost a race: another request inserted this exact domain between
            # our check above and this insert. Re-fetch and handle it exactly
            # like the existing_target branch above, rather than 500ing.
            session.rollback()
            new_target = session.exec(
                select(Target).where(Target.domain == candidate.discovered_domain)
            ).first()
            if new_target is None:
                return HTMLResponse(
                    "<p class=\"text-red-400\">Could not confirm this domain due to a conflicting update. Please retry.</p>",
                    status_code=409,
                )
            if new_target.tenant_id != tenant_id:
                return HTMLResponse(
                    "<p class=\"text-red-400\">This domain is already tracked as a target by another tenant "
                    "and cannot be confirmed here. Please investigate before proceeding.</p>",
                    status_code=409,
                )
        else:
            session.refresh(new_target)

    candidate.status = "confirmed"
    candidate.resolved_target_id = new_target.id
    session.add(candidate)

    entry = SecurityAuditLog(
        event_type="shadow_domain_confirmed",
        username=user.username, user_id=user.id, tenant_id=tenant_id,
        source_ip=request.client.host if request.client else None,
        success=True,
        details={"discovered_domain": candidate.discovered_domain, "new_target_id": new_target.id},
    )
    session.add(entry)
    session.commit()

    return RedirectResponse(url="/compliance-wizard", status_code=303)


@router.post("/shadow-domains/{candidate_id}/dismiss", response_class=HTMLResponse)
async def dismiss_shadow_domain(
    candidate_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(_ALLOWED_ROLES)),
):
    form = await request.form()
    reason = (form.get("reason") or "").strip()

    tenant_id = _effective_tenant_id(session, user)
    candidate = session.exec(
        select(ShadowDomainCandidate).where(
            ShadowDomainCandidate.id == candidate_id,
            ShadowDomainCandidate.tenant_id == tenant_id,
        )
    ).first()
    if not candidate:
        return RedirectResponse(url="/compliance-wizard", status_code=303)

    candidate.status = "dismissed"
    candidate.dismissed_reason = reason
    session.add(candidate)

    entry = SecurityAuditLog(
        event_type="shadow_domain_dismissed",
        username=user.username, user_id=user.id, tenant_id=tenant_id,
        source_ip=request.client.host if request.client else None,
        success=True,
        details={"discovered_domain": candidate.discovered_domain, "reason": reason},
    )
    session.add(entry)
    session.commit()

    return RedirectResponse(url="/compliance-wizard", status_code=303)
