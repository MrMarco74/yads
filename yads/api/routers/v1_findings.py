"""API-key-authenticated, tenant-scoped Findings & Compliance read surface
for yads-mcp (Wave 3). Read-only: exposes the persisted SecurityFinding
records and per-target ComplianceTargetStatus rows with filtering, pagination
and summaries. All queries are scoped to the API key's tenant.

Distinct from the crude /api/v1/findings in v1.py (which dumps every raw
ScanResult unfiltered); that endpoint is left untouched for backwards compat.
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select, func

from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.database import get_session
from yads.models import APIKey, SecurityFinding, ComplianceTargetStatus, Target

router = APIRouter(prefix="/api/v1", tags=["API v1 — Findings & Compliance"])


def _finding_dict(f: SecurityFinding) -> dict:
    return {
        "yf_id": f.yf_id,
        "target_id": f.target_id,
        "domain": f.domain,
        "module": f.module,
        "issue": f.issue,
        "severity": f.severity,
        "status": f.status,
        "first_found": f.first_found.isoformat() if f.first_found else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "due_date": f.due_date.isoformat() if f.due_date else None,
    }


@router.get("/findings", dependencies=[Depends(RequireScope("read"))])
async def list_findings(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    severity: Optional[str] = None,
    status: Optional[str] = None,
    module: Optional[str] = None,
    domain_search: Optional[str] = None,
    page: int = 1,
    limit: int = Query(default=20, le=200),
):
    """Paginated, filtered list of security findings for the key's tenant."""
    if page < 1 or limit < 1:
        raise HTTPException(status_code=422, detail="page and limit must be >= 1")

    base = select(SecurityFinding).where(SecurityFinding.tenant_id == api_key.tenant_id)
    if severity:
        base = base.where(SecurityFinding.severity == severity)
    if status:
        base = base.where(SecurityFinding.status == status)
    if module:
        base = base.where(SecurityFinding.module == module)
    if domain_search:
        base = base.where(SecurityFinding.domain.ilike(f"%{domain_search}%"))

    total = session.exec(select(func.count()).select_from(base.subquery())).one()
    rows = session.exec(
        base.order_by(SecurityFinding.first_found.desc())
        .offset((page - 1) * limit).limit(limit)
    ).all()
    return {
        "items": [_finding_dict(f) for f in rows],
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/findings/summary", dependencies=[Depends(RequireScope("read"))])
async def findings_summary(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    """Counts of the tenant's findings grouped by severity, status and module."""
    def _counts(column):
        rows = session.exec(
            select(column, func.count())
            .where(SecurityFinding.tenant_id == api_key.tenant_id)
            .group_by(column)
        ).all()
        return {k: v for k, v in rows}

    by_severity = _counts(SecurityFinding.severity)
    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
        "by_status": _counts(SecurityFinding.status),
        "by_module": _counts(SecurityFinding.module),
    }


@router.get("/findings/{yf_id}", dependencies=[Depends(RequireScope("read"))])
async def get_finding(
    yf_id: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    f = session.exec(
        select(SecurityFinding).where(
            SecurityFinding.yf_id == yf_id,
            SecurityFinding.tenant_id == api_key.tenant_id,
        )
    ).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    d = _finding_dict(f)
    d["status_note"] = f.status_note
    d["assigned_to"] = f.assigned_to
    d["ticket_ref"] = f.ticket_ref
    return d


@router.get("/compliance/status", dependencies=[Depends(RequireScope("read"))])
async def compliance_status(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    framework: Optional[str] = None,
    page: int = 1,
    limit: int = Query(default=50, le=500),
):
    """Per-target compliance status rows (joined to the target domain), scoped
    to the tenant via the target's tenant_id."""
    if page < 1 or limit < 1:
        raise HTTPException(status_code=422, detail="page and limit must be >= 1")

    base = (
        select(ComplianceTargetStatus, Target.domain)
        .join(Target, Target.id == ComplianceTargetStatus.target_id)
        .where(Target.tenant_id == api_key.tenant_id)
    )
    if framework:
        base = base.where(ComplianceTargetStatus.framework == framework)

    total = session.exec(select(func.count()).select_from(base.subquery())).one()
    rows = session.exec(
        base.order_by(ComplianceTargetStatus.score.asc())
        .offset((page - 1) * limit).limit(limit)
    ).all()
    items = [{
        "target_id": cs.target_id,
        "domain": domain,
        "framework": cs.framework,
        "score": cs.score,
        "grade": cs.grade,
        "passing_controls": cs.passing_controls,
        "failing_controls": cs.failing_controls,
        "last_assessed_at": cs.last_assessed_at.isoformat() if cs.last_assessed_at else None,
    } for cs, domain in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.get("/compliance/summary", dependencies=[Depends(RequireScope("read"))])
async def compliance_summary(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    """Per-framework rollup for the tenant: target count, average score, and
    grade distribution."""
    rows = session.exec(
        select(
            ComplianceTargetStatus.framework,
            func.count(),
            func.avg(ComplianceTargetStatus.score),
        )
        .join(Target, Target.id == ComplianceTargetStatus.target_id)
        .where(Target.tenant_id == api_key.tenant_id)
        .group_by(ComplianceTargetStatus.framework)
    ).all()

    frameworks = {}
    for framework, count, avg_score in rows:
        grade_rows = session.exec(
            select(ComplianceTargetStatus.grade, func.count())
            .join(Target, Target.id == ComplianceTargetStatus.target_id)
            .where(
                Target.tenant_id == api_key.tenant_id,
                ComplianceTargetStatus.framework == framework,
            )
            .group_by(ComplianceTargetStatus.grade)
        ).all()
        frameworks[framework] = {
            "target_count": count,
            "avg_score": round(float(avg_score), 1) if avg_score is not None else None,
            "grade_distribution": {g: c for g, c in grade_rows},
        }
    return {"frameworks": frameworks}
