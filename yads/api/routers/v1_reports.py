"""API-key-authenticated, tenant-scoped Reports & Export read surface for
yads-mcp (Wave 4). Structured JSON views an LLM agent can reason over —
executive posture summary, security-score trend, and a flat targets export —
as opposed to the dashboard's binary PDF/Excel/CSV downloads.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select, func

from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.database import get_session
from yads.models import APIKey, Target, SecurityTrend

router = APIRouter(prefix="/api/v1/reports", tags=["API v1 — Reports & Export"])


@router.get("/executive", dependencies=[Depends(RequireScope("read"))])
async def executive_summary(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    """Executive security-posture summary for the key's tenant: target counts,
    severity breakdown, overall score/grade, top risky targets, top finding
    types, risk trend and recommended actions. Same data as the dashboard's
    Executive Report, as JSON."""
    # _compute_executive_data only reads .tenant_id and .role off the user;
    # pass a tenant-scoped shim rather than loading a real User row.
    from yads.api.routers.executive_report import _compute_executive_data
    shim = SimpleNamespace(tenant_id=api_key.tenant_id, role="scanner")
    return _compute_executive_data(session, shim)


@router.get("/trends", dependencies=[Depends(RequireScope("read"))])
async def security_trends(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    days: int = Query(default=30, ge=1, le=730),
):
    """Historical security-score points for the tenant over the last `days`
    (oldest first) — for plotting/summarizing the posture trend."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    rows = session.exec(
        select(SecurityTrend)
        .where(SecurityTrend.tenant_id == api_key.tenant_id,
               SecurityTrend.recorded_at >= cutoff)
        .order_by(SecurityTrend.recorded_at.asc())
    ).all()
    return {
        "days": days,
        "points": [
            {"score": r.score, "grade": r.grade,
             "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None}
            for r in rows
        ],
    }


@router.get("/targets/export", dependencies=[Depends(RequireScope("read"))])
async def targets_export(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    tag: Optional[str] = None,
    online: Optional[bool] = None,
    archived: bool = False,
    page: int = 1,
    limit: int = Query(default=500, le=2000),
):
    """Flat, reporting-oriented export of the tenant's targets (domain, status,
    tags, rating, timestamps). Higher page size than list_targets for bulk
    export; still paginated to stay bounded at portfolio scale."""
    base = select(Target).where(Target.tenant_id == api_key.tenant_id)
    if not archived:
        base = base.where(Target.is_archived == False)  # noqa: E712
    if tag:
        base = base.where(Target.tags.contains([tag]))

    total = session.exec(select(func.count()).select_from(base.subquery())).one()
    rows = session.exec(
        base.order_by(Target.domain.asc()).offset((page - 1) * limit).limit(limit)
    ).all()
    items = [{
        "id": t.id,
        "domain": t.domain,
        "scan_status": t.scan_status,
        "is_archived": t.is_archived,
        "tags": t.tags or [],
        "relevance_score": t.relevance_score,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    } for t in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}
