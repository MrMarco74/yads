"""API-key-authenticated, tenant-scoped OSINT / Discovery / Intelligence read
surface for yads-mcp (Wave 5): discovery sessions and their candidates, brand
watches, and shadow-domain candidates (the DORA brand-abuse hunt output).
Read-only.
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select, func

from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.database import get_session
from yads.models import (APIKey, DiscoverySession, DiscoveryCandidate,
                         BrandWatch, ShadowDomainCandidate)

router = APIRouter(prefix="/api/v1", tags=["API v1 — Discovery & Intelligence"])


def _session_dict(s: DiscoverySession) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "seed_domains": s.seed_domains or [],
        "status": s.status,
        "max_depth": s.max_depth,
        "current_depth": s.current_depth,
        "total_discovered": s.total_discovered,
        "total_accepted": s.total_accepted,
        "total_rejected": s.total_rejected,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


@router.get("/discovery/sessions", dependencies=[Depends(RequireScope("read"))])
async def list_discovery_sessions(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    status: Optional[str] = None,
    page: int = 1,
    limit: int = Query(default=20, le=200),
):
    """Discovery (asset-hunting) sessions for the key's tenant, newest first."""
    base = select(DiscoverySession).where(DiscoverySession.tenant_id == api_key.tenant_id)
    if status:
        base = base.where(DiscoverySession.status == status)
    total = session.exec(select(func.count()).select_from(base.subquery())).one()
    rows = session.exec(
        base.order_by(DiscoverySession.created_at.desc())
        .offset((page - 1) * limit).limit(limit)
    ).all()
    return {"items": [_session_dict(s) for s in rows], "total": total, "page": page, "limit": limit}


@router.get("/discovery/sessions/{session_id}", dependencies=[Depends(RequireScope("read"))])
async def get_discovery_session(
    session_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    s = session.exec(
        select(DiscoverySession).where(
            DiscoverySession.id == session_id,
            DiscoverySession.tenant_id == api_key.tenant_id,
        )
    ).first()
    if not s:
        raise HTTPException(status_code=404, detail="Discovery session not found")
    return _session_dict(s)


@router.get("/discovery/sessions/{session_id}/candidates", dependencies=[Depends(RequireScope("read"))])
async def list_discovery_candidates(
    session_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    status: Optional[str] = None,
    page: int = 1,
    limit: int = Query(default=50, le=500),
):
    """Discovered domain candidates for one session (relevance-ranked). The
    parent session is tenant-checked first, so this never leaks another
    tenant's candidates."""
    owner = session.exec(
        select(DiscoverySession.id).where(
            DiscoverySession.id == session_id,
            DiscoverySession.tenant_id == api_key.tenant_id,
        )
    ).first()
    if not owner:
        raise HTTPException(status_code=404, detail="Discovery session not found")

    base = select(DiscoveryCandidate).where(DiscoveryCandidate.session_id == session_id)
    if status:
        base = base.where(DiscoveryCandidate.status == status)
    total = session.exec(select(func.count()).select_from(base.subquery())).one()
    rows = session.exec(
        base.order_by(DiscoveryCandidate.relevance_score.desc())
        .offset((page - 1) * limit).limit(limit)
    ).all()
    items = [{
        "id": c.id,
        "domain": c.domain,
        "source_scanner": c.source_scanner,
        "depth": c.depth,
        "relevance_score": c.relevance_score,
        "matching_signals": c.matching_signals or [],
        "status": c.status,
    } for c in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.get("/brand-watches", dependencies=[Depends(RequireScope("read"))])
async def list_brand_watches(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    """Recurring brand-keyword shadow-domain watches for the tenant, each with
    its current shadow-candidate count."""
    watches = session.exec(
        select(BrandWatch).where(BrandWatch.tenant_id == api_key.tenant_id)
        .order_by(BrandWatch.created_at.desc())
    ).all()
    items = []
    for w in watches:
        count = session.exec(
            select(func.count()).select_from(ShadowDomainCandidate)
            .where(ShadowDomainCandidate.brand_watch_id == w.id)
        ).one()
        items.append({
            "id": w.id,
            "keyword": w.keyword,
            "active": w.active,
            "last_run_at": w.last_run_at.isoformat() if w.last_run_at else None,
            "candidate_count": count,
        })
    return {"items": items, "total": len(items)}


@router.get("/shadow-domains", dependencies=[Depends(RequireScope("read"))])
async def list_shadow_domains(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    status: Optional[str] = None,
    brand_watch_id: Optional[int] = None,
    page: int = 1,
    limit: int = Query(default=50, le=500),
):
    """Shadow-domain candidates found by brand watches for the tenant (the DORA
    brand-abuse hunt output). Filter by status (new/confirmed/dismissed) and/or
    brand_watch_id."""
    base = select(ShadowDomainCandidate).where(ShadowDomainCandidate.tenant_id == api_key.tenant_id)
    if status:
        base = base.where(ShadowDomainCandidate.status == status)
    if brand_watch_id is not None:
        base = base.where(ShadowDomainCandidate.brand_watch_id == brand_watch_id)
    total = session.exec(select(func.count()).select_from(base.subquery())).one()
    rows = session.exec(
        base.order_by(ShadowDomainCandidate.first_seen_at.desc())
        .offset((page - 1) * limit).limit(limit)
    ).all()
    items = [{
        "id": s.id,
        "discovered_domain": s.discovered_domain,
        "brand_watch_id": s.brand_watch_id,
        "source": s.source,
        "status": s.status,
        "resolved_target_id": s.resolved_target_id,
        "first_seen_at": s.first_seen_at.isoformat() if s.first_seen_at else None,
        "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
    } for s in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}
