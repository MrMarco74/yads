"""API-key-authenticated Target/Asset Management surface for yads-mcp and
other machine clients. See
docs/superpowers/specs/2026-08-24-yads-mcp-wave2-targets-design.md.
"""

from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, and_, func, or_, select, text

from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.database import get_session
from yads.models import APIKey, ScanResult, Target

router = APIRouter(prefix="/api/v1", tags=["API v1 — Targets"])


@router.get("/targets", dependencies=[Depends(RequireScope("read"))])
async def list_targets(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    tag: Optional[str] = None,
    online: Optional[bool] = None,
    scan_status: Optional[str] = None,
    domain_search: Optional[str] = None,
    archived: bool = False,
    last_scanned_before: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
):
    limit = min(limit, 100)
    page = max(page, 1)

    query = select(Target).where(
        Target.tenant_id == api_key.tenant_id,
        Target.is_archived == archived,
    )

    if tag:
        query = query.where(Target.tags.contains([tag]))
    if scan_status:
        query = query.where(Target.scan_status == scan_status)
    if domain_search:
        query = query.where(Target.domain.ilike(f"%{domain_search}%"))
    if online is not None:
        online_criteria = or_(
            and_(ScanResult.module_name == "infrastructure_scanner", text("data->>'ip' IS NOT NULL")),
            and_(ScanResult.module_name == "web_analyzer", text("(data->>'status_code')::int > 0")),
            and_(ScanResult.module_name == "port_scanner", text("data->>'is_active' = 'true'")),
        )
        sub_online = select(ScanResult.target_id).where(online_criteria).distinct()
        if online:
            query = query.where(Target.id.in_(sub_online))
        else:
            query = query.where(Target.id.notin_(sub_online))
    if last_scanned_before:
        try:
            cutoff = datetime.fromisoformat(last_scanned_before)
        except ValueError:
            raise HTTPException(status_code=400, detail="last_scanned_before must be an ISO date string")
        sub_recent = select(ScanResult.target_id).where(ScanResult.scanned_at >= cutoff).distinct()
        query = query.where(Target.id.notin_(sub_recent))

    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    rows = session.exec(query.order_by(Target.domain).offset((page - 1) * limit).limit(limit)).all()

    return {
        "targets": [
            {"id": t.id, "domain": t.domain, "scan_status": t.scan_status, "tags": t.tags, "is_archived": t.is_archived, "created_at": t.created_at.isoformat()}
            for t in rows
        ],
        "total": total,
        "page": page,
    }


@router.get("/targets/{target_id}", dependencies=[Depends(RequireScope("read"))])
async def get_target(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    last_scan_at = session.exec(
        select(func.max(ScanResult.scanned_at)).where(ScanResult.target_id == target_id)
    ).one()
    module_count = session.exec(
        select(func.count(func.distinct(ScanResult.module_name))).where(ScanResult.target_id == target_id)
    ).one()

    return {
        "id": target.id,
        "domain": target.domain,
        "scan_status": target.scan_status,
        "scan_progress": target.scan_progress,
        "tags": target.tags,
        "is_archived": target.is_archived,
        "archived_reason": target.archived_reason,
        "created_at": target.created_at.isoformat(),
        "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
        "module_count": module_count,
    }
