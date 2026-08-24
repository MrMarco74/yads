# yads/api/routers/v1_scan.py
"""API-key-authenticated scan-triggering surface for yads-mcp and other
machine clients. See
docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md section 5.3.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from yads.api.routers.targets import (
    _audit_scan_trigger,
    _build_bulk_criteria_query,
    _get_final_scan_types,
    _parse_bulk_criteria,
    _queue_single_bulk_target,
)
from yads.auth.deps import RequireScope, get_api_key, require_tenant_scoped_key
from yads.core.module_registry import REGISTRY
from yads.core.scheduler import get_active_scan_count, get_max_concurrent_scans
from yads.database import get_session
from yads.models import APIKey, Target
from yads.worker import celery_app

router = APIRouter(prefix="/api/v1", tags=["API v1 — Scanning"])


class ScanTriggerRequest(BaseModel):
    scan_types: List[str]
    scan_priority: Optional[int] = None


@dataclass
class _ApiKeyAsUser:
    """`_build_bulk_criteria_query`, `_queue_single_bulk_target`, and
    `_audit_scan_trigger` (targets.py) were written to take a `User` ORM
    object and read `.tenant_id`/`.username`/`.id` off it. An `APIKey` has
    `.tenant_id` but no `.username`; this shim adapts an APIKey into the
    minimal shape those functions actually touch, so their tenant-scoping
    logic can be reused verbatim instead of re-implemented here."""
    tenant_id: Optional[int]
    id: Optional[int] = None
    username: str = "api-key"


class BulkScanByCriteriaRequest(BaseModel):
    scan_types: List[str]
    only_roots: bool = False
    online_only: bool = False
    scanned_before: Optional[str] = None


@router.get("/targets/bulk-scan/preview-count")
async def bulk_scan_preview_count(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    only_roots: bool = False,
    online_only: bool = False,
    scanned_before: Optional[str] = None,
):
    from sqlmodel import func as sqlfunc

    fake_user = _ApiKeyAsUser(tenant_id=api_key.tenant_id)
    parsed_only_roots, parsed_online_only, cutoff = _parse_bulk_criteria(only_roots, online_only, scanned_before)
    query = _build_bulk_criteria_query(
        session, fake_user, only_roots=parsed_only_roots, online_only=parsed_online_only, scanned_before=cutoff
    )
    count = session.exec(select(sqlfunc.count()).select_from(query.subquery())).one()
    return {"count": count}


@router.post("/targets/bulk-scan", dependencies=[Depends(RequireScope("scan_execute"))])
async def bulk_scan_by_criteria(
    payload: BulkScanByCriteriaRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    fake_user = _ApiKeyAsUser(tenant_id=api_key.tenant_id)

    final_types = _get_final_scan_types(payload.scan_types)
    if not final_types:
        raise HTTPException(status_code=400, detail="No valid scan types selected")

    only_roots, online_only, cutoff = _parse_bulk_criteria(
        payload.only_roots, payload.online_only, payload.scanned_before
    )
    query = _build_bulk_criteria_query(session, fake_user, only_roots=only_roots, online_only=online_only, scanned_before=cutoff)
    matched_ids = session.exec(query).all()

    count = 0
    for tid in matched_ids:
        if _queue_single_bulk_target(session, fake_user, str(tid), final_types):
            count += 1
    session.commit()
    _audit_scan_trigger(session, None, [str(t) for t in matched_ids[:50]], final_types, "bulk_scan_by_criteria_api")

    return {"matched_count": len(matched_ids), "queued_count": count, "scan_types": final_types}


class BulkScanSelectedRequest(BaseModel):
    target_ids: List[int]
    scan_types: List[str]


@router.post("/targets/bulk/scan", dependencies=[Depends(RequireScope("scan_execute"))])
async def bulk_scan_selected(
    payload: BulkScanSelectedRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    fake_user = _ApiKeyAsUser(tenant_id=api_key.tenant_id)
    final_types = _get_final_scan_types(payload.scan_types)
    if not final_types:
        raise HTTPException(status_code=400, detail="No valid scan types selected")

    count = 0
    for tid in payload.target_ids:
        if _queue_single_bulk_target(session, fake_user, str(tid), final_types):
            count += 1
    session.commit()
    _audit_scan_trigger(session, None, [str(t) for t in payload.target_ids[:50]], final_types, "bulk_scan_selected_api")

    return {"requested_count": len(payload.target_ids), "queued_count": count, "scan_types": final_types}


# NOTE: this dynamic single-target route must be registered AFTER the static
# /targets/bulk-scan, /targets/bulk-scan/preview-count, and /targets/bulk/scan
# routes above -- Starlette matches routes in registration order, and
# /targets/{target_id}/scan would otherwise greedily match a request to
# /targets/bulk/scan (treating "bulk" as target_id and 422'ing on int
# validation) before the more specific bulk routes ever got a chance.
@router.post("/targets/{target_id}/scan", dependencies=[Depends(RequireScope("scan_execute"))])
async def scan_trigger_by_target_id(
    target_id: int,
    payload: ScanTriggerRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.scan_priority is not None:
        target.scan_priority = max(1, min(9, payload.scan_priority))

    valid_types = set(REGISTRY.keys()) | {"dns_cleanup", "full_scan"}
    selected_types = [t for t in payload.scan_types if t in valid_types]
    if not selected_types:
        raise HTTPException(status_code=400, detail="No valid scan types selected")

    if "full_scan" in selected_types:
        selected_types = [n for n in REGISTRY.keys() if n not in ("subdomain_scanner", "catchall_detector")]

    max_concurrent = get_max_concurrent_scans(session)
    if get_active_scan_count(session) >= max_concurrent:
        raise HTTPException(status_code=429, detail=f"Concurrent scan limit ({max_concurrent}) reached")

    celery_app.send_task(
        "yads.worker.run_all_scans",
        args=[target.id, target.domain, selected_types, api_key.tenant_id],
        priority=getattr(target, "scan_priority", 5),
    )

    target.scan_status = "queued"
    target.queued_at = datetime.utcnow()
    session.add(target)
    session.commit()

    return {"status": "queued", "target_id": target.id, "domain": target.domain, "scan_types": selected_types}
