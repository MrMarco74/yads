# yads/api/routers/v1_scan.py
"""API-key-authenticated scan-triggering surface for yads-mcp and other
machine clients. See
docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md section 5.3.
"""

from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from yads.auth.deps import RequireScope, get_api_key
from yads.core.module_registry import REGISTRY
from yads.core.scheduler import get_active_scan_count, get_max_concurrent_scans
from yads.database import get_session
from yads.models import APIKey, Target
from yads.worker import celery_app

router = APIRouter(prefix="/api/v1", tags=["API v1 — Scanning"])


class ScanTriggerRequest(BaseModel):
    scan_types: List[str]
    scan_priority: Optional[int] = None


@router.post("/targets/{target_id}/scan", dependencies=[Depends(RequireScope("scan_execute"))])
async def scan_trigger_by_target_id(
    target_id: int,
    payload: ScanTriggerRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(get_api_key)],
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
