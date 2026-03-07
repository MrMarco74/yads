"""
Attack Surface Change Feed (#22 — Differenz-Alerting)

Shows a chronological feed of scan result changes detected across all targets.
ChangeEvents are recorded by BaseScannerModule.process() whenever a module's
result hash changes between runs.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import ChangeEvent, ScanResult, Target, User

router = APIRouter(prefix="/changes", tags=["changes"])

from yads.core.module_registry import get_module_labels as _get_module_labels

MODULE_LABELS = {
    **_get_module_labels(),
    # Modules not in main registry but may appear in change events
    "dns_cleanup": "DNS Health Check",
    "cve_scanner": "CVE Scanner",
}


@router.get("/", response_class=HTMLResponse)
async def view_changes(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    days: int = 7,
    event_type: Optional[str] = None,
    module: Optional[str] = None,
    target_id: Optional[int] = None,
):
    # Determine visible target IDs for this user/tenant
    if user.role == "admin" and user.tenant_id is None:
        targets_stmt = select(Target)
    else:
        targets_stmt = select(Target).where(Target.tenant_id == user.tenant_id)

    all_targets = session.exec(targets_stmt).all()
    target_map = {t.id: t for t in all_targets}
    visible_ids = list(target_map.keys())

    if not visible_ids:
        return templates.TemplateResponse("changes.html", {
            "request": request,
            "user": user,
            "events": [],
            "targets": all_targets,
            "module_labels": MODULE_LABELS,
            "days": days,
            "event_type": event_type,
            "module_filter": module,
            "target_id": target_id,
            "stats": {"total": 0, "data_changed": 0, "first_scan": 0},
        })

    cutoff = datetime.utcnow() - timedelta(days=days)

    # Query ChangeEvents → ScanResult → Target (tenant-scoped)
    stmt = (
        select(ChangeEvent, ScanResult)
        .join(ScanResult, ChangeEvent.scan_result_id == ScanResult.id)
        .where(ScanResult.target_id.in_(visible_ids))
        .where(ChangeEvent.created_at >= cutoff)
        .order_by(ChangeEvent.created_at.desc())
        .limit(500)
    )

    if event_type:
        stmt = stmt.where(ChangeEvent.event_type == event_type)
    if module:
        stmt = stmt.where(ScanResult.module_name == module)
    if target_id and target_id in target_map:
        stmt = stmt.where(ScanResult.target_id == target_id)

    rows = session.exec(stmt).all()

    events = []
    for ev, sr in rows:
        t = target_map.get(sr.target_id)
        events.append({
            "id": ev.id,
            "event_type": ev.event_type,
            "description": ev.description,
            "created_at": ev.created_at,
            "module_name": sr.module_name,
            "module_label": MODULE_LABELS.get(sr.module_name, sr.module_name),
            "target_id": sr.target_id,
            "target_domain": t.domain if t else "unknown",
            "scan_result_id": sr.id,
        })

    # Stats
    stats = {
        "total": len(events),
        "data_changed": sum(1 for e in events if e["event_type"] == "DATA_CHANGED"),
        "first_scan": sum(1 for e in events if e["event_type"] == "FIRST_SCAN"),
    }

    # Unique modules seen (for filter dropdown)
    seen_modules = sorted({e["module_name"] for e in events})

    return templates.TemplateResponse("changes.html", {
        "request": request,
        "user": user,
        "events": events,
        "targets": all_targets,
        "module_labels": MODULE_LABELS,
        "seen_modules": seen_modules,
        "days": days,
        "event_type": event_type,
        "module_filter": module,
        "target_id": target_id,
        "stats": stats,
    })
