"""API-key-authenticated Target/Asset Management surface for yads-mcp and
other machine clients. See
docs/superpowers/specs/2026-08-24-yads-mcp-wave2-targets-design.md.
"""

import json
import uuid as _uuid
from datetime import datetime
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, and_, func, or_, select, text

from yads.api.routers.targets import _get_owned_target_ids, _is_internal_target, _perform_bulk_delete_from_db
from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.core.redis_logger import get_scan_network_context as get_network_ctx
from yads.database import get_session, redis_client
from yads.models import APIKey, ChangeEvent, DiscoveryDomainBlocklist, ScanResult, Target
from yads.worker import celery_app

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
    if limit > 100 or limit < 1:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
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
            # "offline" mirrors the dashboard's definition: has been scanned
            # at least once, but isn't in the online set -- never-scanned
            # targets are "unknown", not "offline".
            sub_scanned = select(ScanResult.target_id).distinct()
            query = query.where(Target.id.in_(sub_scanned))
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


class AddTargetRequest(BaseModel):
    domain: str


@router.post("/targets", dependencies=[Depends(RequireScope("write"))])
async def add_target(
    payload: AddTargetRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    domain = payload.domain.lower().strip()
    if _is_internal_target(domain):
        raise HTTPException(status_code=400, detail="Internal targets blocked by SSRF protection")

    existing = session.exec(
        select(Target).where(Target.domain == domain, Target.tenant_id == api_key.tenant_id)
    ).first()
    if existing:
        return {"id": existing.id, "domain": existing.domain, "created": False}

    target = Target(domain=domain, tenant_id=api_key.tenant_id)
    session.add(target)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail="Domain is already registered under a different tenant",
        )
    session.refresh(target)
    return {"id": target.id, "domain": target.domain, "created": True}


class BulkDeleteRequest(BaseModel):
    target_ids: List[int]
    confirm: bool


@router.post("/targets/bulk-delete", dependencies=[Depends(RequireScope("destructive"))])
async def bulk_delete_targets(
    payload: BulkDeleteRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to delete these targets")
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    ids_to_delete = set(payload.target_ids)

    safe_ids = _get_owned_target_ids(session, api_key, ids_to_delete)
    if not safe_ids:
        raise HTTPException(status_code=404, detail="No owned targets found")

    revoked_count = 0
    i = celery_app.control.inspect(timeout=5.0)
    if i:
        for tasks in list((i.active() or {}).values()) + list((i.reserved() or {}).values()):
            for task in tasks:
                args = task.get("args", [])
                if args and isinstance(args, list) and len(args) > 0:
                    try:
                        if int(args[0]) in safe_ids:
                            celery_app.control.revoke(task.get("id"), terminate=True)
                            revoked_count += 1
                    except Exception:
                        continue

    targets_to_delete = session.exec(select(Target).where(Target.id.in_(safe_ids))).all()
    snapshot = [
        {"domain": t.domain, "tenant_id": t.tenant_id, "tags": t.tags, "discovery_reason": t.discovery_reason}
        for t in targets_to_delete
    ]
    undo_batch_id = _uuid.uuid4().hex[:12]
    redis_client.setex(f"yads:undo_delete:{undo_batch_id}", 60, json.dumps(snapshot))

    _perform_bulk_delete_from_db(session, safe_ids)
    session.commit()

    return {"deleted_count": len(safe_ids), "revoked_count": revoked_count, "undo_batch": undo_batch_id}


class UndoDeleteRequest(BaseModel):
    undo_batch: str


@router.post("/targets/bulk-delete/undo", dependencies=[Depends(RequireScope("write"))])
async def undo_bulk_delete_targets(
    payload: UndoDeleteRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    key = f"yads:undo_delete:{payload.undo_batch}"
    raw = redis_client.get(key)
    if not raw:
        raise HTTPException(status_code=404, detail="Undo window expired or batch not found")

    snapshot = json.loads(raw)
    own_entries = [entry for entry in snapshot if entry.get("tenant_id") == api_key.tenant_id]
    if not own_entries:
        raise HTTPException(status_code=404, detail="Undo window expired or batch not found")

    restored = 0
    for entry in own_entries:
        existing = session.exec(
            select(Target).where(Target.domain == entry["domain"], Target.tenant_id == entry["tenant_id"])
        ).first()
        if existing:
            continue
        session.add(Target(
            domain=entry["domain"], tenant_id=entry["tenant_id"],
            tags=entry.get("tags"), discovery_reason=entry.get("discovery_reason"),
        ))
        restored += 1
    session.commit()
    redis_client.delete(key)

    return {"restored_count": restored}


class BulkArchiveRequest(BaseModel):
    target_ids: List[int]


@router.post("/targets/bulk-archive", dependencies=[Depends(RequireScope("write"))])
async def bulk_archive_targets(
    payload: BulkArchiveRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    owned_targets = session.exec(
        select(Target).where(
            Target.id.in_(set(payload.target_ids)),
            Target.tenant_id == api_key.tenant_id,
            Target.is_archived == False,
        )
    ).all()

    count = 0
    for target in owned_targets:
        target.is_archived = True
        target.archived_at = datetime.utcnow()
        target.archived_reason = "manual"
        session.add(target)
        count += 1
    session.commit()

    return {"archived_count": count}


@router.post("/targets/archive-dead", dependencies=[Depends(RequireScope("write"))])
async def archive_dead_targets(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    subquery = text("""
        SELECT t.id FROM target t
        JOIN LATERAL (
            SELECT data FROM scanresult
            WHERE target_id = t.id AND module_name = 'dns_scanner'
            ORDER BY scanned_at DESC LIMIT 1
        ) sr ON true
        WHERE (sr.data->'records')::text = '{}'
        AND t.is_archived = false
        AND t.tenant_id = :tenant_id
    """)
    dead_ids = [row[0] for row in session.exec(subquery.bindparams(tenant_id=api_key.tenant_id)).all()]

    count = 0
    if dead_ids:
        targets = session.exec(select(Target).where(Target.id.in_(dead_ids))).all()
        for target in targets:
            target.is_archived = True
            target.archived_at = datetime.utcnow()
            target.archived_reason = "DNS cleanup: empty records"
            session.add(target)
            count += 1
        session.commit()

    return {"archived_count": count}


@router.post("/targets/{target_id}/restore", dependencies=[Depends(RequireScope("write"))])
async def restore_target(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.is_archived = False
    target.archived_at = None
    target.archived_reason = None
    session.add(target)
    session.commit()

    return {"id": target.id, "domain": target.domain, "is_archived": target.is_archived}


class BulkBlocklistRequest(BaseModel):
    target_ids: List[int]
    confirm: bool


@router.post("/targets/bulk-blocklist", dependencies=[Depends(RequireScope("destructive"))])
async def bulk_blocklist_targets(
    payload: BulkBlocklistRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to blocklist these targets")
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    owned_targets = session.exec(
        select(Target).where(
            Target.id.in_(set(payload.target_ids)),
            Target.tenant_id == api_key.tenant_id,
        )
    ).all()

    existing_patterns = set(session.exec(
        select(DiscoveryDomainBlocklist.pattern).where(
            DiscoveryDomainBlocklist.tenant_id == api_key.tenant_id,
        )
    ).all())

    blocked = 0
    archived = 0
    for target in owned_targets:
        pattern = target.domain.strip().lower()
        if pattern and pattern not in existing_patterns:
            session.add(DiscoveryDomainBlocklist(
                tenant_id=api_key.tenant_id,
                pattern=pattern,
                created_by=None,
                note="Added via /api/v1/targets/bulk-blocklist",
            ))
            existing_patterns.add(pattern)
            blocked += 1
        if not target.is_archived:
            target.is_archived = True
            target.archived_at = datetime.utcnow()
            target.archived_reason = "blocklisted"
            session.add(target)
            archived += 1

    session.commit()

    return {"blocklisted_count": blocked, "archived_count": archived}


@router.get("/targets/{target_id}/changes", dependencies=[Depends(RequireScope("read"))])
async def get_target_changes(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    limit: int = 30,
):
    if limit > 100 or limit < 1:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100")

    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    rows = session.exec(
        select(ChangeEvent, ScanResult.module_name)
        .join(ScanResult, ChangeEvent.scan_result_id == ScanResult.id)
        .where(ScanResult.target_id == target_id)
        .order_by(ChangeEvent.created_at.desc())
        .limit(limit)
    ).all()

    return [
        {
            "id": ce.id,
            "module_name": mod_name,
            "event_type": ce.event_type,
            "description": ce.description,
            "detected_at": ce.created_at.isoformat(),
        }
        for ce, mod_name in rows
    ]


@router.get("/targets/{target_id}/scan-status", dependencies=[Depends(RequireScope("read"))])
async def get_scan_status(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    status_msg = redis_client.get(f"scan:status:{target_id}")
    if status_msg:
        return {"status": status_msg}
    return {"status": target.scan_progress or target.scan_status}


@router.get("/targets/{target_id}/network-context", dependencies=[Depends(RequireScope("read"))])
async def get_network_context(
    target_id: int,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    context = get_network_ctx(target_id)
    return {"network_context": context, "target_domain": target.domain}
