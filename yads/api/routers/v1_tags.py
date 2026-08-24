"""API-key-authenticated tagging surface for yads-mcp and other machine
clients. Tenant-scoped throughout -- a deliberate tightening versus the
cookie-session tags.py routes for add_tag/remove_tag/list_tags, which
currently have no tenant check at all (see
docs/superpowers/specs/2026-08-24-yads-mcp-foundation-design.md section 6).
"""

from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from yads.api.routers.tags import get_unique_tags
from yads.auth.deps import RequireScope, require_tenant_scoped_key
from yads.database import get_session
from yads.models import APIKey, Target

router = APIRouter(prefix="/api/v1", tags=["API v1 — Tags"])


@router.get("/tags", dependencies=[Depends(RequireScope("read"))])
async def list_tags(
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    return get_unique_tags(session, tenant_id=api_key.tenant_id)


class AddTagRequest(BaseModel):
    tag: str


@router.post("/targets/{target_id}/tags", dependencies=[Depends(RequireScope("write"))])
async def add_tag(
    target_id: int,
    payload: AddTagRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.tag not in (target.tags or []):
        new_tags = list(target.tags or [])
        new_tags.append(payload.tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags


@router.delete("/targets/{target_id}/tags/{tag}", dependencies=[Depends(RequireScope("write"))])
async def remove_tag(
    target_id: int,
    tag: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == api_key.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if tag in (target.tags or []):
        new_tags = [t for t in target.tags if t != tag]
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags


class BulkAssignRequest(BaseModel):
    target_ids: List[int]
    tags: List[str]
    action: str = "add"


@router.post("/tags/bulk-assign", dependencies=[Depends(RequireScope("write"))])
async def bulk_assign_tags(
    payload: BulkAssignRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")
    if payload.action not in ("add", "remove", "replace"):
        raise HTTPException(status_code=400, detail="action must be add, remove, or replace")

    targets = session.exec(
        select(Target).where(Target.id.in_(payload.target_ids), Target.tenant_id == api_key.tenant_id)
    ).all()

    updated = 0
    for target in targets:
        current = list(target.tags or [])
        if payload.action == "add":
            for tg in payload.tags:
                if tg not in current:
                    current.append(tg)
        elif payload.action == "remove":
            current = [tg for tg in current if tg not in payload.tags]
        else:
            current = list(payload.tags)
        target.tags = current
        session.add(target)
        updated += 1

    session.commit()
    return {"updated": updated, "action": payload.action}


class BulkAddByIdsRequest(BaseModel):
    target_ids: List[int]
    tag: str


@router.post("/targets/bulk/tag", dependencies=[Depends(RequireScope("write"))])
async def bulk_add_tag(
    payload: BulkAddByIdsRequest,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
):
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")

    targets = session.exec(
        select(Target).where(Target.id.in_(payload.target_ids), Target.tenant_id == api_key.tenant_id)
    ).all()

    updated = 0
    for target in targets:
        curr_tags = target.tags or []
        if payload.tag not in curr_tags:
            new_tags = list(curr_tags)
            new_tags.append(payload.tag)
            target.tags = new_tags
            session.add(target)
            updated += 1

    session.commit()
    return {"updated": updated, "tag": payload.tag}


@router.delete("/tags/{tag_name}", dependencies=[Depends(RequireScope("destructive"))])
async def delete_tag_globally(
    tag_name: str,
    session: Annotated[Session, Depends(get_session)],
    api_key: Annotated[APIKey, Depends(require_tenant_scoped_key)],
    confirm: bool = False,
):
    if not confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to delete this tag globally")

    targets = session.exec(
        select(Target).where(Target.tags.contains([tag_name]), Target.tenant_id == api_key.tenant_id)
    ).all()

    removed_from = 0
    for target in targets:
        new_tags = [tg for tg in (target.tags or []) if tg != tag_name]
        if len(new_tags) != len(target.tags or []):
            target.tags = new_tags
            session.add(target)
            removed_from += 1

    session.commit()
    return {"tag": tag_name, "removed_from": removed_from}
