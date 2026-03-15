import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Form, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select, func, text

from yads.database import get_session
from yads.models import Target, User
from yads.api.templating import templates
from yads.auth.deps import get_current_user_html, RoleChecker

logger = logging.getLogger(__name__)
router = APIRouter()

def get_unique_tags(session: Session, tenant_id: Optional[int] = None) -> List[str]:
    """Helper to fetch all unique tags from all targets."""
    try:
        if tenant_id:
            query = text(
                "SELECT DISTINCT jsonb_array_elements_text(tags) FROM target "
                "WHERE tenant_id = :tid ORDER BY 1"
            )
            results = session.exec(query, params={"tid": tenant_id}).all()
        else:
            query = text("SELECT DISTINCT jsonb_array_elements_text(tags) FROM target ORDER BY 1")
            results = session.exec(query).all()
        return [r[0] for r in results]
    except Exception as e:
        logger.debug(f"Failed to get unique tags: {e}")
        return []


# ─── HTML UI ────────────────────────────────────────────────────────────────

@router.get("/tags", response_class=HTMLResponse)
async def tags_page(
    request: Request,
    tag: Optional[str] = None,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """Asset tag management page."""
    # Targets scoped by tenant
    q = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        q = q.where(Target.tenant_id == user.tenant_id)
    all_targets = session.exec(q.order_by(Target.domain)).all()

    # Tags filtered by tenant
    all_tags = get_unique_tags(session, user.tenant_id)

    # Filter targets by selected tag
    if tag:
        filtered_targets = [t for t in all_targets if tag in (t.tags or [])]
    else:
        filtered_targets = all_targets

    # Stats
    untagged_count = sum(1 for t in all_targets if not t.tags)

    # Tag usage counts
    tag_counts: dict = {}
    for t in all_targets:
        for tg in (t.tags or []):
            tag_counts[tg] = tag_counts.get(tg, 0) + 1
    top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return templates.TemplateResponse("tags.html", {
        "request": request,
        "user": user,
        "all_tags": all_tags,
        "filtered_targets": filtered_targets,
        "selected_tag": tag,
        "untagged_count": untagged_count,
        "top_tags": top_tags,
        "tag_counts": tag_counts,
        "total_targets": len(all_targets),
    })


# ─── JSON API ────────────────────────────────────────────────────────────────

@router.get("/api/tags")
async def list_tags(session: Session = Depends(get_session)):
    return get_unique_tags(session)


@router.post("/api/tags/bulk-assign")
async def bulk_assign_tags(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """Assign/remove/replace tags on multiple targets at once.

    Body JSON: {target_ids: [int], tags: [str], action: "add"|"remove"|"replace"}
    """
    body = await request.json()
    target_ids: List[int] = body.get("target_ids", [])
    tags: List[str] = body.get("tags", [])
    action: str = body.get("action", "add")

    if not target_ids:
        raise HTTPException(status_code=400, detail="No target_ids provided")
    if action not in ("add", "remove", "replace"):
        raise HTTPException(status_code=400, detail="action must be add, remove, or replace")

    q = select(Target).where(Target.id.in_(target_ids))
    if user.tenant_id:
        q = q.where(Target.tenant_id == user.tenant_id)
    targets = session.exec(q).all()

    updated = 0
    for target in targets:
        current = list(target.tags or [])
        if action == "add":
            for tg in tags:
                if tg not in current:
                    current.append(tg)
        elif action == "remove":
            current = [tg for tg in current if tg not in tags]
        elif action == "replace":
            current = list(tags)
        target.tags = current
        session.add(target)
        updated += 1

    session.commit()
    return {"updated": updated, "action": action}


@router.post("/api/targets/{target_id}/tags")
async def set_target_tags(
    target_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """Set (replace) tags for a single target.

    Body JSON: {tags: [str]}
    """
    body = await request.json()
    tags: List[str] = body.get("tags", [])

    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if user.tenant_id and target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    target.tags = [str(t).strip() for t in tags if str(t).strip()]
    session.add(target)
    session.commit()
    return {"target_id": target_id, "tags": target.tags}


@router.delete("/api/tags/{tag_name}")
async def delete_tag_globally(
    tag_name: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """Remove a tag from all targets in the tenant."""
    q = select(Target).where(Target.tags.contains([tag_name]))
    if user.tenant_id:
        q = q.where(Target.tenant_id == user.tenant_id)
    targets = session.exec(q).all()

    removed_from = 0
    for target in targets:
        new_tags = [tg for tg in (target.tags or []) if tg != tag_name]
        if len(new_tags) != len(target.tags or []):
            target.tags = new_tags
            session.add(target)
            removed_from += 1

    session.commit()
    return {"tag": tag_name, "removed_from": removed_from}


# ─── Legacy form routes (kept for backwards compat) ──────────────────────────

@router.post("/targets/{target_id}/tags")
async def add_tag(target_id: int, tag: str = Body(..., embed=True), session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if tag not in target.tags:
        new_tags = list(target.tags)
        new_tags.append(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags


@router.delete("/targets/{target_id}/tags/{tag}")
async def remove_tag(target_id: int, tag: str, session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if tag in target.tags:
        new_tags = list(target.tags)
        new_tags.remove(tag)
        target.tags = new_tags
        session.add(target)
        session.commit()
    return target.tags


@router.get("/api/search")
async def search_targets(q: str, session: Session = Depends(get_session)):
    """
    Global search across domains and JSON scan results.
    """
    if not q or len(q) < 2:
        return {"targets": [], "findings": []}

    query_str = f"%{q}%"

    # 1. Search Domains
    t_query = select(Target).where(Target.domain.ilike(query_str)).limit(10)
    targets = session.exec(t_query).all()

    # 2. Search Scan Results (Deep Search) - PostgreSQL JSONB -> Text
    sr_query = text("""
        SELECT sr.id, sr.module_name, sr.data, t.id, t.domain
        FROM scanresult sr
        JOIN target t ON sr.target_id = t.id
        WHERE sr.data::text ILIKE :q
        LIMIT 20
    """)

    findings_raw = session.exec(sr_query, params={"q": query_str}).all()

    findings = []
    for row in findings_raw:
        findings.append({
            "module": row[1],
            "target": row[4],
            "target_id": row[3],
            "snippet": "Match found in data"
        })

    return {
        "targets": [{"id": t.id, "domain": t.domain} for t in targets],
        "findings": findings
    }


@router.get("/search", response_class=HTMLResponse)
async def view_search(request: Request, q: str = ""):
    return templates.TemplateResponse("search.html", {"request": request, "q": q})


@router.post("/targets/bulk/tag", response_class=RedirectResponse)
async def bulk_add_tag(
    target_ids: List[int] = Form(default=[]),
    tag: str = Form(..., max_length=100),
    session: Session = Depends(get_session)
):
    if not target_ids:
        return RedirectResponse(url="/targets/table?msg=No+targets+selected", status_code=303)

    targets = session.exec(select(Target).where(Target.id.in_(target_ids))).all()
    count = 0
    for target in targets:
        curr_tags = target.tags or []
        if tag not in curr_tags:
            new_tags = list(curr_tags)
            new_tags.append(tag)
            target.tags = new_tags
            session.add(target)
            count += 1

    session.commit()
    return RedirectResponse(url=f"/targets/table?msg=Added tag '{tag}' to {count} targets", status_code=303)
