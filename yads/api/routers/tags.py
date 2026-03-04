import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Form, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select, func, text

from yads.database import get_session
from yads.models import Target
from yads.api.templating import templates

logger = logging.getLogger(__name__)
router = APIRouter()

def get_unique_tags(session: Session) -> List[str]:
    """Helper to fetch all unique tags from all targets."""
    # This is a bit brute force for JSONB lists in pure SQLModel without proper func.unnest support easily accessible
    # Raw SQL is best here
    try:
        query = text("SELECT DISTINCT jsonb_array_elements_text(tags) FROM target ORDER BY 1")
        results = session.exec(query).all()
        # We need r[0] because session.exec(text) returns Row objects
        return [r[0] for r in results]
    except Exception as e:
        logger.debug(f"Failed to get unique tags: {e}")
        return []

@router.get("/api/tags")
async def list_tags(session: Session = Depends(get_session)):
    return get_unique_tags(session)

@router.post("/targets/{target_id}/tags")
async def add_tag(target_id: int, tag: str = Body(..., embed=True), session: Session = Depends(get_session)):
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    if tag not in target.tags:
        # Create new list to ensure change tracking
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
    # We select the scan result and the associated target domain
    # Casting JSONB to Text allows simple "contains" text search
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
        # row: (id, module_name, data, target_id, domain)
        findings.append({
            "module": row[1],
            "target": row[4],
            "target_id": row[3],
            "snippet": "Match found in data" # MVP: Highlighting is complex in JSON
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
    tag: str = Form(...),
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
