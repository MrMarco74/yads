"""
Discovery Sessions — Recursive domain discovery with relevance scoring.

GET  /discovery                     → session list page
POST /discovery/sessions            → create + start session
GET  /discovery/{session_id}        → session detail + live stats
POST /discovery/sessions/{id}/stop  → stop session
GET  /api/discovery/sessions        → JSON list
GET  /api/discovery/sessions/{id}   → JSON detail
GET  /api/discovery/sessions/{id}/candidates → JSON candidates (filter by status)
POST /api/discovery/sessions/{id}/candidates/{cid}/accept → manual accept
POST /api/discovery/sessions/{id}/candidates/{cid}/reject → manual reject
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlmodel import Session, select, func

from yads.api.templating import templates
from yads.auth.deps import RoleChecker, get_current_user_html
from yads.database import get_session
from yads.models import DiscoverySession, DiscoveryCandidate, DiscoveryDomainBlocklist, Target, User

logger = logging.getLogger(__name__)

router = APIRouter()
scanner_only = RoleChecker(["admin", "tenant_admin", "scanner"])
manager_only = RoleChecker(["admin", "tenant_admin"])


# ── HTML Pages ──────────────────────────────────────────────────────────────

@router.get("/discovery", response_class=HTMLResponse)
async def discovery_list(
    request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    stmt = select(DiscoverySession)
    if current_user.tenant_id is not None:
        stmt = stmt.where(DiscoverySession.tenant_id == current_user.tenant_id)
    stmt = stmt.order_by(DiscoverySession.created_at.desc())
    sessions = session.exec(stmt).all()
    return templates.TemplateResponse("discovery_sessions.html", {
        "request": request,
        "sessions": sessions,
        "user": current_user,
        "current_user": current_user,
    })


@router.get("/discovery/{session_id}", response_class=HTMLResponse)
async def discovery_detail(
    session_id: int,
    request: Request,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    disc_sess = db.get(DiscoverySession, session_id)
    if not disc_sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if current_user.tenant_id is not None and disc_sess.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    candidates = db.exec(
        select(DiscoveryCandidate)
        .where(DiscoveryCandidate.session_id == session_id)
        .order_by(DiscoveryCandidate.relevance_score.desc())
    ).all()

    blocklist = db.exec(
        select(DiscoveryDomainBlocklist)
        .where(DiscoveryDomainBlocklist.tenant_id == current_user.tenant_id)
        .order_by(DiscoveryDomainBlocklist.created_at.desc())
    ).all()

    return templates.TemplateResponse("discovery_detail.html", {
        "request": request,
        "disc_sess": disc_sess,
        "candidates": candidates,
        "blocklist": blocklist,
        "user": current_user,
        "current_user": current_user,
    })


# ── Actions ──────────────────────────────────────────────────────────────────

@router.post("/discovery/sessions", dependencies=[Depends(scanner_only)])
async def create_session(
    request: Request,
    name: str = Form(...),
    seed_domains_raw: str = Form(...),
    max_depth: int = Form(3),
    relevance_threshold: float = Form(0.7),
    max_targets: int = Form(500),
    include_typosquats: bool = Form(False),
    allowed_tld_filter_raw: str = Form(""),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    seeds = [d.strip().lower() for d in seed_domains_raw.splitlines() if d.strip()]
    if not seeds:
        raise HTTPException(status_code=400, detail="At least one seed domain required")

    tld_filter = [t.strip().lower() for t in allowed_tld_filter_raw.split(",") if t.strip()]

    disc_sess = DiscoverySession(
        tenant_id=current_user.tenant_id,
        created_by=current_user.id,
        name=name,
        seed_domains=seeds,
        max_depth=max_depth,
        relevance_threshold=relevance_threshold,
        max_targets=max_targets,
        include_typosquats=include_typosquats,
        allowed_tld_filter=tld_filter,
        status="pending",
    )
    db.add(disc_sess)
    db.commit()
    db.refresh(disc_sess)

    # Start orchestration asynchronously via Celery
    from yads.worker_core import celery_app
    celery_app.send_task(
        "yads.worker.start_discovery_session",
        args=[disc_sess.id],
        queue="discovery",
    )

    return RedirectResponse(url=f"/discovery/{disc_sess.id}", status_code=303)


@router.post("/discovery/sessions/{session_id}/stop", dependencies=[Depends(manager_only)])
async def stop_session(
    session_id: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    disc_sess = db.get(DiscoverySession, session_id)
    if not disc_sess:
        raise HTTPException(status_code=404, detail="Not found")
    if current_user.tenant_id is not None and disc_sess.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=403)
    disc_sess.status = "stopped"
    from datetime import datetime
    disc_sess.finished_at = datetime.utcnow()
    db.add(disc_sess)
    db.commit()
    return JSONResponse({"status": "stopped"})


# ── JSON API ──────────────────────────────────────────────────────────────────

@router.get("/api/discovery/sessions")
async def api_list_sessions(
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    stmt = select(DiscoverySession)
    if current_user.tenant_id is not None:
        stmt = stmt.where(DiscoverySession.tenant_id == current_user.tenant_id)
    sessions = db.exec(stmt.order_by(DiscoverySession.created_at.desc())).all()
    return [
        {
            "id": s.id, "name": s.name, "status": s.status,
            "total_accepted": s.total_accepted, "total_rejected": s.total_rejected,
            "total_discovered": s.total_discovered, "current_depth": s.current_depth,
            "max_depth": s.max_depth, "created_at": s.created_at,
            "started_at": s.started_at, "finished_at": s.finished_at,
        }
        for s in sessions
    ]


@router.get("/api/discovery/sessions/{session_id}")
async def api_session_detail(
    session_id: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    sess = db.get(DiscoverySession, session_id)
    if not sess:
        raise HTTPException(status_code=404)
    if current_user.tenant_id is not None and sess.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=403)
    return {
        "id": sess.id, "name": sess.name, "status": sess.status,
        "seed_domains": sess.seed_domains, "max_depth": sess.max_depth,
        "relevance_threshold": sess.relevance_threshold, "max_targets": sess.max_targets,
        "total_accepted": sess.total_accepted, "total_rejected": sess.total_rejected,
        "total_discovered": sess.total_discovered, "current_depth": sess.current_depth,
        "created_at": sess.created_at, "started_at": sess.started_at, "finished_at": sess.finished_at,
    }


@router.get("/api/discovery/sessions/{session_id}/candidates")
async def api_candidates(
    session_id: int,
    status: Optional[str] = Query(None),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    sess = db.get(DiscoverySession, session_id)
    if not sess:
        raise HTTPException(status_code=404)
    if current_user.tenant_id is not None and sess.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=403)
    stmt = select(DiscoveryCandidate).where(DiscoveryCandidate.session_id == session_id)
    if status:
        stmt = stmt.where(DiscoveryCandidate.status == status)
    stmt = stmt.order_by(DiscoveryCandidate.relevance_score.desc())
    candidates = db.exec(stmt).all()
    return [
        {
            "id": c.id, "domain": c.domain, "status": c.status,
            "relevance_score": c.relevance_score, "matching_signals": c.matching_signals,
            "source_scanner": c.source_scanner, "depth": c.depth,
            "rejection_reason": c.rejection_reason, "created_at": c.created_at,
        }
        for c in candidates
    ]


@router.post("/api/discovery/sessions/{session_id}/candidates/{cid}/accept",
             dependencies=[Depends(manager_only)])
async def api_accept_candidate(
    session_id: int,
    cid: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    cand = db.get(DiscoveryCandidate, cid)
    if not cand or cand.session_id != session_id:
        raise HTTPException(status_code=404)
    sess = db.get(DiscoverySession, session_id)
    if not sess:
        raise HTTPException(status_code=404)

    existing = db.exec(select(Target).where(Target.domain == cand.domain)).first()
    if not existing:
        t = Target(
            domain=cand.domain,
            tenant_id=sess.tenant_id,
            discovery_session_id=session_id,
            parent_target_id=cand.source_target_id,
            discovery_depth=cand.depth + 1,
            relevance_score=cand.relevance_score,
            discovery_signals=cand.matching_signals,
            discovery_reason=f"Manually accepted from discovery session {session_id}",
        )
        db.add(t)
        sess.total_accepted += 1

    cand.status = "accepted"
    db.add(cand)
    db.add(sess)
    db.commit()
    return {"status": "accepted"}


@router.post("/api/discovery/sessions/{session_id}/candidates/{cid}/reject",
             dependencies=[Depends(manager_only)])
async def api_reject_candidate(
    session_id: int,
    cid: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    cand = db.get(DiscoveryCandidate, cid)
    if not cand or cand.session_id != session_id:
        raise HTTPException(status_code=404)
    sess = db.get(DiscoverySession, session_id)
    if sess:
        sess.total_rejected += 1
        db.add(sess)
    cand.status = "rejected"
    cand.rejection_reason = "manual"
    db.add(cand)
    _archive_discovery_target(db, cand.domain, session_id)
    db.commit()
    return {"status": "rejected"}


@router.post("/api/discovery/sessions/{session_id}/candidates/{cid}/block-domain",
             dependencies=[Depends(manager_only)])
async def api_block_domain(
    session_id: int,
    cid: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    """
    Block *.parent of this candidate's domain tenant-wide.
    Also immediately rejects all matching candidates in this session.
    """
    cand = db.get(DiscoveryCandidate, cid)
    if not cand or cand.session_id != session_id:
        raise HTTPException(status_code=404)

    # Build pattern: strip first label → *.parent
    parts = cand.domain.split(".")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Cannot block a TLD-level domain")
    parent = ".".join(parts[1:])
    pattern = f"*.{parent}"

    # Idempotent: skip if already blocked for this tenant
    existing = db.exec(
        select(DiscoveryDomainBlocklist).where(
            DiscoveryDomainBlocklist.tenant_id == current_user.tenant_id,
            DiscoveryDomainBlocklist.pattern == pattern,
        )
    ).first()
    if not existing:
        entry = DiscoveryDomainBlocklist(
            tenant_id=current_user.tenant_id,
            pattern=pattern,
            created_by=current_user.id,
        )
        db.add(entry)

    # Reject all matching candidates in this session immediately
    all_cands = db.exec(
        select(DiscoveryCandidate).where(
            DiscoveryCandidate.session_id == session_id,
            DiscoveryCandidate.status.in_(["pending", "accepted"]),
        )
    ).all()
    rejected_count = 0
    for c in all_cands:
        if _domain_matches_pattern(c.domain, pattern):
            c.status = "rejected"
            c.rejection_reason = f"domain_blocked:{pattern}"
            db.add(c)
            _archive_discovery_target(db, c.domain, session_id)
            rejected_count += 1

    db.commit()
    return {"status": "blocked", "pattern": pattern, "rejected_candidates": rejected_count}


@router.get("/api/discovery/blocklist", dependencies=[Depends(manager_only)])
async def api_list_blocklist(
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    entries = db.exec(
        select(DiscoveryDomainBlocklist)
        .where(DiscoveryDomainBlocklist.tenant_id == current_user.tenant_id)
        .order_by(DiscoveryDomainBlocklist.created_at.desc())
    ).all()
    return [{"id": e.id, "pattern": e.pattern, "created_at": e.created_at} for e in entries]


@router.delete("/api/discovery/blocklist/{entry_id}", dependencies=[Depends(manager_only)])
async def api_delete_blocklist_entry(
    entry_id: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user_html),
):
    entry = db.get(DiscoveryDomainBlocklist, entry_id)
    if not entry or entry.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404)
    db.delete(entry)
    db.commit()
    return {"status": "deleted"}


def _archive_discovery_target(db: Session, domain: str, session_id: int) -> None:
    """Archive the Target for a rejected discovery candidate so queued scans are skipped."""
    target = db.exec(
        select(Target).where(
            Target.domain == domain,
            Target.discovery_session_id == session_id,
        )
    ).first()
    if target and not target.is_archived:
        target.is_archived = True
        target.archived_reason = "discovery_rejected"
        db.add(target)


def _domain_matches_pattern(domain: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        parent = pattern[2:]
        return domain == parent or domain.endswith("." + parent)
    return domain == pattern
