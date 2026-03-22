"""
Addon Module Reports

Dedicated report views for optional scanner add-on modules:
  - /leak-monitor     — Leak Monitor (HIBP breach results)
  - /tech-stack       — Tech Stack Analyzer (fingerprinting + EOL)
  - /whois-history    — WHOIS History Scanner (domain registration data)
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from typing import Optional
from datetime import datetime

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import User, Target, ScanResult

router = APIRouter(tags=["addon-reports"])


def _tenant_target_ids(session: Session, user: User):
    q = select(Target)
    if user.tenant_id:
        q = q.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        q = q.where(Target.tenant_id == None)
    targets = session.exec(q).all()
    return {t.id: t for t in targets}


# ---------------------------------------------------------------------------
# Leak Monitor
# ---------------------------------------------------------------------------
@router.get("/leak-monitor", response_class=HTMLResponse)
async def leak_monitor_report(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    target_map = _tenant_target_ids(session, user)
    if not target_map:
        return templates.TemplateResponse("leak_monitor_report.html", {
            "request": request, "user": user,
            "entries": [], "stats": {"total_leaks": 0, "targets_affected": 0, "emails_checked": 0},
        })

    results = session.exec(
        select(ScanResult).where(
            ScanResult.module_name == "leak_monitor",
            ScanResult.target_id.in_(tuple(target_map.keys())),
        ).order_by(ScanResult.scanned_at.desc())
    ).all()

    entries = []
    stats = {"total_leaks": 0, "targets_affected": set(), "emails_checked": 0}

    for r in results:
        data = r.data or {}
        target = target_map.get(r.target_id)
        leaks = data.get("leaks_found", [])
        emails = data.get("emails_checked", [])
        if not leaks and not emails:
            continue
        stats["emails_checked"] += len(emails)
        stats["total_leaks"] += len(leaks)
        if leaks:
            stats["targets_affected"].add(r.target_id)
        entries.append({
            "target": target,
            "scanned_at": r.scanned_at,
            "leaks": leaks,
            "emails_checked": emails,
            "status": data.get("status", "ok"),
        })

    stats["targets_affected"] = len(stats["targets_affected"])

    return templates.TemplateResponse("leak_monitor_report.html", {
        "request": request, "user": user,
        "entries": entries, "stats": stats,
    })


# ---------------------------------------------------------------------------
# Tech Stack Analyzer
# ---------------------------------------------------------------------------
@router.get("/tech-stack", response_class=HTMLResponse)
async def tech_stack_report(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    target_map = _tenant_target_ids(session, user)
    if not target_map:
        return templates.TemplateResponse("tech_stack_report.html", {
            "request": request, "user": user,
            "entries": [], "stats": {"targets_scanned": 0, "total_techs": 0, "findings": 0},
        })

    results = session.exec(
        select(ScanResult).where(
            ScanResult.module_name == "tech_stack_analyzer",
            ScanResult.target_id.in_(tuple(target_map.keys())),
        ).order_by(ScanResult.scanned_at.desc())
    ).all()

    # Latest result per target
    seen = set()
    entries = []
    stats = {"targets_scanned": 0, "total_techs": 0, "findings": 0}

    for r in results:
        if r.target_id in seen:
            continue
        seen.add(r.target_id)
        data = r.data or {}
        techs = data.get("technologies", [])
        findings = data.get("findings", [])
        target = target_map.get(r.target_id)
        stats["targets_scanned"] += 1
        stats["total_techs"] += len(techs)
        stats["findings"] += len(findings)
        entries.append({
            "target": target,
            "scanned_at": r.scanned_at,
            "technologies": techs,
            "findings": findings,
            "score": data.get("summary", {}).get("score", 100),
        })

    entries.sort(key=lambda e: len(e["findings"]), reverse=True)

    return templates.TemplateResponse("tech_stack_report.html", {
        "request": request, "user": user,
        "entries": entries, "stats": stats,
    })


# ---------------------------------------------------------------------------
# WHOIS History Scanner
# ---------------------------------------------------------------------------
@router.get("/whois-history", response_class=HTMLResponse)
async def whois_history_report(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    target_map = _tenant_target_ids(session, user)
    if not target_map:
        return templates.TemplateResponse("whois_history_report.html", {
            "request": request, "user": user,
            "entries": [], "stats": {"targets_scanned": 0, "expiring_soon": 0, "findings": 0},
        })

    results = session.exec(
        select(ScanResult).where(
            ScanResult.module_name == "whois_history_scanner",
            ScanResult.target_id.in_(tuple(target_map.keys())),
        ).order_by(ScanResult.scanned_at.desc())
    ).all()

    seen = set()
    entries = []
    stats = {"targets_scanned": 0, "expiring_soon": 0, "findings": 0}

    for r in results:
        if r.target_id in seen:
            continue
        seen.add(r.target_id)
        data = r.data or {}
        whois = data.get("whois_data", {})
        findings = data.get("findings", [])
        target = target_map.get(r.target_id)

        # Parse expiry
        exp_raw = whois.get("expiration_date")
        if isinstance(exp_raw, list):
            exp_raw = exp_raw[0]
        expiry_date = None
        days_left = None
        try:
            if exp_raw:
                expiry_date = datetime.fromisoformat(str(exp_raw).replace("Z", ""))
                days_left = (expiry_date - datetime.utcnow()).days
                if days_left < 60:
                    stats["expiring_soon"] += 1
        except Exception:
            pass

        stats["targets_scanned"] += 1
        stats["findings"] += len(findings)
        entries.append({
            "target": target,
            "scanned_at": r.scanned_at,
            "whois": whois,
            "findings": findings,
            "expiry_date": expiry_date,
            "days_left": days_left,
            "score": data.get("summary", {}).get("score", 100),
        })

    entries.sort(key=lambda e: (e["days_left"] or 9999))

    return templates.TemplateResponse("whois_history_report.html", {
        "request": request, "user": user,
        "entries": entries, "stats": stats,
    })
