"""
WAF / IDS / IPS Reaction Profiling
====================================
Aggregated view of WAF/CDN detection results across all tenant targets.
Shows protection levels, bypass risks, and provider distribution.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, Target, User

router = APIRouter(prefix="/waf-analysis", tags=["analytics"])


def _severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


@router.get("/", response_class=HTMLResponse)
async def waf_analysis_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    target_id: Optional[int] = Query(default=None),
):
    tenant_id = user.tenant_id

    # Fetch all WAF scan results for the tenant
    stmt = (
        select(ScanResult, Target)
        .join(Target, ScanResult.target_id == Target.id)
        .where(ScanResult.module_name == "waf_detector")
    )
    if tenant_id is not None:
        stmt = stmt.where(Target.tenant_id == tenant_id)

    rows = session.exec(stmt).all()

    # Build per-target summaries
    entries = []
    stats = {
        "total": 0,
        "waf_protected": 0,
        "actively_blocking": 0,
        "no_waf": 0,
        "bypass_risk": 0,
        "providers": {},
    }

    for scan, target in rows:
        if not scan.data:
            continue
        d = scan.data
        stats["total"] += 1

        waf_detected = d.get("waf_detected", False)
        waf_blocking = d.get("waf_blocking", False)
        providers = d.get("providers", [])
        findings = sorted(d.get("findings", []), key=lambda f: _severity_order(f.get("severity", "info")))
        origin_ips = d.get("origin_ips", [])
        direct_access = d.get("direct_access", [])
        score = d.get("summary", {}).get("score", 100)
        protection_level = d.get("summary", {}).get("protection_level", "unknown")

        has_bypass = bool(direct_access)
        worst_severity = findings[0].get("severity", "info") if findings else "info"

        if waf_detected:
            stats["waf_protected"] += 1
        else:
            stats["no_waf"] += 1
        if waf_blocking:
            stats["actively_blocking"] += 1
        if has_bypass:
            stats["bypass_risk"] += 1
        for p in providers:
            stats["providers"][p] = stats["providers"].get(p, 0) + 1

        entries.append({
            "target": target,
            "waf_detected": waf_detected,
            "waf_blocking": waf_blocking,
            "providers": providers,
            "findings": findings,
            "origin_ips": origin_ips,
            "direct_access": direct_access,
            "score": score,
            "protection_level": protection_level,
            "has_bypass": has_bypass,
            "worst_severity": worst_severity,
            "scanned_at": scan.scanned_at,
        })

    # Sort: bypass risks first, then no WAF, then by score ascending
    entries.sort(key=lambda e: (
        0 if e["has_bypass"] else (1 if not e["waf_detected"] else 2),
        -e["score"],
    ))

    # Highlighted target (from target_id param)
    highlighted = None
    if target_id:
        highlighted = next((e for e in entries if e["target"].id == target_id), None)

    provider_list = sorted(stats["providers"].items(), key=lambda x: -x[1])

    return templates.TemplateResponse("waf_analysis.html", {
        "request": request,
        "user": user,
        "entries": entries,
        "stats": stats,
        "provider_list": provider_list,
        "highlighted_id": target_id,
    })
