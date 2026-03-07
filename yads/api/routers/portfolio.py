"""
Multi-Domain Portfolio View
============================
Platform-admin view aggregating all tenants and their domains with security stats.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import Session, select, func

from yads.api.templating import templates
from yads.auth.deps import PlatformAdminChecker
from yads.database import get_session
from yads.models import ScanResult, Target, Tenant, User
from yads.core.scoring import calculate_target_score, get_grade

router = APIRouter(tags=["portfolio"])
ui_router = APIRouter(tags=["portfolio"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FINDING_MODULES = [
    "email_security",
    "axfr_scanner",
    "security_txt",
    "http_headers",
    "cookie_security",
    "cors_scanner",
    "csp_scanner",
    "threat_intel",
]


def _extract_finding_counts(module: str, data: Dict) -> Tuple[int, int, int]:
    """
    Returns (total, critical, high) finding counts for a single scan result.
    Uses same logic as security_findings router for consistency.
    """
    total = critical = high = 0
    if not data:
        return total, critical, high

    # Nuclei / CVE data embedded in various modules
    findings: List[Dict] = []

    if module == "email_security":
        findings = data.get("findings", [])
    elif module == "axfr_scanner":
        if data.get("vulnerable"):
            findings = [{"severity": "critical"}]
    elif module in ("security_txt", "http_headers", "cookie_security",
                    "cors_scanner", "csp_scanner", "threat_intel"):
        findings = data.get("findings", [])
    else:
        # Generic extractor
        findings = data.get("findings", [])

    for f in findings:
        sev = f.get("severity", "info")
        total += 1
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1

    return total, critical, high


def _get_latest_results_for_targets(
    session: Session, target_ids: List[int]
) -> Dict[Tuple[int, str], ScanResult]:
    """Fetch the latest ScanResult per (target_id, module_name)."""
    if not target_ids:
        return {}
    stmt = (
        select(ScanResult)
        .where(ScanResult.target_id.in_(target_ids))
        .order_by(ScanResult.scanned_at.desc())
    )
    latest: Dict[Tuple[int, str], ScanResult] = {}
    for r in session.exec(stmt).all():
        key = (r.target_id, r.module_name)
        if key not in latest:
            latest[key] = r
    return latest


def _compute_tenant_stats(
    tenant: Tenant,
    session: Session,
) -> Dict[str, Any]:
    """
    Compute aggregate security statistics for one tenant.
    """
    # All targets (including archived) for total count
    all_targets = session.exec(
        select(Target).where(Target.tenant_id == tenant.id)
    ).all()

    active_targets = [t for t in all_targets if not t.is_archived]
    active_ids = [t.id for t in active_targets]

    total_findings = 0
    critical_findings = 0
    high_findings = 0
    last_scan_at: Optional[datetime] = None

    # Per-domain finding counts for top_domains ranking
    domain_finding_counts: Dict[str, int] = {}

    if active_ids:
        latest_map = _get_latest_results_for_targets(session, active_ids)

        # Build target id -> domain lookup
        id_to_domain = {t.id: t.domain for t in active_targets}

        for (tid, module), result in latest_map.items():
            # Track last scan timestamp
            if last_scan_at is None or result.scanned_at > last_scan_at:
                last_scan_at = result.scanned_at

            # Count findings
            if result.data:
                t_total, t_crit, t_high = _extract_finding_counts(module, result.data)
                total_findings += t_total
                critical_findings += t_crit
                high_findings += t_high

                domain = id_to_domain.get(tid, "")
                if domain:
                    domain_finding_counts[domain] = (
                        domain_finding_counts.get(domain, 0) + t_total
                    )

        # Compute aggregate security score
        # Score each active target independently, then average
        scores = []
        for target in active_targets:
            target_results = {
                module: latest_map[(target.id, module)]
                for module in [
                    "ssl_scanner", "port_scanner", "web_analyzer"
                ]
                if (target.id, module) in latest_map
            }
            if target_results:
                score, _grade, _factors = calculate_target_score(target, target_results)
                scores.append(score)

        security_score = round(sum(scores) / len(scores)) if scores else None
    else:
        security_score = None

    # Top 3 domains by finding count
    top_domains = sorted(
        domain_finding_counts.items(), key=lambda x: x[1], reverse=True
    )[:3]
    top_domains_list = [
        {"domain": d, "findings": c} for d, c in top_domains
    ]

    # Determine plan label from osint_enabled / quota
    if tenant.osint_enabled and tenant.osint_quota_max > 0:
        plan = "Enterprise"
    elif tenant.osint_enabled:
        plan = "Pro"
    else:
        plan = "Standard"

    return {
        "tenant_id": tenant.id,
        "tenant_name": tenant.name,
        "plan": plan,
        "total_targets": len(all_targets),
        "active_targets": len(active_targets),
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "security_score": security_score,
        "security_grade": get_grade(security_score) if security_score is not None else None,
        "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
        "top_domains": top_domains_list,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@ui_router.get("/portfolio", response_class=HTMLResponse)
async def portfolio_page(
    request: Request,
    user: User = Depends(PlatformAdminChecker()),
):
    return templates.TemplateResponse(
        "portfolio.html",
        {"request": request, "user": user},
    )


@router.get("/api/portfolio/stats")
async def portfolio_stats(
    session: Session = Depends(get_session),
    user: User = Depends(PlatformAdminChecker()),
):
    tenants = session.exec(select(Tenant).order_by(Tenant.name)).all()

    tenant_stats = []
    global_totals = {
        "total_tenants": len(tenants),
        "total_targets": 0,
        "active_targets": 0,
        "total_findings": 0,
        "critical_findings": 0,
        "high_findings": 0,
    }

    for tenant in tenants:
        stats = _compute_tenant_stats(tenant, session)
        tenant_stats.append(stats)

        global_totals["total_targets"] += stats["total_targets"]
        global_totals["active_targets"] += stats["active_targets"]
        global_totals["total_findings"] += stats["total_findings"]
        global_totals["critical_findings"] += stats["critical_findings"]
        global_totals["high_findings"] += stats["high_findings"]

    return JSONResponse(
        content={
            "tenants": tenant_stats,
            "totals": global_totals,
        }
    )
