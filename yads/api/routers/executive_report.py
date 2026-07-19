from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from typing import Optional
from datetime import datetime, timedelta
from collections import defaultdict

from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult, SecurityTrend
from yads.api.templating import templates

router = APIRouter(
    prefix="/executive-report",
    tags=["executive-report"],
)


def _get_tenant_targets(session: Session, user: User):
    query = select(Target)
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        query = query.where(Target.tenant_id == None)
    return session.exec(query).all()


def _compute_executive_data(session: Session, user: User) -> dict:
    targets = _get_tenant_targets(session, user)

    total_targets = len(targets)
    archived_targets = sum(1 for t in targets if getattr(t, "is_archived", False))
    active_targets = [t for t in targets if not getattr(t, "is_archived", False)]
    scanned_targets = 0

    # Severity counters
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # For top targets: target_id -> {domain, critical, high, total}
    target_finding_map: dict[int, dict] = {}

    # For top finding types: title -> count
    finding_title_counts: dict[str, int] = defaultdict(int)

    for target in active_targets:
        # Fetch all results for this target, pick latest per module
        all_results = session.exec(
            select(ScanResult)
            .where(ScanResult.target_id == target.id)
            .order_by(ScanResult.scanned_at.desc())
        ).all()

        latest_per_module: dict[str, ScanResult] = {}
        for res in all_results:
            if res.module_name not in latest_per_module:
                latest_per_module[res.module_name] = res

        if latest_per_module:
            scanned_targets += 1

        target_critical = 0
        target_high = 0
        target_total = 0

        for res in latest_per_module.values():
            data = res.data or {}
            findings = data.get("findings", [])
            for finding in findings:
                sev = str(finding.get("severity", "info")).lower()
                if sev not in sev_counts:
                    sev = "info"
                sev_counts[sev] += 1
                target_total += 1

                title = finding.get("title") or finding.get("name") or finding.get("type") or "Unknown Finding"
                finding_title_counts[title] += 1

                if sev == "critical":
                    target_critical += 1
                elif sev == "high":
                    target_high += 1

        target_finding_map[target.id] = {
            "domain": target.domain,
            "critical": target_critical,
            "high": target_high,
            "total": target_total,
        }

    # Security score
    raw_score = (
        100
        - sev_counts["critical"] * 15
        - sev_counts["high"] * 8
        - sev_counts["medium"] * 3
        - sev_counts["low"] * 1
    )
    security_score = max(0, min(100, raw_score))

    # Grade
    if security_score >= 90:
        grade = "A"
    elif security_score >= 75:
        grade = "B"
    elif security_score >= 60:
        grade = "C"
    elif security_score >= 45:
        grade = "D"
    else:
        grade = "F"

    # Top 5 most critical targets
    sorted_targets = sorted(
        target_finding_map.values(),
        key=lambda x: (x["critical"], x["high"], x["total"]),
        reverse=True,
    )
    top_targets = sorted_targets[:5]

    # Top 5 finding types
    top_findings = sorted(finding_title_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_finding_types = [{"title": title, "count": count} for title, count in top_findings]

    # Risk trend from SecurityTrend
    risk_trend = "stable"
    try:
        trend_query = select(SecurityTrend).order_by(SecurityTrend.recorded_at.desc())
        if user.tenant_id:
            trend_query = trend_query.where(SecurityTrend.tenant_id == user.tenant_id)
        trend_records = session.exec(trend_query.limit(10)).all()
        if len(trend_records) >= 2:
            recent_avg = sum(r.score for r in trend_records[:3]) / min(3, len(trend_records))
            older_avg = sum(r.score for r in trend_records[3:]) / max(1, len(trend_records) - 3)
            if recent_avg > older_avg + 5:
                risk_trend = "improving"
            elif recent_avg < older_avg - 5:
                risk_trend = "deteriorating"
    except Exception:
        pass

    # Recommended actions based on findings
    recommended_actions = _build_recommendations(sev_counts, finding_title_counts, top_finding_types)

    # Total findings
    total_findings = sum(sev_counts.values())

    # Risk bar percentages
    risk_bar = {}
    if total_findings > 0:
        risk_bar = {
            "critical": round(sev_counts["critical"] / total_findings * 100),
            "high": round(sev_counts["high"] / total_findings * 100),
            "medium": round(sev_counts["medium"] / total_findings * 100),
            "low": round(sev_counts["low"] / total_findings * 100),
            "info": round(sev_counts["info"] / total_findings * 100),
        }
    else:
        risk_bar = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    return {
        "total_targets": total_targets,
        "scanned_targets": scanned_targets,
        "archived_targets": archived_targets,
        "findings": sev_counts,
        "total_findings": total_findings,
        "security_score": security_score,
        "grade": grade,
        "top_targets": top_targets,
        "top_finding_types": top_finding_types,
        "risk_trend": risk_trend,
        "recommended_actions": recommended_actions,
        "risk_bar": risk_bar,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    }


def _build_recommendations(sev_counts: dict, title_counts: dict, top_findings: list) -> list:
    actions = []
    titles_lower = {t.lower() for t in title_counts.keys()}

    if sev_counts["critical"] > 0:
        actions.append({
            "priority": 1,
            "icon": "fire",
            "title": "Address Critical Vulnerabilities Immediately",
            "description": (
                f"There are {sev_counts['critical']} critical vulnerabilities across your assets. "
                "These pose an immediate risk and should be patched or mitigated within 24 hours."
            ),
        })

    if sev_counts["high"] > 0:
        actions.append({
            "priority": 2,
            "icon": "exclamation",
            "title": "Remediate High-Severity Issues",
            "description": (
                f"{sev_counts['high']} high-severity issues were identified. "
                "Schedule remediation within the next 7 days to reduce exposure."
            ),
        })

    ssl_keywords = {"ssl", "tls", "certificate", "cert"}
    if any(kw in title for title in titles_lower for kw in ssl_keywords):
        actions.append({
            "priority": 3,
            "icon": "lock-closed",
            "title": "Review SSL/TLS Certificates",
            "description": (
                "One or more assets have certificate or encryption issues. "
                "Ensure all certificates are valid, up to date, and use modern TLS versions."
            ),
        })

    header_keywords = {"header", "csp", "hsts", "x-frame", "content-security"}
    if any(kw in title for title in titles_lower for kw in header_keywords):
        actions.append({
            "priority": 3,
            "icon": "shield-check",
            "title": "Harden HTTP Security Headers",
            "description": (
                "Missing or misconfigured HTTP security headers were detected. "
                "Add Content-Security-Policy, Strict-Transport-Security, and X-Frame-Options headers to protect users."
            ),
        })

    port_keywords = {"port", "open port", "exposed service"}
    if any(kw in title for title in titles_lower for kw in port_keywords):
        actions.append({
            "priority": 4,
            "icon": "server",
            "title": "Reduce Exposed Network Services",
            "description": (
                "Unnecessary open ports were found on one or more assets. "
                "Close or firewall any services not required for business operations."
            ),
        })

    if sev_counts["medium"] > 0 and len(actions) < 5:
        actions.append({
            "priority": 4,
            "icon": "clipboard-list",
            "title": "Schedule Medium-Risk Remediation",
            "description": (
                f"{sev_counts['medium']} medium-severity findings require attention. "
                "Include these in your next sprint or security review cycle."
            ),
        })

    if not actions:
        actions.append({
            "priority": 1,
            "icon": "check-circle",
            "title": "Maintain Current Security Posture",
            "description": (
                "No significant vulnerabilities detected. Continue regular scanning and "
                "review your asset inventory to ensure new additions are covered."
            ),
        })

    # Cap at 5 and sort by priority
    actions.sort(key=lambda x: x["priority"])
    return actions[:5]


@router.get("/", response_class=HTMLResponse)
async def executive_report_page(
    request: Request,
    user: User = Depends(get_current_user_html),
):
    return templates.TemplateResponse("executive_report.html", {
        "request": request,
        "user": user,
    })


@router.get("/data")
async def executive_report_data(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    data = _compute_executive_data(session, user)
    return data
