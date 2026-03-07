"""
Security Findings Overview (ASM Aggregation)
=============================================
Aggregates findings from all Phase 1 scanners across all tenant targets.
Provides a unified view of SPF/DKIM/DMARC, AXFR, CORS, headers, cookies, etc.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, Target, User

router = APIRouter(prefix="/security-findings", tags=["analytics"])

# Modules included in this aggregated view
FINDING_MODULES = [
    "email_security",
    "axfr_scanner",
    "security_txt",
    "http_headers",
    "cookie_scanner",
    "cors_scanner",
    "cert_mismatch",
    "shodan_censys",
    "threat_intel",
    "subdomain_takeover",
    "git_exposure",
    "js_secrets",
    "wayback_scanner",
    "external_resources",
    "metadata_scanner",
]


def _get_tenant_targets(session: Session, user: User) -> Dict[int, Target]:
    q = select(Target).where(Target.is_archived == False)
    if user.tenant_id:
        q = q.where(Target.tenant_id == user.tenant_id)
    targets = session.exec(q).all()
    return {t.id: t for t in targets}


def _fetch_latest_results(session: Session, target_ids: Tuple[int, ...]) -> Dict[Tuple[int, str], ScanResult]:
    if not target_ids:
        return {}
    stmt = select(ScanResult).where(
        ScanResult.module_name.in_(FINDING_MODULES),
        ScanResult.target_id.in_(target_ids),
    ).order_by(ScanResult.scanned_at.desc())
    latest: Dict[Tuple[int, str], ScanResult] = {}
    for r in session.exec(stmt).all():
        key = (r.target_id, r.module_name)
        if key not in latest:
            latest[key] = r
    return latest


def _extract_findings(module: str, data: Dict) -> List[Dict]:
    """Normalize findings from any module into a standard list."""
    findings = []
    if not data:
        return findings

    if module == "email_security":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "info"),
                "issue": f"[{f.get('section','')}] {f.get('issue','')}",
                "score": data.get("score"),
            })

    elif module == "axfr_scanner":
        if data.get("vulnerable"):
            f = data.get("finding") or {}
            findings.append({
                "severity": "critical",
                "issue": f.get("issue", "Zone transfer succeeded"),
                "score": 0,
            })

    elif module == "security_txt":
        for issue in data.get("issues", []):
            findings.append({
                "severity": "low" if data.get("found") else "medium",
                "issue": issue,
                "score": data.get("score"),
            })

    elif module == "http_headers":
        for f in data.get("findings", []):
            if f.get("severity") != "info":
                findings.append({
                    "severity": f.get("severity", "low"),
                    "issue": f"{f.get('header','')}: {f.get('issue','')}",
                    "score": data.get("score"),
                })

    elif module == "cookie_scanner":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "low"),
                "issue": f"[{f.get('cookie','')}] {f.get('issue','')}",
                "score": data.get("score"),
            })

    elif module == "cors_scanner":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("issue", ""),
                "score": data.get("score"),
            })

    elif module == "cert_mismatch":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("issue", ""),
                "score": None,
            })

    elif module == "shodan_censys":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "threat_intel":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "subdomain_takeover":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "high"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "git_exposure":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "high"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "js_secrets":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "high"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "wayback_scanner":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "external_resources":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    elif module == "metadata_scanner":
        for f in data.get("findings", []):
            findings.append({
                "severity": f.get("severity", "medium"),
                "issue": f.get("title", ""),
                "score": data.get("summary", {}).get("score"),
            })

    return findings


def _build_summary(target_findings: List[Dict]) -> Dict:
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for entry in target_findings:
        for f in entry["findings"]:
            sev = f.get("severity", "info")
            stats[sev] = stats.get(sev, 0) + 1
    stats["total"] = sum(stats.values())
    stats["targets_with_findings"] = sum(1 for e in target_findings if e["findings"])
    return stats


@router.get("/", response_class=HTMLResponse)
async def security_findings_overview(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    module_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
):
    target_map = _get_tenant_targets(session, user)
    if not target_map:
        return templates.TemplateResponse("security_findings.html", {
            "request": request,
            "user": user,
            "target_findings": [],
            "summary": {"total": 0, "targets_with_findings": 0},
            "module_filter": module_filter,
            "severity_filter": severity_filter,
            "finding_modules": FINDING_MODULES,
        })

    target_ids = tuple(target_map.keys())
    latest = _fetch_latest_results(session, target_ids)

    target_findings = []
    for tid, target in sorted(target_map.items(), key=lambda x: x[1].domain):
        all_findings = []
        modules_scanned = []

        for module in FINDING_MODULES:
            if module_filter and module != module_filter:
                continue
            result = latest.get((tid, module))
            if result and result.data:
                findings = _extract_findings(module, result.data)
                if severity_filter:
                    findings = [f for f in findings if f["severity"] == severity_filter]
                if findings:
                    all_findings.extend([{**f, "module": module} for f in findings])
                modules_scanned.append({
                    "module": module,
                    "scanned_at": result.scanned_at,
                    "finding_count": len(findings),
                })

        if all_findings or not (module_filter or severity_filter):
            # Sort findings by severity weight
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 99))
            target_findings.append({
                "target": target,
                "findings": all_findings,
                "modules_scanned": modules_scanned,
                "highest_severity": all_findings[0]["severity"] if all_findings else None,
            })

    # Sort: targets with critical/high findings first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 99}
    target_findings.sort(key=lambda x: sev_order.get(x["highest_severity"], 99))

    summary = _build_summary(target_findings)

    return templates.TemplateResponse("security_findings.html", {
        "request": request,
        "user": user,
        "target_findings": target_findings,
        "summary": summary,
        "module_filter": module_filter,
        "severity_filter": severity_filter,
        "finding_modules": FINDING_MODULES,
    })
