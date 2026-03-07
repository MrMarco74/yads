"""
Generic Module Report Views  (/reports/module/{module_name})

Provides a rich per-module report page for every scanner module that does not
have a dedicated view.  Includes:
  - KPI cards (targets scanned, finding counts by severity)
  - Per-target data table with key fields extracted per module
  - Trend chart data (findings over time)
  - PDF / Excel export
  - Forwards AI context for the AI assistant
"""
from __future__ import annotations

import io
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.core.module_registry import REGISTRY, get_module
from yads.database import get_session
from yads.models import ScanResult, Target, User

router = APIRouter(prefix="/reports/module", tags=["module-reports"])

# ---------------------------------------------------------------------------
# Template selection per module  (falls back to generic)
# ---------------------------------------------------------------------------
_SPECIALIZED: Dict[str, str] = {
    "subdomain_scanner":     "module_report_dns.html",
    "dns_scanner":           "module_report_dns.html",
    "axfr_scanner":          "module_report_dns.html",
    "web_analyzer":          "module_report_web.html",
    "nuclei_scanner":        "module_report_nuclei.html",
    "threat_intel":          "module_report_threat.html",
    "shodan_censys":         "module_report_threat.html",
    "deception_detector":    "module_report_deception.html",
    "infrastructure_scanner":"module_report_infra.html",
    "port_scanner":          "module_report_ports_generic.html",
    "nmap_scanner":          "module_report_ports_generic.html",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tenant_target_ids(session: Session, user: User) -> List[int]:
    q = select(Target.id)
    if user.tenant_id:
        q = q.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        q = q.where(Target.tenant_id == None)
    return [r for r in session.exec(q)]


def _latest_results(session: Session, target_ids: List[int], module_name: str) -> Dict[int, ScanResult]:
    """Latest ScanResult per target for given module."""
    if not target_ids:
        return {}
    rows = session.exec(
        select(ScanResult)
        .where(ScanResult.module_name == module_name)
        .where(ScanResult.target_id.in_(target_ids))
        .order_by(ScanResult.scanned_at.desc())
    ).all()
    latest: Dict[int, ScanResult] = {}
    for r in rows:
        if r.target_id not in latest:
            latest[r.target_id] = r
    return latest


def _extract_kpi_row(module_name: str, data: Dict) -> Dict:
    """Extract a flat KPI dict from a module's data payload."""
    row: Dict[str, Any] = {}

    if module_name in ("subdomain_scanner", "dns_scanner"):
        subs = data.get("subdomains") or data.get("records", {})
        row["subdomains"] = len(subs) if isinstance(subs, list) else 0
        row["dangling"] = len(data.get("dangling_cnames") or [])
        row["takeover_risks"] = len(data.get("takeover_risks") or [])

    elif module_name == "axfr_scanner":
        row["vulnerable"] = data.get("vulnerable", False)
        row["nameservers"] = len(data.get("nameservers_checked") or [])

    elif module_name == "web_analyzer":
        stack = data.get("tech_stack") or []
        row["tech_count"] = len(stack)
        row["cves"] = len(data.get("cves") or [])
        row["broken_links"] = len(data.get("broken_links") or [])
        row["emails"] = len(data.get("emails") or [])

    elif module_name == "nuclei_scanner":
        findings = data.get("findings") or []
        sev = Counter(f.get("severity", "info") for f in findings)
        row.update({"critical": sev["critical"], "high": sev["high"],
                    "medium": sev["medium"], "low": sev["low"], "total": len(findings)})

    elif module_name == "threat_intel":
        summary = data.get("summary") or {}
        row["score"] = summary.get("score", 0)
        row["sources"] = summary.get("sources_checked", 0)
        row["flagged"] = summary.get("flagged_by", 0)

    elif module_name == "shodan_censys":
        summary = data.get("summary") or {}
        row["open_ports"] = summary.get("open_ports", 0)
        row["score"] = summary.get("score", 0)

    elif module_name == "deception_detector":
        row["honeypots"] = len(data.get("honeypots") or [])
        row["sinkholes"] = len(data.get("sinkholes") or [])
        row["tarpits"] = len(data.get("tarpits") or [])

    elif module_name == "infrastructure_scanner":
        row["cloud_provider"] = data.get("cloud_provider") or "—"
        row["ip"] = data.get("ip") or "—"
        geo = data.get("geoip") or {}
        row["country"] = geo.get("country_name") or "—"

    elif module_name in ("port_scanner", "nmap_scanner"):
        ports = data.get("open_ports") or []
        row["open_ports"] = len(ports)

    else:
        # Generic: score + finding count
        findings = data.get("findings") or []
        row["findings"] = len(findings)
        score = data.get("score") or (data.get("summary") or {}).get("score")
        if score is not None:
            row["score"] = score

    return row


def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    counts["total"] = sum(counts.values())
    return counts


def _build_report_data(
    module_name: str,
    target_ids: List[int],
    session: Session,
    user: User,
) -> Dict:
    """Build the full context dict for the report template."""
    # Load all targets for name lookup
    targets = {t.id: t for t in session.exec(
        select(Target).where(Target.id.in_(target_ids))
    ).all()}

    latest = _latest_results(session, target_ids, module_name)

    rows = []
    total_findings = 0
    sev_agg = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    last_scan: Optional[datetime] = None

    # Import extractor from security_findings to reuse
    from yads.api.routers.security_findings import _extract_findings

    for tid in target_ids:
        result = latest.get(tid)
        target = targets.get(tid)
        if not target:
            continue

        kpi = {}
        findings: List[Dict] = []
        scanned_at = None

        if result and result.data:
            kpi = _extract_kpi_row(module_name, result.data)
            findings = _extract_findings(module_name, result.data)
            scanned_at = result.scanned_at
            if last_scan is None or (scanned_at and scanned_at > last_scan):
                last_scan = scanned_at

        sev = _severity_counts(findings)
        total_findings += sev["total"]
        for k in ("critical", "high", "medium", "low", "info"):
            sev_agg[k] += sev[k]

        rows.append({
            "target": target,
            "result": result,
            "scanned_at": scanned_at,
            "kpi": kpi,
            "findings": findings,
            "sev": sev,
            "data": result.data if result else {},
        })

    rows.sort(key=lambda r: (
        -(r["sev"]["critical"] * 1000 + r["sev"]["high"] * 100 + r["sev"]["medium"] * 10 + r["sev"]["low"]),
        r["target"].domain,
    ))

    sev_agg["total"] = total_findings
    module_def = get_module(module_name)

    return {
        "module_name": module_name,
        "module_def": module_def,
        "rows": rows,
        "summary": sev_agg,
        "targets_scanned": len([r for r in rows if r["result"]]),
        "targets_total": len(target_ids),
        "last_scan": last_scan,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/{module_name}", response_class=HTMLResponse)
async def module_report_view(
    module_name: str,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    module_def = get_module(module_name)
    if not module_def:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found")

    # Redirect to dedicated page if one exists
    if module_def.report_view and module_def.report_view != f"/reports/module/{module_name}":
        from fastapi.responses import RedirectResponse
        return RedirectResponse(module_def.report_view, status_code=302)

    target_ids = _tenant_target_ids(session, user)
    ctx = _build_report_data(module_name, target_ids, session, user)

    template_name = _SPECIALIZED.get(module_name, "module_report_generic.html")

    return templates.TemplateResponse(template_name, {
        "request": request,
        "user": user,
        **ctx,
    })


@router.get("/{module_name}/export/excel")
async def module_report_excel(
    module_name: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    from yads.utils.export import generate_excel

    module_def = get_module(module_name)
    if not module_def:
        raise HTTPException(status_code=404, detail="Module not found")

    target_ids = _tenant_target_ids(session, user)
    ctx = _build_report_data(module_name, target_ids, session, user)

    export_rows = []
    for r in ctx["rows"]:
        if not r["result"]:
            continue
        export_rows.append({
            "Domain": r["target"].domain,
            "Scanned At": r["scanned_at"].strftime("%Y-%m-%d %H:%M") if r["scanned_at"] else "",
            "Critical": r["sev"]["critical"],
            "High": r["sev"]["high"],
            "Medium": r["sev"]["medium"],
            "Low": r["sev"]["low"],
            "Findings Total": r["sev"]["total"],
        })

    return generate_excel(export_rows, f"{module_name}_report")


@router.get("/{module_name}/export/pdf")
async def module_report_pdf(
    module_name: str,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    from yads.utils.export import generate_pdf

    module_def = get_module(module_name)
    if not module_def:
        raise HTTPException(status_code=404, detail="Module not found")

    target_ids = _tenant_target_ids(session, user)
    ctx = _build_report_data(module_name, target_ids, session, user)

    rows = []
    for r in ctx["rows"]:
        if not r["result"]:
            continue
        rows.append({
            "Domain": r["target"].domain,
            "Scanned At": r["scanned_at"].strftime("%Y-%m-%d %H:%M") if r["scanned_at"] else "",
            "Critical": r["sev"]["critical"],
            "High": r["sev"]["high"],
            "Medium": r["sev"]["medium"],
            "Low": r["sev"]["low"],
            "Total": r["sev"]["total"],
        })

    label = module_def.label if module_def else module_name
    return generate_pdf(rows, f"{label} Report", f"{module_name}_report")
