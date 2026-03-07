"""
Attack Surface Dashboard (#20)

Tenant-wide matrix view: targets × modules with worst-severity colour coding.
Provides CISO-level overview of risk coverage across the entire asset inventory.
"""
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, Target, User

router = APIRouter(prefix="/attack-surface", tags=["analytics"])

# Same modules as security_findings, ordered for display
MODULES = [
    ("email_security",      "Email Sec."),
    ("axfr_scanner",        "AXFR"),
    ("security_txt",        "Sec.txt"),
    ("http_headers",        "Headers"),
    ("cookie_scanner",      "Cookies"),
    ("cors_scanner",        "CORS"),
    ("cert_mismatch",       "Cert"),
    ("shodan_censys",       "Shodan"),
    ("threat_intel",        "Threat"),
    ("subdomain_takeover",  "Takeover"),
    ("git_exposure",        "Git"),
    ("js_secrets",          "JS Sec."),
    ("wayback_scanner",     "Wayback"),
    ("external_resources",  "ExtRes."),
    ("metadata_scanner",    "Meta"),
    ("rpki_scanner",        "RPKI"),
    ("dsgvo_scanner",       "GDPR"),
    ("nuclei_scanner",      "Nuclei"),
    ("ssl_scanner",         "SSL"),
]

MODULE_NAMES = [m for m, _ in MODULES]

SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "clean": 0}
SEV_CSS = {
    "critical": "bg-red-900/70 text-red-200 border-red-800",
    "high":     "bg-orange-900/70 text-orange-200 border-orange-800",
    "medium":   "bg-yellow-900/70 text-yellow-200 border-yellow-800",
    "low":      "bg-blue-900/60 text-blue-200 border-blue-800",
    "info":     "bg-slate-700/60 text-slate-300 border-slate-600",
    "clean":    "bg-green-900/50 text-green-300 border-green-800",
    "none":     "bg-slate-800/40 text-slate-600 border-slate-700",
}


def _worst_severity(findings: List[Dict]) -> str:
    """Return the worst severity across a finding list."""
    best = -1
    worst = "none"
    for f in findings:
        sev = f.get("severity", "info")
        if SEV_ORDER.get(sev, 0) > best:
            best = SEV_ORDER.get(sev, 0)
            worst = sev
    return worst if findings else "none"


def _extract_worst(module: str, data: Optional[Dict]) -> str:
    """Return worst severity for a given module's scan data, or 'none' if not scanned."""
    if data is None:
        return "none"
    findings = data.get("findings", [])
    if not findings:
        # Check summary score — if it's perfect / no issues, mark clean
        score = (data.get("summary") or {}).get("score") or data.get("score")
        if score is not None:
            return "clean" if score >= 90 else "info"
        return "clean"
    worst = _worst_severity(findings)
    return worst if worst != "none" else "clean"


@router.get("/", response_class=HTMLResponse)
async def view_attack_surface(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    # --- Tenant-scoped targets ---
    if user.role == "admin" and user.tenant_id is None:
        targets_stmt = select(Target).where(Target.is_archived == False)
    else:
        targets_stmt = select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.is_archived == False,
        )
    targets = session.exec(targets_stmt.order_by(Target.domain)).all()
    target_map = {t.id: t for t in targets}
    target_ids = list(target_map.keys())

    # --- Latest ScanResult per (target_id, module_name) ---
    cell_data: Dict[Tuple[int, str], str] = {}  # (target_id, module) → worst severity
    module_findings_count: Dict[str, int] = {m: 0 for m in MODULE_NAMES}
    target_finding_count: Dict[int, int] = {tid: 0 for tid in target_ids}

    if target_ids:
        stmt = (
            select(ScanResult)
            .where(
                ScanResult.module_name.in_(MODULE_NAMES),
                ScanResult.target_id.in_(target_ids),
            )
            .order_by(ScanResult.scanned_at.desc())
        )
        latest: Dict[Tuple[int, str], ScanResult] = {}
        for r in session.exec(stmt).all():
            key = (r.target_id, r.module_name)
            if key not in latest:
                latest[key] = r

        for (tid, mod), sr in latest.items():
            worst = _extract_worst(mod, sr.data or {})
            cell_data[(tid, mod)] = worst
            sev_rank = SEV_ORDER.get(worst, 0)
            if sev_rank >= 2:  # low or above counts as a "finding"
                module_findings_count[mod] = module_findings_count.get(mod, 0) + 1
                target_finding_count[tid] = target_finding_count.get(tid, 0) + 1

    # --- Build heatmap rows ---
    rows = []
    for t in targets:
        cells = []
        for mod, _ in MODULES:
            sev = cell_data.get((t.id, mod), "none")
            cells.append({
                "module": mod,
                "severity": sev,
                "css": SEV_CSS.get(sev, SEV_CSS["none"]),
            })
        rows.append({
            "target": t,
            "cells": cells,
            "finding_count": target_finding_count.get(t.id, 0),
        })

    # Sort by finding count desc so riskiest targets come first
    rows.sort(key=lambda r: r["finding_count"], reverse=True)

    # --- Top risky targets (finding count ≥ 1) ---
    top_targets = [r for r in rows if r["finding_count"] > 0][:10]

    # --- KPIs ---
    total_cells = len(target_ids) * len(MODULES)
    scanned_cells = len(cell_data)
    coverage_pct = round(scanned_cells * 100 / total_cells, 1) if total_cells else 0

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev in cell_data.values():
        if sev in sev_counts:
            sev_counts[sev] += 1

    # --- Module risk ranking ---
    module_risk = sorted(
        [{"name": lbl, "module": mod, "count": module_findings_count.get(mod, 0)} for mod, lbl in MODULES],
        key=lambda x: x["count"],
        reverse=True,
    )

    return templates.TemplateResponse("attack_surface.html", {
        "request": request,
        "user": user,
        "targets": targets,
        "modules": MODULES,
        "rows": rows,
        "top_targets": top_targets,
        "module_risk": module_risk,
        "sev_counts": sev_counts,
        "coverage_pct": coverage_pct,
        "scanned_cells": scanned_cells,
        "total_cells": total_cells,
        "SEV_CSS": SEV_CSS,
    })
