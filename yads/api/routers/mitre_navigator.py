"""
ATT&CK Navigator heatmap (#52).

Builds on #51 (real MITRE mapping wired into SecurityFinding). Renders a
grid in the style of the official MITRE ATT&CK Navigator: tactics as
columns, techniques as cells, colored by hit count/severity for the current
tenant. Read-only aggregation over SecurityFinding — no new scanning.
"""
from collections import defaultdict
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.database import get_session
from yads.auth.deps import get_current_user_html
from yads.models import SecurityFinding, User
from yads.api.templating import templates
from yads.core.mitre_mapping import TACTIC_NAMES

router = APIRouter(prefix="/mitre-navigator", tags=["analytics"])

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@router.get("/", response_class=HTMLResponse)
async def view_mitre_navigator(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    query = select(SecurityFinding).where(SecurityFinding.mitre_tactic_id != None)  # noqa: E711
    if user.tenant_id:
        query = query.where(SecurityFinding.tenant_id == user.tenant_id)
    elif user.role != "admin":
        query = query.where(SecurityFinding.tenant_id == None)  # noqa: E711

    findings = session.exec(query).all()

    # {tactic_id: {technique_id: {"name": str, "count": int, "max_severity_weight": int, "domains": set}}}
    grid: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(lambda: defaultdict(
        lambda: {"name": "", "count": 0, "max_severity_weight": 0, "domains": set()}
    ))

    for f in findings:
        if not f.mitre_tactic_id or not f.mitre_technique_id:
            continue
        cell = grid[f.mitre_tactic_id][f.mitre_technique_id]
        cell["name"] = f.mitre_technique_name or f.mitre_technique_id
        cell["count"] += 1
        cell["max_severity_weight"] = max(cell["max_severity_weight"], _SEVERITY_WEIGHT.get(f.severity, 0))
        cell["domains"].add(f.domain)

    # Only render tactic columns that actually have hits, in kill-chain order.
    tactic_order = list(TACTIC_NAMES.keys())
    tactics = []
    for tid, techs in sorted(grid.items(), key=lambda kv: tactic_order.index(kv[0]) if kv[0] in tactic_order else 99):
        tactics.append({
            "id": tid,
            "name": TACTIC_NAMES.get(tid, tid),
            "techniques": [
                {
                    "id": tech_id,
                    "name": cell["name"],
                    "count": cell["count"],
                    "max_severity_weight": cell["max_severity_weight"],
                    "domains": sorted(cell["domains"]),
                }
                for tech_id, cell in sorted(techs.items(), key=lambda kv: -kv[1]["max_severity_weight"])
            ],
        })

    return templates.TemplateResponse("mitre_navigator.html", {
        "request": request,
        "user": user,
        "tactics": tactics,
        "total_mapped_findings": len(findings),
    })
