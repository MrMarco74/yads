from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from yads.database import get_session
from yads.auth.deps import get_current_user_html
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pqc", tags=["reports"])
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals
from yads.config import settings
templates.env.globals['settings'] = settings

def get_all_tenants():
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()
templates.env.globals['get_available_tenants'] = get_all_tenants


def _get_pqc_fleet_data(session: Session, user: User):
    """
    Fetches all SSL scan results and aggregates PQC readiness data across the fleet.
    Returns a list of per-target stats and overall distribution counts.
    """
    targets_query = select(Target)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    targets = session.exec(targets_query).all()
    if not targets:
        return [], {"active": 0, "capable": 0, "not_ready": 0, "unknown": 0, "total": 0}

    target_ids = tuple(t.id for t in targets)
    target_map = {t.id: t for t in targets}

    # Fetch the latest ssl_scanner result per target
    results = session.exec(
        select(ScanResult).where(
            ScanResult.module_name == "ssl_scanner",
            ScanResult.target_id.in_(target_ids)
        ).order_by(ScanResult.id.desc())
    ).all()

    # Keep only the latest result per target
    latest = {}
    for r in results:
        if r.target_id not in latest:
            latest[r.target_id] = r

    rows = []
    dist = {"active": 0, "capable": 0, "not_ready": 0, "unknown": 0, "total": 0}

    for t_id, res in latest.items():
        if not res.data:
            continue
        target = target_map.get(t_id)
        if not target:
            continue

        data = res.data
        pqc = data.get("pqc_readiness", {}) or {}
        status = pqc.get("status", "Unknown")
        score = pqc.get("score", 0)
        flags = pqc.get("flags", [])
        recs = pqc.get("recommendations", [])
        groups = pqc.get("hybrid_groups_detected", [])
        tls13_count = pqc.get("tls13_ciphers", 0)
        classical_count = pqc.get("classical_only_ciphers", 0)
        scanned_at = res.scanned_at.strftime("%Y-%m-%d") if res.scanned_at else "—"

        rows.append({
            "target_id": t_id,
            "domain": target.domain,
            "status": status,
            "score": score,
            "flags": flags,
            "recommendations": recs,
            "hybrid_groups": groups,
            "tls13_ciphers": tls13_count,
            "classical_ciphers": classical_count,
            "scanned_at": scanned_at,
        })

        dist["total"] += 1
        if status == "PQC Active":
            dist["active"] += 1
        elif status == "PQC Capable":
            dist["capable"] += 1
        elif status in ("Not Ready", "Evaluation Failed"):
            dist["not_ready"] += 1
        else:
            dist["unknown"] += 1

    # Sort by score descending
    rows.sort(key=lambda x: x["score"], reverse=True)

    return rows, dist


@router.get("", response_class=HTMLResponse)
async def pqc_report(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    try:
        rows, dist = _get_pqc_fleet_data(session, user)
    except Exception as e:
        logger.warning(f"PQC fleet data fetch failed: {e}")
        rows, dist = [], {"active": 0, "capable": 0, "not_ready": 0, "unknown": 0, "total": 0}

    return templates.TemplateResponse("pqc_report.html", {
        "request": request,
        "user": user,
        "rows": rows,
        "dist": dist,
    })
