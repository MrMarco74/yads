from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select

from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from yads.utils.export import generate_excel, generate_pdf

router = APIRouter(prefix="/dormant-domains", tags=["reports"])
from yads.api.templating import templates


def _get_dormant_domains_data(session: Session, user: User, for_export: bool = False):
    """
    Reads persisted dormant_detector results (does not recompute signals --
    that's the scan module's job, this just reports what it already found).
    Returns (dormant_items, not_yet_analyzed_items, stats).
    """
    targets_query = select(Target)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    targets = session.exec(targets_query).all()
    target_ids = tuple(t.id for t in targets)
    target_map = {t.id: t for t in targets}

    if not targets:
        return [], [], {"dormant_count": 0, "not_yet_analyzed_count": 0, "total_targets": 0}

    statement = select(ScanResult).where(
        ScanResult.module_name.in_(["dormant_detector", "whois_history_scanner"]),
        ScanResult.target_id.in_(target_ids),
    ).order_by(ScanResult.scanned_at.desc())

    results = session.exec(statement).all()

    latest = {}
    for r in results:
        key = (r.target_id, r.module_name)
        if key not in latest:
            latest[key] = r

    dormant_items = []
    not_yet_analyzed_items = []

    for t_id, target in target_map.items():
        dormant_res = latest.get((t_id, "dormant_detector"))
        if not dormant_res or not dormant_res.data:
            not_yet_analyzed_items.append({"target_id": t_id, "domain": target.domain})
            continue

        data = dormant_res.data
        if not data.get("is_dormant"):
            continue

        whois_res = latest.get((t_id, "whois_history_scanner"))
        whois_data = (whois_res.data.get("whois_data") if (whois_res and whois_res.data) else None) or {}

        triggered_signals = [name for name, sig in data.get("signals", {}).items() if sig.get("triggered")]

        dormant_items.append({
            "target_id": t_id,
            "domain": target.domain,
            "score": data.get("dormancy_score", 0),
            "signals": triggered_signals,
            "last_activity_at": data.get("last_activity_at"),
            "whois_creation_date": whois_data.get("creation_date"),
            "whois_expiration_date": whois_data.get("expiration_date"),
            "detected_at": dormant_res.scanned_at,
        })

    dormant_items.sort(key=lambda x: x["score"], reverse=True)
    not_yet_analyzed_items.sort(key=lambda x: x["domain"])

    stats = {
        "dormant_count": len(dormant_items),
        "not_yet_analyzed_count": len(not_yet_analyzed_items),
        "total_targets": len(targets),
    }
    return dormant_items, not_yet_analyzed_items, stats


@router.get("/", response_class=HTMLResponse)
async def dormant_domains_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    dormant_items, not_yet_analyzed_items, stats = _get_dormant_domains_data(session, user)
    return templates.TemplateResponse("dormant_domains.html", {
        "request": request,
        "user": user,
        "items": dormant_items,
        "not_yet_analyzed": not_yet_analyzed_items,
        "stats": stats,
    })


@router.get("/export/excel")
async def export_dormant_domains_excel(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    items, _, _ = _get_dormant_domains_data(session, user, for_export=True)
    export_data = []
    for i in items:
        export_data.append({
            "Domain": i["domain"],
            "Dormancy Score": f"{i['score']}/13",
            "Triggered Signals": ", ".join(i["signals"]),
            "Last Activity": i["last_activity_at"] or "",
            "WHOIS Created": i["whois_creation_date"] or "",
            "WHOIS Expires": i["whois_expiration_date"] or "",
        })
    return generate_excel(export_data, "dormant_domains_report")


@router.get("/export/pdf")
async def export_dormant_domains_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    items, _, _ = _get_dormant_domains_data(session, user, for_export=True)
    export_data = []
    for i in items:
        export_data.append({
            "Domain": i["domain"],
            "Score": f"{i['score']}/13",
            "Signals": ", ".join(i["signals"]),
            "Last Activity": i["last_activity_at"] or "",
        })
    return generate_pdf(export_data, "Dormant Domains", "dormant_domains_report")
