from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from typing import Optional
from datetime import datetime
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from yads.utils.export import generate_excel, generate_pdf
from yads.api.utils.date_filter import parse_date_range, get_date_range_display

router = APIRouter(prefix="/cloud-assets", tags=["reports"])
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

def _get_cloud_data(session: Session, user: User, for_export: bool = False, date_from: datetime = None, date_to: datetime = None):
    # 1. Fetch relevant targets
    targets_query = select(Target)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    targets = session.exec(targets_query).all()
    target_ids = tuple(t.id for t in targets)
    target_map = {t.id: t for t in targets}

    if not targets:
        return [], {"total_assets": 0, "public_acc": 0, "protected_acc": 0}

    # 2. Fetch Cloud Scanner Results
    statement = select(ScanResult).where(
        ScanResult.module_name == "cloud_scanner",
        ScanResult.target_id.in_(target_ids)
    )

    # Apply date filtering
    if date_from:
        statement = statement.where(ScanResult.scanned_at >= date_from)
    if date_to:
        statement = statement.where(ScanResult.scanned_at <= date_to)

    statement = statement.order_by(ScanResult.scanned_at.desc())

    results = session.exec(statement).all()
    
    # Dedup: Keep latest per target
    # Wait, usually multiple assets per target. We need latest RESULT (which contains list of assets)
    latest_results = {}
    for r in results:
        if r.target_id not in latest_results:
            latest_results[r.target_id] = r
            
    items = []
    stats = {
        "total_assets": 0,
        "public_acc": 0,
        "protected_acc": 0
    }
    
    for t_id, res in latest_results.items():
        if not res.data: continue
        target = target_map.get(t_id)
        
        assets = res.data.get("assets", [])
        for asset in assets:
            # {provider, bucket_name, url, status, status_code}
            
            # Formatting status for stats
            status_lower = asset.get("status", "").lower()
            if "public" in status_lower:
                stats["public_acc"] += 1
            elif "protected" in status_lower:
                stats["protected_acc"] += 1
                
            stats["total_assets"] += 1
            
            items.append({
                "target_id": t_id,
                "domain": target.domain,
                "provider": asset.get("provider"),
                "bucket_name": asset.get("bucket_name"),
                "url": asset.get("url"),
                "status": asset.get("status"),
                "detected_at": res.scanned_at
            })
            
    # Sort by Status (Public first)
    items.sort(key=lambda x: "public" not in x["status"].lower())
    
    return items, stats

@router.get("/", response_class=HTMLResponse)
async def cloud_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    items, stats = _get_cloud_data(session, user, date_from=from_dt, date_to=to_dt)
    return templates.TemplateResponse("cloud_assets.html", {
        "request": request,
        "user": user,
        "items": items,
        "stats": stats,
        "date_range_display": date_range_display
    })

@router.get("/export/excel")
async def export_cloud_excel(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    items, _ = _get_cloud_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for i in items:
        export_data.append({
            "Domain": i["domain"],
            "Provider": i["provider"],
            "Bucket Name": i["bucket_name"],
            "Status": i["status"],
            "URL": i["url"]
        })
    return generate_excel(export_data, "cloud_assets_report")

@router.get("/export/pdf")
async def export_cloud_pdf(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    items, _ = _get_cloud_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for i in items:
        export_data.append({
            "Domain": i["domain"],
            "Provider": i["provider"],
            "Bucket": i["bucket_name"],
            "Status": i["status"]
        })
    return generate_pdf(export_data, "Cloud Asset Exposure", "cloud_assets_report")
