from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import Session, select
from typing import Optional, List
from datetime import datetime, timezone
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult, SecurityFinding, SystemConfig
from yads.utils.export import generate_excel, generate_pdf
from yads.utils.findings import get_finding_hash
from yads.api.utils.date_filter import parse_date_range, get_date_range_display
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cloud-assets", tags=["reports"])
from yads.api.templating import templates

# Inject Globals
from yads.config import settings
templates.env.globals['settings'] = settings

def get_all_tenants():
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()
templates.env.globals['get_available_tenants'] = get_all_tenants


def _confidence_from_name(domain: str, bucket_name: str) -> str:
    """
    Estimate ownership confidence purely from the bucket name vs. the target domain.
    Used as fallback when the scanner did not store a confidence value.
    """
    parts = domain.split(".")
    base = parts[0] if parts[0] != "www" or len(parts) == 1 else parts[1]
    safe = domain.replace(".", "-")
    bn = bucket_name.lower()
    if bn == base or bn == safe:
        return "high"
    if bn.startswith(base + "-") or bn.endswith("-" + base):
        return "medium"
    if bn.startswith(safe + "-") or bn.endswith("-" + safe):
        return "medium"
    return "low"


def _get_cloud_data(session: Session, user: User, for_export: bool = False, date_from: datetime = None, date_to: datetime = None, status_filter=None):
    from yads.utils.findings import FindingStatusFilter
    if not status_filter:
        status_filter = FindingStatusFilter(session, user.tenant_id if user.tenant_id else None)

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
            bucket_name = asset.get("bucket_name")
            
            # Filter triaged findings
            if status_filter.is_ignored(target.domain, "cloud_scanner", bucket_name):
                continue
            
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
                "bucket_name": bucket_name,
                "url": asset.get("url"),
                "status": asset.get("status"),
                "detected_at": res.scanned_at,
                "confidence": asset.get("confidence"),        # from scanner, may be None
                "content_match": asset.get("content_match", False),
            })
            
    # Sort by Status (Public first)
    items.sort(key=lambda x: "public" not in x["status"].lower())

    # Enrich with confidence + triage status (skip for exports to keep it fast)
    if items and not for_export:
        hashes = [get_finding_hash(i["domain"], "cloud_scanner", i["bucket_name"]) for i in items]
        sfs = session.exec(select(SecurityFinding).where(SecurityFinding.finding_hash.in_(hashes))).all()
        sf_map = {sf.finding_hash: sf for sf in sfs}
        for item in items:
            fhash = get_finding_hash(item["domain"], "cloud_scanner", item["bucket_name"])
            item["finding_hash"] = fhash
            sf = sf_map.get(fhash)
            item["triage_status"] = sf.status if sf else "open"
            item["yf_id"] = sf.yf_id if sf else None
            # Use stored confidence from scanner if available, else derive from name
            stored_conf = item.get("confidence")
            item["confidence"] = stored_conf if stored_conf in ("high", "medium", "low") \
                else _confidence_from_name(item["domain"], item["bucket_name"])
    elif items:
        for item in items:
            item["finding_hash"] = get_finding_hash(item["domain"], "cloud_scanner", item["bucket_name"])
            item["triage_status"] = "open"
            item["yf_id"] = None
            item["confidence"] = _confidence_from_name(item["domain"], item["bucket_name"])

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

    triage_stats = {
        "unreviewed": sum(1 for i in items if i.get("triage_status") == "open"),
        "confirmed": sum(1 for i in items if i.get("triage_status") == "acknowledged"),
        "high_confidence": sum(1 for i in items if i.get("confidence") == "high"),
    }

    return templates.TemplateResponse("cloud_assets.html", {
        "request": request,
        "user": user,
        "items": items,
        "stats": stats,
        "triage_stats": triage_stats,
        "date_range_display": date_range_display
    })

@router.post("/triage")
async def triage_cloud_assets(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
):
    """Triage one or many cloud asset findings: confirm (ours), false_positive, or reset to open."""
    body = await request.json()
    action = body.get("action")
    items: List[dict] = body.get("items", [])

    STATUS_MAP = {"confirm": "acknowledged", "false_positive": "false_positive", "open": "open"}
    if action not in STATUS_MAP or not items:
        return JSONResponse({"error": "Invalid request"}, status_code=400)

    new_status = STATUS_MAP[action]
    tenant_id = user.tenant_id
    now = datetime.now(timezone.utc)

    hashes = [get_finding_hash(i["domain"], "cloud_scanner", i["bucket_name"]) for i in items]
    hash_to_item = {get_finding_hash(i["domain"], "cloud_scanner", i["bucket_name"]): i for i in items}

    existing = session.exec(select(SecurityFinding).where(SecurityFinding.finding_hash.in_(hashes))).all()
    existing_map = {sf.finding_hash: sf for sf in existing}

    counter_cfg = session.get(SystemConfig, "finding_yf_counter")
    counter = int(counter_cfg.value) if counter_cfg and counter_cfg.value else 0
    counter_changed = False

    results = []
    for fhash in hashes:
        item = hash_to_item[fhash]
        if fhash in existing_map:
            sf = existing_map[fhash]
            sf.status = new_status
            sf.last_seen = now
            sf.closing_date = now if new_status in ("false_positive", "fixed") else None
            session.add(sf)
        else:
            counter += 1
            counter_changed = True
            sf = SecurityFinding(
                yf_id=f"YF-{counter:06d}",
                finding_hash=fhash,
                tenant_id=tenant_id,
                target_id=item.get("target_id"),
                domain=item["domain"],
                module="cloud_scanner",
                issue=item["bucket_name"],
                severity="info",
                first_found=now,
                last_seen=now,
                status=new_status,
                closing_date=now if new_status in ("false_positive", "fixed") else None,
            )
            session.add(sf)
            existing_map[fhash] = sf
        results.append({"finding_hash": fhash, "yf_id": sf.yf_id, "status": new_status})

    if counter_changed:
        if counter_cfg:
            counter_cfg.value = str(counter)
            session.add(counter_cfg)
        else:
            session.add(SystemConfig(key="finding_yf_counter", value=str(counter)))

    try:
        session.commit()
    except Exception as e:
        logger.error(f"Cloud triage commit failed: {e}")
        session.rollback()
        return JSONResponse({"error": "Database error"}, status_code=500)

    return JSONResponse({"updated": len(results), "items": results})


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
