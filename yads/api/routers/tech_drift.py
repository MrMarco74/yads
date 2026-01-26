from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from typing import Optional
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from datetime import datetime
from yads.utils.export import generate_excel, generate_pdf
from yads.api.utils.date_filter import parse_date_range, get_date_range_display

router = APIRouter(prefix="/tech-drift", tags=["reports"])
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

def _get_tech_drift_data(session: Session, user: User, for_export: bool = False, date_from: datetime = None, date_to: datetime = None):
    # 1. Fetch relevant targets
    targets_query = select(Target)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    targets = session.exec(targets_query).all()
    target_map = {t.id: t for t in targets}
    target_ids = tuple(t.id for t in targets)

    if not targets:
        return {}, {"added_count": 0, "removed_count": 0, "total_events": 0}

    # 2. Fetch Historical WebAnalyzer Results
    statement = select(ScanResult).where(
        ScanResult.module_name == "web_analyzer",
        ScanResult.target_id.in_(target_ids)
    )

    # Apply date filtering
    if date_from:
        statement = statement.where(ScanResult.scanned_at >= date_from)
    if date_to:
        statement = statement.where(ScanResult.scanned_at <= date_to)

    statement = statement.order_by(ScanResult.scanned_at.asc())

    results = session.exec(statement).all()
    
    # Group by Target
    history = {}
    for r in results:
        if r.target_id not in history: history[r.target_id] = []
        history[r.target_id].append(r)
        
    # 3. Calculate Drift
    events = []
    
    for t_id, scans in history.items():
        if len(scans) < 2: continue 
        
        target = target_map.get(t_id)
        
        for i in range(1, len(scans)):
            prev = scans[i-1]
            curr = scans[i]
            
            prev_tech = set(prev.data.get("tech_stack", []))
            curr_tech = set(curr.data.get("tech_stack", []))
            
            # Added
            added = curr_tech - prev_tech
            for tech in added:
                events.append({
                    "type": "ADDED",
                    "tech": tech,
                    "target_id": t_id,
                    "domain": target.domain,
                    "timestamp": curr.scanned_at,
                    "scanner": "Web Analyzer"
                })
                
            # Removed
            removed = prev_tech - curr_tech
            for tech in removed:
                events.append({
                    "type": "REMOVED",
                    "tech": tech,
                    "target_id": t_id,
                    "domain": target.domain,
                    "timestamp": curr.scanned_at,
                    "scanner": "Web Analyzer"
                })

    # 4. Sort Events (Newest First)
    events.sort(key=lambda x: x['timestamp'], reverse=True)
    
    stats = {"added_count": 0, "removed_count": 0, "total_events": len(events)}
    
    # 5. Group by Day for Timeline (or just return list for export)
    if for_export:
        for e in events:
            e['time'] = e['timestamp'].strftime("%Y-%m-%d %H:%M")
        return events, stats
        
    timeline = {}
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    for e in events:
        day_str = e['timestamp'].strftime("%Y-%m-%d")
        if day_str == today_str: day_display = "Today"
        else: day_display = e['timestamp'].strftime("%B %d, %Y")
        
        if day_display not in timeline: timeline[day_display] = []
        
        e['time'] = e['timestamp'].strftime("%H:%M")
        timeline[day_display].append(e)
        
        if e['type'] == "ADDED": stats["added_count"] += 1
        else: stats["removed_count"] += 1
        
    return timeline, stats

@router.get("/", response_class=HTMLResponse)
async def tech_drift_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    timeline, stats = _get_tech_drift_data(session, user, date_from=from_dt, date_to=to_dt)
    return templates.TemplateResponse("tech_drift.html", {
        "request": request,
        "user": user,
        "timeline": timeline,
        "stats": stats,
        "date_range_display": date_range_display
    })

@router.get("/export/excel")
async def export_drift_excel(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    events, _ = _get_tech_drift_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for e in events:
        export_data.append({
            "Timestamp": e["time"],
            "Domain": e["domain"],
            "Change": e["type"],
            "Technology": e["tech"]
        })
    return generate_excel(export_data, "technology_drift_report")

@router.get("/export/pdf")
async def export_drift_pdf(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    events, _ = _get_tech_drift_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for e in events:
        export_data.append({
            "Time": e["time"],
            "Domain": e["domain"],
            "Type": e["type"],
            "Tech": e["tech"]
        })
    return generate_pdf(export_data, "Technology Drift Report", "technology_drift_report")
