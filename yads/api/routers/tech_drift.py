from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from datetime import datetime
from yads.utils.export import generate_excel, generate_pdf

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

def _get_tech_drift_data(session: Session, user: User, for_export: bool = False):
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
    ).order_by(ScanResult.scanned_at.asc())
    
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
async def tech_drift_dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    timeline, stats = _get_tech_drift_data(session, user)
    return templates.TemplateResponse("tech_drift.html", {
        "request": request, 
        "user": user, 
        "timeline": timeline,
        "stats": stats
    })

@router.get("/export/excel")
async def export_drift_excel(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    events, _ = _get_tech_drift_data(session, user, for_export=True)
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
async def export_drift_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    events, _ = _get_tech_drift_data(session, user, for_export=True)
    export_data = []
    for e in events:
        export_data.append({
            "Time": e["time"],
            "Domain": e["domain"],
            "Type": e["type"],
            "Tech": e["tech"]
        })
    return generate_pdf(export_data, "Technology Drift Report", "technology_drift_report")
