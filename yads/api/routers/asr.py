from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from datetime import datetime
import dateutil.parser
from yads.utils.export import generate_excel, generate_pdf

router = APIRouter(prefix="/asr", tags=["reports"])
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

def _get_asr_data(session: Session, user: User, for_export: bool = False):
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
        return [], {"dead_endpoints": 0, "unconfigured": 0, "expired_certs": 0, "total_cleanup": 0}

    # 2. Fetch Latest Results for WebAnalyzer & SSL
    statement = select(ScanResult).where(
        ScanResult.module_name.in_(["web_analyzer", "ssl_scanner"]),
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.desc())
    
    results = session.exec(statement).all()
    
    # Dedup: Keep latest per target per module
    latest = {}
    for r in results:
        key = (r.target_id, r.module_name)
        if key not in latest:
            latest[key] = r
            
    items = []
    stats = {
        "dead_endpoints": 0,
        "unconfigured": 0,
        "expired_certs": 0,
        "total_cleanup": 0
    }
    
    # 3. Analyze for Cleanup Candidates
    
    # Default Page Titles to watch for
    DEFAULT_TITLES = [
        "Welcome to nginx!",
        "Apache2 Ubuntu Default Page",
        "IIS Windows Server",
        "It works!",
        "Welcome to CentOS",
        "Test Page for the Nginx HTTP Server"
    ]
    
    for t_id, target in target_map.items():
        
        # --- Web Analyzer Check ---
        web_res = latest.get((t_id, "web_analyzer"))
        if web_res and web_res.data:
            # Check Status Code
            status = web_res.data.get("status_code")
            if status in [404, 500, 502, 503]:
                items.append({
                    "target_id": t_id,
                    "domain": target.domain,
                    "type": "Dead Endpoint",
                    "issue": f"HTTP {status} Response",
                    "recommendation": "Decommission DNS record if service is retired.",
                    "severity": "low", 
                    "detected_at": web_res.scanned_at
                })
                stats["dead_endpoints"] += 1
                
            # Check Default Page
            title = web_res.data.get("title", "")
            if title and any(dt.lower() in title.lower() for dt in DEFAULT_TITLES):
                items.append({
                    "target_id": t_id,
                    "domain": target.domain,
                    "type": "Unconfigured Server",
                    "issue": f"Default Page: '{title}'",
                    "recommendation": "Remove default page or decommission server.",
                    "severity": "medium", 
                    "detected_at": web_res.scanned_at
                })
                stats["unconfigured"] += 1

        # --- SSL Scanner Check ---
        ssl_res = latest.get((t_id, "ssl_scanner"))
        if ssl_res and ssl_res.data:
            not_after = ssl_res.data.get("notAfter")
            if not_after:
                try:
                    expiry = dateutil.parser.parse(not_after).replace(tzinfo=None)
                    if expiry < datetime.now():
                        items.append({
                            "target_id": t_id,
                            "domain": target.domain,
                            "type": "Expired Certificate",
                            "issue": f"Expired on {expiry.strftime('%Y-%m-%d')}",
                            "recommendation": "Renew certificate or decommission asset.",
                            "severity": "high", 
                            "detected_at": ssl_res.scanned_at
                        })
                        stats["expired_certs"] += 1
                except:
                    pass

    stats["total_cleanup"] = len(items)
    
    # Sort by Severity then Domain
    severity_order = {"high": 0, "medium": 1, "low": 2}
    items.sort(key=lambda x: (severity_order.get(x["severity"], 3), x["domain"]))

    return items, stats

@router.get("/", response_class=HTMLResponse)
async def asr_dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    items, stats = _get_asr_data(session, user)
    return templates.TemplateResponse("asr.html", {
        "request": request, 
        "user": user, 
        "items": items,
        "stats": stats
    })

@router.get("/export/excel")
async def export_asr_excel(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    items, _ = _get_asr_data(session, user, for_export=True)
    export_data = []
    for i in items:
        export_data.append({
            "Domain": i["domain"],
            "Issue Type": i["type"],
            "Details": i["issue"],
            "Recommendation": i["recommendation"],
            "Severity": i["severity"].upper()
        })
    return generate_excel(export_data, "attack_surface_reduction_report")

@router.get("/export/pdf")
async def export_asr_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    items, _ = _get_asr_data(session, user, for_export=True)
    export_data = []
    for i in items:
        export_data.append({
            "Domain": i["domain"],
            "Type": i["type"],
            "Details": i["issue"],
            "Severity": i["severity"].upper()
        })
    return generate_pdf(export_data, "Attack Surface Reduction", "asr_report")
