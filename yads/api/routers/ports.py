from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select, text
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from collections import Counter
from yads.utils.export import generate_excel, generate_pdf

router = APIRouter(prefix="/ports", tags=["ports"])
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals
from yads.config import settings
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

def get_all_tenants():
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()
templates.env.globals['get_available_tenants'] = get_all_tenants

def _get_ports_data(session: Session, user: User, for_export: bool = False):
    """
    Shared logic to fetch and process port data.
    """
    # 1. Scope definition (Strict Tenant Isolation)
    targets_query = select(Target)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)
        
    targets = session.exec(targets_query).all()
    target_map = {t.id: t for t in targets}
    
    if not targets:
        return [], {}

    # 2. Fetch Port Scan Results
    target_ids = tuple(t.id for t in targets)
    
    # Robust approach: Get all 'port_scanner' results for these targets, ordered by date desc.
    statement = select(ScanResult).where(
        ScanResult.module_name == "port_scanner",
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.desc())
    
    results = session.exec(statement).all()
    
    # Dedup: Keep only the first result (latest) per target_id
    latest_results = {}
    for r in results:
        if r.target_id not in latest_results:
            latest_results[r.target_id] = r
            
    # 3. Aggregate Data
    rows = []
    all_open_ports = []
    exposed_targets_count = 0
    
    for t_id, t in target_map.items():
        res = latest_results.get(t_id)
        open_ports = []
        ip = "-"
        last_scanned = "Never"
        
        if res:
            data = res.data or {}
            
            # Helper to extract ports based on the known structure from port_scanner.py
            if data.get("http", {}).get("open"):
                open_ports.append(80)
            if data.get("https", {}).get("open"):
                open_ports.append(443)
                
            # If the module was Nmap or similar returning "open_ports" list
            if "open_ports" in data:
                 raw_ports = data.get("open_ports", [])
                 if isinstance(raw_ports, list):
                     for p in raw_ports:
                         if isinstance(p, int) and p not in open_ports:
                             open_ports.append(p)
            
            if open_ports:
                open_ports.sort()
                exposed_targets_count += 1
                all_open_ports.extend(open_ports)
                
            ip = data.get("ip", "-")
            last_scanned = res.scanned_at.strftime("%Y-%m-%d %H:%M")
        
        if res or not for_export: # For UI show all, for export maybe all too? Yes, let's keep consistent.
             rows.append({
                "target_id": t.id,
                "domain": t.domain,
                "ip": ip,
                "ports": open_ports, # List of ints
                "ports_str": ", ".join(map(str, open_ports)), # Helper for export
                "last_scanned": last_scanned
            })
    
    # Sort rows: Exposed first, then by domain
    rows.sort(key=lambda x: (len(x["ports"]) == 0, x["domain"]))

    # Stats
    port_counts = Counter(all_open_ports)
    top_port = port_counts.most_common(1)
    top_port = top_port[0] if top_port else None
    
    stats = {
        "total_targets": len(targets),
        "exposed_targets": exposed_targets_count,
        "top_port": top_port,
        "top_ports_list": port_counts.most_common(5)
    }
    
    return rows, stats

@router.get("/", response_class=HTMLResponse)
async def list_open_ports(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    rows, stats = _get_ports_data(session, user)
    return templates.TemplateResponse("ports.html", {
        "request": request, 
        "user": user, 
        "rows": rows,
        "stats": stats
    })

@router.get("/export/excel")
async def export_ports_excel(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    rows, _ = _get_ports_data(session, user, for_export=True)
    # Prepare flat data for export
    export_data = []
    for r in rows:
        export_data.append({
            "Domain": r["domain"],
            "IP Address": r["ip"],
            "Open Ports": r["ports_str"],
            "Last Scanned": r["last_scanned"]
        })
    return generate_excel(export_data, "port_exposure_report")

@router.get("/export/pdf")
async def export_ports_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    rows, _ = _get_ports_data(session, user, for_export=True)
    # Prepare flat data for export
    export_data = []
    for r in rows:
        export_data.append({
            "Domain": r["domain"],
            "IP": r["ip"],
            "Ports": r["ports_str"],
            "Last Scan": r["last_scanned"]
        })
    return generate_pdf(export_data, "Port Exposure Report", "port_exposure_report")
