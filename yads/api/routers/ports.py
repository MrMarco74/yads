from fastapi import APIRouter, Depends, Request, Query
from typing import List, Dict, Any, Optional
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select, text
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from collections import Counter
from yads.utils.export import generate_excel, generate_pdf
from yads.api.utils.date_filter import parse_date_range, apply_date_filter_to_results, get_date_range_display
from datetime import datetime as dt_datetime

router = APIRouter(prefix="/ports", tags=["ports"])
from yads.api.templating import templates

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

def _get_ports_data(session: Session, user: User, for_export: bool = False, q: str = None, port: str = None, exposed_only: bool = False, date_from: dt_datetime = None, date_to: dt_datetime = None):
    """
    Shared logic to fetch and process port data with filtering support.

    Args:
        date_from: Start datetime for filtering scan results
        date_to: End datetime for filtering scan results
    """
    # Convert port to int if possible
    port_int = None
    if port and str(port).strip():
        try:
            port_int = int(port)
        except (ValueError, TypeError) as e:
            import logging
            logging.getLogger(__name__).debug(f"Invalid port filter format: {e}")
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

    # Robust approach: Get all 'port_scanner' and 'nmap_scanner' results for these targets, ordered by date desc.
    statement = select(ScanResult).where(
        ScanResult.module_name.in_(["port_scanner", "nmap_scanner"]),
        ScanResult.target_id.in_(target_ids)
    )

    # Apply date filtering
    if date_from:
        statement = statement.where(ScanResult.scanned_at >= date_from)
    if date_to:
        statement = statement.where(ScanResult.scanned_at <= date_to)

    statement = statement.order_by(ScanResult.scanned_at.desc())

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
        
        # Prepare Data
        data = res.data or {} if res else {}
        ip = data.get("ip", "-")
        last_scanned = res.scanned_at.strftime("%Y-%m-%d %H:%M") if res else "Never"
        
        # Extract Ports
        if res:
            # Historically some results might have had http/https keys
            if data.get("http", {}).get("open"):
                open_ports.append(80)
            if data.get("https", {}).get("open"):
                open_ports.append(443)
                
            # Both port_scanner and nmap_scanner return "open_ports" as a list of dicts or ints
            raw_ports = data.get("open_ports", [])
            if isinstance(raw_ports, list):
                for p in raw_ports:
                    p_num = None
                    if isinstance(p, int):
                        p_num = p
                    elif isinstance(p, dict) and "port" in p:
                        p_num = p["port"]
                    
                    if p_num and p_num not in open_ports:
                        open_ports.append(p_num)
        
        # Filtering Logic
        match_q = True
        if q:
            q_lower = q.lower()
            match_q = q_lower in t.domain.lower() or (ip and q_lower in ip.lower())
        
        match_port = True
        if port_int:
            match_port = port_int in open_ports
        
        match_exposed = True
        if exposed_only:
            match_exposed = len(open_ports) > 0
        
        if match_q and match_port and match_exposed:
            if open_ports:
                open_ports.sort()
                exposed_targets_count += 1
                all_open_ports.extend(open_ports)
            
            if res or not for_export:
                 delta = (data.get("port_delta") or {}) if res else {}
                 rows.append({
                    "target_id": t.id,
                    "domain": t.domain,
                    "ip": ip,
                    "ports": open_ports, # List of ints
                    "ports_str": ", ".join(map(str, open_ports)), # Helper for export
                    "last_scanned": last_scanned,
                    "newly_exposed": delta.get("newly_exposed", []),
                    "closed_since_last": delta.get("closed_since_last", []),
                })
    
    # Sort rows: Exposed first, then by domain
    rows.sort(key=lambda x: (len(x["ports"]) == 0, x["domain"]))

    # Stats
    port_counts = Counter(all_open_ports)
    top_port = port_counts.most_common(1)
    top_port = top_port[0] if top_port else None
    
    stats = {
        "total_targets": len(rows),
        "total_tenant_targets": len(targets),
        "exposed_targets": exposed_targets_count,
        "top_port": top_port,
        "top_ports_list": port_counts.most_common(5),
        "newly_exposed_targets": sum(1 for r in rows if r.get("newly_exposed")),
    }
    
    return rows, stats

@router.get("/", response_class=HTMLResponse)
async def list_open_ports(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    q: Optional[str] = None,
    port: Optional[str] = None,
    exposed_only: Optional[str] = None,
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    # Normalize exposed_only to bool
    is_exposed_only = False
    if exposed_only and exposed_only.lower() == "true":
        is_exposed_only = True

    # Parse date range
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    rows, stats = _get_ports_data(session, user, q=q, port=port, exposed_only=is_exposed_only, date_from=from_dt, date_to=to_dt)
    return templates.TemplateResponse("ports.html", {
        "request": request,
        "user": user,
        "rows": rows,
        "stats": stats,
        "date_range_display": date_range_display
    })

@router.get("/export/excel")
async def export_ports_excel(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    q: Optional[str] = None,
    port: Optional[str] = None,
    exposed_only: Optional[str] = None,
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    # Normalize exposed_only to bool
    is_exposed_only = False
    if exposed_only and exposed_only.lower() == "true":
        is_exposed_only = True

    # Parse date range
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)

    rows, _ = _get_ports_data(session, user, for_export=True, q=q, port=port, exposed_only=is_exposed_only, date_from=from_dt, date_to=to_dt)
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
async def export_ports_pdf(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    q: Optional[str] = None,
    port: Optional[str] = None,
    exposed_only: Optional[str] = None,
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    # Normalize exposed_only to bool
    is_exposed_only = False
    if exposed_only and exposed_only.lower() == "true":
        is_exposed_only = True

    # Parse date range
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)

    rows, _ = _get_ports_data(session, user, for_export=True, q=q, port=port, exposed_only=is_exposed_only, date_from=from_dt, date_to=to_dt)
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
