from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from typing import Optional
from sqlmodel import Session, select
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from datetime import datetime
import dateutil.parser
from yads.utils.export import generate_excel, generate_pdf
from yads.api.utils.date_filter import parse_date_range, get_date_range_display

router = APIRouter(prefix="/cert-timeline", tags=["reports"])
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

def _get_cert_timeline_data(session: Session, user: User, for_export: bool = False, date_from: datetime = None, date_to: datetime = None):
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
        return {}, {"total_certs": 0, "expiring_soon": 0, "rogue_candidates": 0}

    # 2. Fetch Latest SSL Results
    statement = select(ScanResult).where(
        ScanResult.module_name == "ssl_scanner",
        ScanResult.target_id.in_(target_ids)
    )

    # Apply date filtering
    if date_from:
        statement = statement.where(ScanResult.scanned_at >= date_from)
    if date_to:
        statement = statement.where(ScanResult.scanned_at <= date_to)

    statement = statement.order_by(ScanResult.scanned_at.desc())

    results = session.exec(statement).all()
    
    # Dedup: Keep only latest per target
    latest_results = {}
    for r in results:
        if r.target_id not in latest_results:
            latest_results[r.target_id] = r
            
    # 3. Process Certificate Dates
    events = []
    
    stats = {
        "total_certs": 0,
        "expiring_soon": 0,
        "rogue_candidates": 0 
    }
    
    for t_id, res in latest_results.items():
        if not res.data: continue
        target = target_map.get(t_id)
        
        # Extract Dates
        not_before_str = res.data.get("notBefore")
        not_after_str = res.data.get("notAfter")
        issuer = res.data.get("issuer", {}).get("commonName", "Unknown Issuer")
        
        if not not_before_str: continue
        
        try:
            issued_date = dateutil.parser.parse(not_before_str).replace(tzinfo=None) # naive comparison
            expiry_date = dateutil.parser.parse(not_after_str).replace(tzinfo=None) if not_after_str else None
            
            stats["total_certs"] += 1
            
            # Check for expiring soon (< 30 days)
            if expiry_date:
                days_left = (expiry_date - datetime.now()).days
                if days_left < 30:
                    stats["expiring_soon"] += 1
            
            # Check for "New" (Rogue candidate?)
            hours_since_issue = (datetime.now() - issued_date).total_seconds() / 3600
            if hours_since_issue < 24:
                stats["rogue_candidates"] += 1
                
            events.append({
                "target_id": t_id,
                "domain": target.domain,
                "issuer": issuer,
                "issued_at": issued_date,
                "expires_at": expiry_date,
                "days_valid": (expiry_date - issued_date).days if expiry_date else 0,
                "is_new": hours_since_issue < 24,
                "subject": res.data.get("subject", {}).get("commonName", target.domain),
                "issued_display": issued_date.strftime("%b %d, %Y"),
                "expires_display": expiry_date.strftime("%b %d, %Y") if expiry_date else "Unknown"
            })
            
        except Exception:
            continue

    # 4. Sort by Issuance Date (Newest First)
    events.sort(key=lambda x: x['issued_at'], reverse=True)
    
    # 5. Group by Month/Year
    if for_export:
        return events, stats

    timeline = {}
    for e in events:
        month_year = e['issued_at'].strftime("%B %Y")
        if month_year not in timeline:
            timeline[month_year] = []
        timeline[month_year].append(e)

    return timeline, stats

@router.get("/", response_class=HTMLResponse)
async def cert_timeline_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    timeline, stats = _get_cert_timeline_data(session, user, date_from=from_dt, date_to=to_dt)
    return templates.TemplateResponse("cert_timeline.html", {
        "request": request,
        "user": user,
        "timeline": timeline,
        "stats": stats,
        "date_range_display": date_range_display
    })

@router.get("/export/excel")
async def export_cert_excel(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    events, _ = _get_cert_timeline_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for e in events:
        export_data.append({
            "Domain": e["domain"],
            "Issued On": e["issued_display"],
            "Issuer": e["issuer"],
            "Expires On": e["expires_display"],
            "Days Valid": e["days_valid"]
        })
    return generate_excel(export_data, "certificate_timeline_report")

@router.get("/export/pdf")
async def export_cert_pdf(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    events, _ = _get_cert_timeline_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for e in events:
        export_data.append({
            "Domain": e["domain"],
            "Issued": e["issued_display"],
            "Expires": e["expires_display"],
            "Issuer": e["issuer"]
        })
@router.get("/inventory", response_class=HTMLResponse)
async def ssl_inventory_view(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    inventory, stats = _get_ssl_inventory_data(session, user, date_from=from_dt, date_to=to_dt)
    return templates.TemplateResponse("analytics_ssl.html", {
        "request": request,
        "user": user,
        "inventory": inventory,
        "stats": stats,
        "date_range_display": date_range_display
    })

def _get_ssl_inventory_data(session: Session, user: User, for_export: bool = False, date_from: datetime = None, date_to: datetime = None):
    # Reuse logic to fetch targets and results
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
        return [], {"total_certs": 0}

    # 2. Fetch Latest SSL Results
    statement = select(ScanResult).where(
        ScanResult.module_name == "ssl_scanner",
        ScanResult.target_id.in_(target_ids)
    )

    # Apply date filtering
    if date_from:
        statement = statement.where(ScanResult.scanned_at >= date_from)
    if date_to:
        statement = statement.where(ScanResult.scanned_at <= date_to)

    statement = statement.order_by(ScanResult.scanned_at.desc())

    results = session.exec(statement).all()
    
    # Dedup
    latest_results = {}
    for r in results:
        if r.target_id not in latest_results:
            latest_results[r.target_id] = r
            
    inventory = []
    stats = {"total_certs": 0}
    
    for t_id, res in latest_results.items():
        if not res.data: continue
        target = target_map.get(t_id)
        
        # Extract Fields
        data = res.data
        if not data.get("notBefore"): continue
        
        try:
            issued_date = dateutil.parser.parse(data.get("notBefore")).replace(tzinfo=None)
            expiry_date = dateutil.parser.parse(data.get("notAfter")).replace(tzinfo=None) if data.get("notAfter") else None
            
            stats["total_certs"] += 1
            
            # SAN processing
            sans = data.get("subjectAltName", [])
            san_list = []
            for item in sans:
                if isinstance(item, (list, tuple)) and len(item) > 1:
                    san_list.append(item[1])
                else:
                    san_list.append(str(item))
            
            # Intelligent Issuer Name
            # "E7", "R3", "R10" are confusing. We want "Let's Encrypt (E7)" or "Google Trust Services (GTS CA 1C3)"
            issuer_data = data.get("issuer", {})
            cn = issuer_data.get("commonName", "")
            org = issuer_data.get("organizationName", "")
            
            # Known Mappings for specific short codes (Optional fallback)
            known_map = {
                "R3": "Let's Encrypt (RSA)",
                "R10": "Let's Encrypt (RSA)",
                "R11": "Let's Encrypt (RSA)",
                "R12": "Let's Encrypt (RSA)",
                "R13": "Let's Encrypt (RSA)",
                "R14": "Let's Encrypt (RSA)",
                "E1": "Let's Encrypt (ECDSA)",
                "E5": "Let's Encrypt (ECDSA)",
                "E6": "Let's Encrypt (ECDSA)", 
                "E7": "Let's Encrypt (ECDSA)",
                "E8": "Let's Encrypt (ECDSA)",
                "E9": "Let's Encrypt (ECDSA)"
            }

            if cn in known_map:
                issuer_display = known_map[cn]
            elif org and cn:
                if org in cn:
                    issuer_display = cn # e.g. "Google Trust Services LLC" is both Org and part of CN sometimes
                else:
                    issuer_display = f"{org} ({cn})" 
            elif org:
                issuer_display = org
            else:
                issuer_display = cn or "Unknown Issuer"

            inventory.append({
                "target_id": t_id,
                "domain": target.domain,
                "subject": data.get("subject", {}).get("commonName", target.domain),
                "issuer": issuer_display,
                "issued_display": issued_date.strftime("%Y-%m-%d"),
                "expires_display": expiry_date.strftime("%Y-%m-%d") if expiry_date else "Unknown",
                "days_valid": (expiry_date - datetime.now()).days if expiry_date else 0,
                "serial_short": str(data.get("serialNumber", ""))[:8],
                "version": f"v{data.get('version', '?')}",
                "san_count": len(san_list),
                "sans": ", ".join(san_list[:5]) + ("..." if len(san_list) > 5 else "")
            })
            
        except Exception:
            continue

    # Sort by failing/expiring first
    inventory.sort(key=lambda x: x['days_valid'])
    
    return inventory, stats
