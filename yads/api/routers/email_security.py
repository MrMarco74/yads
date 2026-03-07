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

router = APIRouter(prefix="/email-security", tags=["reports"])
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

def _get_email_security_data(session: Session, user: User, for_export: bool = False, date_from: datetime = None, date_to: datetime = None):
    # 1. Fetch relevant targets
    targets_query = select(Target)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)

    targets = session.exec(targets_query).all()
    target_map = {t.id: t for t in targets}

    if not targets:
        return [], {}

    # 2. Fetch Latest email_security and dns_scanner results
    target_ids = tuple(t.id for t in targets)

    def _fetch_latest(module: str):
        stmt = select(ScanResult).where(
            ScanResult.module_name == module,
            ScanResult.target_id.in_(target_ids)
        )
        if date_from:
            stmt = stmt.where(ScanResult.scanned_at >= date_from)
        if date_to:
            stmt = stmt.where(ScanResult.scanned_at <= date_to)
        stmt = stmt.order_by(ScanResult.scanned_at.desc())
        latest = {}
        for r in session.exec(stmt).all():
            if r.target_id not in latest:
                latest[r.target_id] = r
        return latest

    # Prefer dedicated email_security module; fall back to dns_scanner
    es_results = _fetch_latest("email_security")
    dns_results = _fetch_latest("dns_scanner")

    # 3. Analyze Data
    rows = []

    secure_count = 0
    monitoring_count = 0
    vulnerable_count = 0

    for t_id, t in target_map.items():
        es_res = es_results.get(t_id)
        dns_res = dns_results.get(t_id)

        spf_data = {"present": False, "status": "unknown"}
        dmarc_data = {"present": False, "status": "unknown", "policy": "?"}
        dkim_data = {"count": 0, "selectors_found": []}
        score = None
        overall_status = "Vulnerable"

        if es_res and es_res.data:
            # Use dedicated email_security scanner results (new format)
            d = es_res.data
            spf_data = d.get("spf", spf_data)
            dmarc_data = d.get("dmarc", dmarc_data)
            dkim_data = d.get("dkim", dkim_data)
            score = d.get("score")
        elif dns_res and dns_res.data:
            # Fallback: legacy dns_scanner with embedded email_security sub-key
            es = dns_res.data.get("email_security")
            if es:
                spf_data = es.get("spf", spf_data)
                dmarc_data = es.get("dmarc", dmarc_data)
            else:
                records = dns_res.data.get("records", {})
                txts = records.get("TXT", [])
                for r in txts:
                    if "v=spf1" in r:
                        spf_data["present"] = True
                        spf_data["record"] = r
                        if "-all" in r: spf_data["status"] = "strong"
                        elif "~all" in r: spf_data["status"] = "softfail"
                        else: spf_data["status"] = "weak"
                        break

        # Determine Status
        has_spf = spf_data.get("present")
        has_dmarc = dmarc_data.get("present")
        dmarc_policy = dmarc_data.get("policy", "none")
        
        if has_spf and has_dmarc and dmarc_policy in ["reject", "quarantine"]:
            overall_status = "Secure"
            secure_count += 1
        elif has_dmarc and dmarc_policy == "none":
            overall_status = "Monitoring"
            monitoring_count += 1
        elif has_spf and not has_dmarc:
            overall_status = "Vulnerable"
            vulnerable_count += 1
        else:
            overall_status = "Vulnerable"
            vulnerable_count += 1
            
        rows.append({
            "target_id": t.id,
            "domain": t.domain,
            "overall_status": overall_status,
            "spf": spf_data,
            "dmarc": dmarc_data,
            "dkim": dkim_data,
            "score": score,
        })
        
    # Sort: Vulnerable first
    rows.sort(key=lambda x: (x["overall_status"] == 'Secure', x["overall_status"] == 'Monitoring'))

    stats = {
        "total_targets": len(targets),
        "secure_count": secure_count,
        "monitoring_count": monitoring_count,
        "vulnerable_count": vulnerable_count
    }
    
    return rows, stats

@router.get("/", response_class=HTMLResponse)
async def email_security_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    rows, stats = _get_email_security_data(session, user, date_from=from_dt, date_to=to_dt)
    return templates.TemplateResponse("email_security.html", {
        "request": request,
        "user": user,
        "rows": rows,
        "stats": stats,
        "date_range_display": date_range_display
    })

@router.get("/export/excel")
async def export_email_excel(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    rows, _ = _get_email_security_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for r in rows:
        export_data.append({
            "Domain": r["domain"],
            "Status": r["overall_status"],
            "SPF Present": r["spf"]["present"],
            "SPF Status": r["spf"]["status"],
            "DMARC Present": r["dmarc"]["present"],
            "DMARC Policy": r["dmarc"].get("policy", "none")
        })
    return generate_excel(export_data, "email_security_report")

@router.get("/export/pdf")
async def export_email_pdf(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    rows, _ = _get_email_security_data(session, user, for_export=True, date_from=from_dt, date_to=to_dt)
    export_data = []
    for r in rows:
        export_data.append({
            "Domain": r["domain"],
            "Status": r["overall_status"],
            "SPF": "Yes" if r["spf"]["present"] else "No",
            "DMARC": r["dmarc"].get("policy", "none")
        })
    return generate_pdf(export_data, "Email Security Report", "email_security_report")
