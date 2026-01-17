from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from yads.utils.export import generate_excel, generate_pdf

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

def _get_email_security_data(session: Session, user: User, for_export: bool = False):
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

    # 2. Fetch Latest DNS Results
    target_ids = tuple(t.id for t in targets)
    
    statement = select(ScanResult).where(
        ScanResult.module_name == "dns_scanner",
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.desc())
    
    results = session.exec(statement).all()
    
    latest_results = {}
    for r in results:
        if r.target_id not in latest_results:
            latest_results[r.target_id] = r
            
    # 3. Analyze Data
    rows = []
    
    secure_count = 0
    monitoring_count = 0
    vulnerable_count = 0
    
    for t_id, t in target_map.items():
        res = latest_results.get(t_id)
        
        spf_data = {"present": False, "status": "unknown"}
        dmarc_data = {"present": False, "status": "unknown", "policy": "?"}
        overall_status = "Vulnerable" # Default
        
        if res and res.data:
            # Check for new 'email_security' key from updated scanner
            es = res.data.get("email_security")
            if es:
                spf_data = es.get("spf", spf_data)
                dmarc_data = es.get("dmarc", dmarc_data)
            else:
                # Fallback
                records = res.data.get("records", {})
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
            "dmarc": dmarc_data
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
async def email_security_dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    rows, stats = _get_email_security_data(session, user)
    return templates.TemplateResponse("email_security.html", {
        "request": request, 
        "user": user, 
        "rows": rows,
        "stats": stats
    })

@router.get("/export/excel")
async def export_email_excel(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    rows, _ = _get_email_security_data(session, user, for_export=True)
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
async def export_email_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    rows, _ = _get_email_security_data(session, user, for_export=True)
    export_data = []
    for r in rows:
        export_data.append({
            "Domain": r["domain"],
            "Status": r["overall_status"],
            "SPF": "Yes" if r["spf"]["present"] else "No",
            "DMARC": r["dmarc"].get("policy", "none")
        })
    return generate_pdf(export_data, "Email Security Report", "email_security_report")
