from fastapi import APIRouter, Depends, Request, Response, HTTPException
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user, RoleChecker
from yads.models import User, Target
from fastapi.templating import Jinja2Templates
import csv
import io
from datetime import datetime
from yads.utils.export import generate_excel, generate_pdf, generate_api_excel, generate_form_excel
from yads.models import User, Target, ScanResult
from yads.modules.report_generator import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals
from yads.config import settings
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

# Helper for sidebar (duplicate from main.py unfortunately, unless we put it in dependencies)
def get_all_tenants():
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()
templates.env.globals['get_available_tenants'] = get_all_tenants

def _get_targets_data(session: Session, user: User, for_export: bool = False):
    query = select(Target)
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        query = query.where(Target.tenant_id == None)
        
    targets = session.exec(query).all()
    
    if not for_export:
        return targets
        
    export_data = []
    for t in targets:
        export_data.append({
            "ID": t.id,
            "Domain": t.domain,
            "Created At": t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Last Scan": t.last_scanned_at.strftime("%Y-%m-%d %H:%M:%S") if t.last_scanned_at else "Never",
            "Status": t.scan_status
        })
    return export_data

@router.get("/", response_class=HTMLResponse)
async def reports_index(request: Request, user: User = Depends(get_current_user_html)):
    return templates.TemplateResponse("reports.html", {
        "request": request,
        "user": user
    })

@router.get("/targets/csv")
async def export_targets_csv(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    targets = _get_targets_data(session, user, for_export=False)
    
    # Generate CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['ID', 'Domain', 'Created At', 'Last Scan', 'Status'])
    
    for t in targets:
        writer.writerow([
            t.id, 
            t.domain, 
            t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            t.last_scanned_at.strftime("%Y-%m-%d %H:%M:%S") if t.last_scanned_at else "Never",
            t.scan_status
        ])
        
    filename = f"targets_export_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/targets/excel")
async def export_targets_excel(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    data = _get_targets_data(session, user, for_export=True)
    return generate_excel(data, "targets_list")

@router.get("/targets/pdf")
async def export_targets_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    data = _get_targets_data(session, user, for_export=True)
    return generate_pdf(data, "Target List", "targets_list")

@router.get("/scan/{target_id}/pdf")
async def export_scan_pdf(target_id: int, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"]))):
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Fetch Scan Results
    # We want the LATEST result for each module.
    # Logic: group by module_name, take latest.
    
    # 1. Fetch all results for target
    all_results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc())).all()
    
    # 2. Filter for latest per module
    latest_results_map = {}
    for res in all_results:
        if res.module_name not in latest_results_map:
            latest_results_map[res.module_name] = res
            
    latest_results = list(latest_results_map.values())
    
    # Generate PDF
    pdf_bytes = generate_report(target.domain, latest_results)
    
    filename = f"report_{target.domain}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    
    return Response(
        content=bytes(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@router.get("/scan/{target_id}/excel")
async def export_api_excel(target_id: int, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"]))):
    """
    Exports API Discovery data specifically to Excel.
    """
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Fetch API Discovery Result
    api_res = session.exec(select(ScanResult).where(
        ScanResult.target_id == target_id, 
        ScanResult.module_name == "api_discovery"
    ).order_by(ScanResult.scanned_at.desc())).first()
    
    data = {}
    if api_res:
        data = api_res.data
        
    return generate_api_excel(data, f"api_discovery_{target.domain}")

@router.get("/scan/{target_id}/forms/excel")
async def export_form_excel(target_id: int, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"]))):
    """
    Exports Form Discovery data specifically to Excel.
    """
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    # Fetch Form Discovery Result
    form_res = session.exec(select(ScanResult).where(
        ScanResult.target_id == target_id, 
        ScanResult.module_name == "form_discovery"
    ).order_by(ScanResult.scanned_at.desc())).first()
    
    data = {}
    if form_res:
        data = form_res.data
        
    return generate_form_excel(data, f"form_discovery_{target.domain}")
