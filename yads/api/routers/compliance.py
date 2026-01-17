from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select, text
from yads.database import get_session
from yads.auth.deps import get_current_user_html
from yads.models import User, Target, ScanResult
from yads.modules.compliance import ComplianceScorer
from fastapi.templating import Jinja2Templates

router = APIRouter(prefix="/compliance", tags=["compliance"])
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

@router.get("/", response_class=HTMLResponse)
async def compliance_dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    
    # 1. Fetch relevant targets
    targets_query = select(Target)
    if user.tenant_id:
        targets_query = targets_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        targets_query = targets_query.where(Target.tenant_id == None)
        
    all_targets = session.exec(targets_query).all()
    
    # 2. Fetch Latest Results
    params = {}
    tenant_clause = ""
    
    if user.tenant_id:
        tenant_clause = "AND t.tenant_id = :tenant_id"
        params["tenant_id"] = user.tenant_id
    elif user.role != "admin":
        tenant_clause = "AND t.tenant_id IS NULL"
    
    query = f"""
        SELECT DISTINCT ON (s.target_id, s.module_name) 
            s.target_id, s.module_name, s.data 
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE s.module_name IN ('ssl_scanner', 'web_analyzer', 'cve_scanner', 'infrastructure_scanner', 'port_scanner')
        {tenant_clause}
        ORDER BY s.target_id, s.module_name, s.scanned_at DESC
    """
    
    comp_results = session.exec(text(query), params=params).all()
    
    class MockResult:
        def __init__(self, tid, mod, d):
            self.target_id = tid
            self.module_name = mod
            self.data = d
            
    mock_results = [MockResult(r[0], r[1], r[2]) for r in comp_results]
    
    # 3. Calculate Score
    scorer = ComplianceScorer()
    stats = scorer.calculate_score(all_targets, mock_results)
    
    return templates.TemplateResponse("compliance_report.html", {
        "request": request,
        "user": user,
        "stats": stats
    })
