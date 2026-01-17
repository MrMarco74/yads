
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user
from yads.models import User, Target, ScanResult
from fastapi.templating import Jinja2Templates
from yads.utils.export import generate_excel, generate_pdf

router = APIRouter(prefix="/secrets", tags=["reports"])
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

def _get_secrets_data(session: Session, user: User, for_export: bool = False):
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
        return {"credentials": [], "configs": [], "pii": []}, {
            "critical": 0,
            "configs": 0,
            "pii": 0,
            "targets_affected": 0
        }

    # 2. Fetch Nuclei & WebAnalyzer results
    statement = select(ScanResult).where(
        ScanResult.module_name.in_(["nuclei_scanner", "web_analyzer"]),
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.desc())
    
    results = session.exec(statement).all()
    
    # Dedup logic: keep latest per target per module
    latest_results = {} # key: (target_id, module)
    for r in results:
        key = (r.target_id, r.module_name)
        if key not in latest_results:
            latest_results[key] = r

    # 3. Aggregate Finding
    findings = {
        "credentials": [],
        "configs": [],
        "pii": []
    }
    
    stats = {
        "critical": 0,
        "configs": 0,
        "pii": 0,
        "targets_affected": 0
    }
    
    affected_targets = set()
    
    # Keywords for Nuclei Tags/Names
    cred_keywords = ["token", "api-key", "secret", "credential", "password", "aws-key", "google-key"]
    config_keywords = ["exposure", "config", "env", "git-config", "backup", "db-dump"]
    
    for (t_id, mod), res in latest_results.items():
        target = target_map.get(t_id)
        if not target or not res.data: continue
        
        # --- Nuclei Analysis ---
        if mod == "nuclei_scanner":
            scan_findings = res.data.get("findings", [])
            for f in scan_findings:
                name_addr = f.get("name", "").lower()
                tid = f.get("template_id", "").lower()
                severity = f.get("severity", "").lower()

                item = {
                    "name": f.get("name"),
                    "target_id": t_id,
                    "target_domain": target.domain,
                    "location": f.get("matched_at"),
                    "severity": severity,
                    "scanner": "Nuclei"
                }
                if not for_export:
                    item["description"] = f.get("description")
                
                is_cred = any(k in name_addr or k in tid for k in cred_keywords)
                is_config = any(k in name_addr or k in tid for k in config_keywords)
                
                # Filter Logic
                if is_cred and severity in ["critical", "high", "medium"]:
                    findings["credentials"].append(item)
                    if severity == "critical": stats["critical"] += 1
                    affected_targets.add(t_id)
                elif is_config and severity in ["critical", "high", "medium", "low"]:
                    # Configs can be low (e.g. phpinfo) but still useful here
                    findings["configs"].append(item)
                    stats["configs"] += 1
                    affected_targets.add(t_id)

        # --- Web Analyzer Analysis ---
        elif mod == "web_analyzer":
            # Secrets
            secrets = res.data.get("secrets", [])
            for s in secrets:
                # {type, value, snippet}
                item = {
                    "name": s.get("type"),
                    "target_id": t_id,
                    "target_domain": target.domain,
                    "location": f"http://{target.domain}", # Web Analyzer usually scans root
                    "scanner": "Web Analyzer"
                }
                if not for_export:
                    item["secret"] = s.get("value")
                findings["credentials"].append(item)
                stats["critical"] += 1 # Assume web analyzer secrets are critical
                affected_targets.add(t_id)
            
            # PII (Emails) - optional to show?
            emails = res.data.get("emails", [])
            if emails:
                 stats["pii"] += len(emails)
                 # We are not listing every email in the generic view to avoid clutter, just stats
                 if len(emails) > 0: affected_targets.add(t_id)

    stats["targets_affected"] = len(affected_targets)
    return findings, stats

@router.get("/", response_class=HTMLResponse)
async def secrets_dashboard(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_user_html)):
    findings, stats = _get_secrets_data(session, user)
    return templates.TemplateResponse("secrets.html", {
        "request": request, 
        "user": user, 
        "findings": findings,
        "stats": stats
    })

@router.get("/export/excel")
async def export_secrets_excel(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    findings, _ = _get_secrets_data(session, user, for_export=True)
    
    # Combine lists for export
    all_rows = []
    for f in findings["credentials"]:
        all_rows.append({"Type": "Credential", "Name": f["name"], "Domain": f["target_domain"], "Severity": "High", "Scanner": f["scanner"]})
    for f in findings["configs"]:
        all_rows.append({"Type": "Configuration", "Name": f["name"], "Domain": f["target_domain"], "Severity": f.get("severity", "Unknown"), "Scanner": f["scanner"]})
        
    return generate_excel(all_rows, "secrets_audit_report")

@router.get("/export/pdf")
async def export_secrets_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    findings, _ = _get_secrets_data(session, user, for_export=True)
    
    all_rows = []
    for f in findings["credentials"]:
         all_rows.append({"Type": "Key", "Name": f["name"], "Domain": f["target_domain"], "Severity": "High"})
    for f in findings["configs"]:
         all_rows.append({"Type": "Config", "Name": f["name"], "Domain": f["target_domain"], "Severity": f.get("severity", "Unknown")})
         
    return generate_pdf(all_rows, "Sensitive Data Audit", "secrets_audit_report")

