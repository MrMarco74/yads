from fastapi import APIRouter, Depends, Request, Response, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select
from typing import Optional
from yads.database import get_session
from yads.auth.deps import get_current_user_html, get_current_active_user, RoleChecker
from yads.models import User, Target
from fastapi.templating import Jinja2Templates
import csv
import io
from datetime import datetime
from yads.utils.export import generate_excel, generate_pdf, generate_api_excel, generate_form_excel, generate_traffic_excel, generate_traffic_pdf
from yads.models import User, Target, ScanResult, HTTPTraffic
from yads.modules.report_generator import generate_report
from yads.utils.license_deps import require_feature
from yads.api.utils.date_filter import parse_date_range, get_date_range_display

router = APIRouter(prefix="/reports", tags=["reports"], dependencies=[Depends(require_feature("reports"))])
from yads.api.templating import templates
# from fastapi.templating import Jinja2Templates

# Inject Globals (Handled in templating.py now)
from yads.config import settings
from datetime import datetime
# templates.env.globals['settings'] = settings
# templates.env.globals['now_utc'] = ...

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
        # Fetch latest result for last scan timestamp
        latest_res = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).first()
        last_scan = latest_res.scanned_at.strftime("%Y-%m-%d %H:%M:%S") if latest_res else "Never"
        
        export_data.append({
            "ID": t.id,
            "Domain": t.domain,
            "Created At": t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Last Scan": last_scan,
            "Status": t.scan_status
        })
    return export_data

@router.get("/", response_class=HTMLResponse)
async def reports_index(request: Request, user: User = Depends(get_current_user_html)):
    from yads.core.module_registry import REGISTRY, CATEGORIES

    # Modules with dedicated view/export pages
    DEDICATED = {
        "email_security":    {"view": "/email-security",  "excel": "/email-security/export/excel",  "pdf": "/email-security/export/pdf"},
        "cloud_scanner":     {"view": "/cloud-assets",    "excel": "/cloud-assets/export/excel",    "pdf": "/cloud-assets/export/pdf"},
        "port_scanner":      {"view": "/ports",           "excel": "/ports/export/excel",           "pdf": "/ports/export/pdf"},
        "nmap_scanner":      {"view": "/ports",           "excel": "/ports/export/excel",           "pdf": "/ports/export/pdf"},
        "js_secrets":        {"view": "/secrets",         "excel": "/secrets/export/excel",         "pdf": "/secrets/export/pdf"},
        "ssl_scanner":       {"view": "/cert-timeline",   "excel": "/cert-timeline/export/excel",   "pdf": "/cert-timeline/export/pdf"},
        "tls_deep_scanner":  {"view": "/cert-timeline",   "excel": "/cert-timeline/export/excel",   "pdf": "/cert-timeline/export/pdf"},
        "infrastructure_scanner": {"view": "/ports",      "excel": "/ports/export/excel",           "pdf": "/ports/export/pdf"},
        "threat_intel":      {"view": "/security-findings?module=threat_intel"},
    }

    # Build grouped structure following CATEGORIES order
    grouped = []
    for cat in CATEGORIES:
        mods = [
            {
                "name": defn.label,
                "name_de": defn.label_de,
                "module": name,
                "dedicated": DEDICATED.get(name),
            }
            for name, defn in REGISTRY.items()
            if defn.category == cat["id"] and defn.finding_module
        ]
        if mods:
            grouped.append({"cat": cat, "modules": mods})

    return templates.TemplateResponse("reports.html", {
        "request": request,
        "user": user,
        "grouped": grouped,
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
        # Fetch latest result for last scan timestamp
        latest_res = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).first()
        last_scan = latest_res.scanned_at.strftime("%Y-%m-%d %H:%M:%S") if latest_res else "Never"
        
        writer.writerow([
            t.id, 
            t.domain, 
            t.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            last_scan,
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
    from yads.utils.findings import FindingStatusFilter
    status_filter = FindingStatusFilter(session, user.tenant_id if user.tenant_id else None)
    pdf_bytes = generate_report(target.domain, latest_results, status_filter=status_filter)
    
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

@router.get("/traffic", response_class=HTMLResponse)
async def view_traffic_history(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    """
    Web view for HTTP Traffic History.
    """
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)
    date_range_display = get_date_range_display(from_dt, to_dt, preset)

    query = select(HTTPTraffic).join(Target)
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        query = query.where(Target.tenant_id == None)

    # Apply date filtering on timestamp field
    if from_dt:
        query = query.where(HTTPTraffic.timestamp >= from_dt)
    if to_dt:
        query = query.where(HTTPTraffic.timestamp <= to_dt)

    # Fetch latest 500 entries for performance
    traffic = session.exec(query.order_by(HTTPTraffic.timestamp.desc()).limit(500)).all()

    return templates.TemplateResponse("reports_traffic.html", {
        "request": request,
        "user": user,
        "traffic": traffic,
        "date_range_display": date_range_display
    })

@router.get("/traffic/excel")
async def export_traffic_excel(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    """
    Exports ALL HTTP traffic for the current tenant to Excel.
    """
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)

    query = select(HTTPTraffic).join(Target)
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        query = query.where(Target.tenant_id == -1)  # no results for non-admin without tenant

    # Apply date filtering
    if from_dt:
        query = query.where(HTTPTraffic.timestamp >= from_dt)
    if to_dt:
        query = query.where(HTTPTraffic.timestamp <= to_dt)

    traffic = session.exec(query.order_by(HTTPTraffic.timestamp.desc())).all()
    return generate_traffic_excel(traffic, "tenant_http_traffic")

@router.get("/traffic/pdf")
async def export_traffic_pdf(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    preset: Optional[str] = Query("all")
):
    """
    Exports ALL HTTP traffic for the current tenant to PDF.
    """
    from_dt, to_dt = parse_date_range(date_from, date_to, preset)

    query = select(HTTPTraffic).join(Target)
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        query = query.where(Target.tenant_id == -1)  # no results for non-admin without tenant

    # Apply date filtering
    if from_dt:
        query = query.where(HTTPTraffic.timestamp >= from_dt)
    if to_dt:
        query = query.where(HTTPTraffic.timestamp <= to_dt)

    traffic = session.exec(query.order_by(HTTPTraffic.timestamp.desc())).all()
    return generate_traffic_pdf(traffic, "Tenant Infrastructure", "tenant_http_traffic")

@router.get("/scan/{target_id}/traffic/excel")
async def export_target_traffic_excel(target_id: int, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"]))):
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    traffic = session.exec(select(HTTPTraffic).where(HTTPTraffic.target_id == target_id).order_by(HTTPTraffic.timestamp.desc())).all()
    return generate_traffic_excel(traffic, f"traffic_{target.domain}")

@router.get("/scan/{target_id}/traffic/pdf")
async def export_target_traffic_pdf(target_id: int, session: Session = Depends(get_session), user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner", "auditor"]))):
    # Tenant Scope Check
    target = session.exec(select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    traffic = session.exec(select(HTTPTraffic).where(HTTPTraffic.target_id == target_id).order_by(HTTPTraffic.timestamp.desc())).all()
    return generate_traffic_pdf(traffic, target.domain, f"traffic_{target.domain}")


@router.get("/export-all-zip")
async def export_all_zip(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Generates all available report types and packages them into a single ZIP file.
    """
    import zipfile
    import io as _io
    from yads.api.routers.ports import _get_ports_data
    from yads.api.routers.asr import _get_asr_data
    from yads.api.routers.email_security import _get_email_security_data
    from yads.api.routers.tech_drift import _get_tech_drift_data
    from yads.api.routers.cert_timeline import _get_cert_timeline_data
    from yads.api.routers.cloud_assets import _get_cloud_data
    from yads.api.routers.secrets import _get_secrets_data
    from yads.api.routers.analytics import _get_infrastructure_data, _get_external_links_data, _get_hijacking_data
    from yads.modules.report_generator import generate_infrastructure_report, generate_external_links_report
    from yads.utils.export import generate_traffic_excel as _gen_traffic_excel, generate_traffic_pdf as _gen_traffic_pdf

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
    buf = _io.BytesIO()

    from yads.utils.findings import FindingStatusFilter
    status_filter = FindingStatusFilter(session, user.tenant_id if user.tenant_id else None)

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

        # --- 1. Target List ---
        targets_data = _get_targets_data(session, user, for_export=True)
        zf.writestr(f"targets_list_{ts}.xlsx", generate_excel(targets_data, "targets_list").body)
        zf.writestr(f"targets_list_{ts}.csv", _targets_csv(targets_data))

        # --- 2. Port Exposure ---
        port_rows, _ = _get_ports_data(session, user)
        port_export = [{"Domain": r["domain"], "IP Address": r["ip"], "Open Ports": r["ports_str"], "Last Scanned": r["last_scanned"]} for r in port_rows]
        zf.writestr(f"port_exposure_{ts}.xlsx", generate_excel(port_export, "port_exposure_report").body)
        zf.writestr(f"port_exposure_{ts}.pdf", generate_pdf(port_export, "Port Exposure Report", "port_exposure_report", orientation='L').body)

        # --- 3. Email Security ---
        email_rows, _ = _get_email_security_data(session, user, for_export=True)
        email_export = [{"Domain": r["domain"], "Status": r["overall_status"], "SPF Present": r["spf"]["present"], "SPF Status": r["spf"]["status"], "DMARC Present": r["dmarc"]["present"], "DMARC Policy": r["dmarc"].get("policy", "none")} for r in email_rows]
        zf.writestr(f"email_security_{ts}.xlsx", generate_excel(email_export, "email_security_report").body)
        zf.writestr(f"email_security_{ts}.pdf", generate_pdf(email_export, "Email Security Report", "email_security_report").body)

        # --- 4. Technology Drift ---
        drift_events, _ = _get_tech_drift_data(session, user, for_export=True)
        drift_export = [{"Timestamp": e["time"], "Domain": e["domain"], "Change": e["type"], "Technology": e["tech"]} for e in drift_events]
        zf.writestr(f"tech_drift_{ts}.xlsx", generate_excel(drift_export, "technology_drift_report").body)
        zf.writestr(f"tech_drift_{ts}.pdf", generate_pdf(drift_export, "Technology Drift Report", "tech_drift_report").body)

        # --- 5. Certificate Timeline ---
        cert_events, _ = _get_cert_timeline_data(session, user, for_export=True)
        cert_export = [{"Domain": e["domain"], "Issued On": e["issued_display"], "Issuer": e["issuer"], "Expires On": e["expires_display"], "Days Valid": e["days_valid"]} for e in cert_events]
        zf.writestr(f"cert_timeline_{ts}.xlsx", generate_excel(cert_export, "certificate_timeline_report").body)
        zf.writestr(f"cert_timeline_{ts}.pdf", generate_pdf(cert_export, "Certificate Timeline Report", "cert_timeline_report").body)

        # --- 6. Cloud Assets ---
        cloud_items, _ = _get_cloud_data(session, user, for_export=True, status_filter=status_filter)
        cloud_export = [{"Domain": i["domain"], "Provider": i["provider"], "Bucket Name": i["bucket_name"], "Status": i["status"], "URL": i["url"]} for i in cloud_items]
        zf.writestr(f"cloud_assets_{ts}.xlsx", generate_excel(cloud_export, "cloud_assets_report").body)
        zf.writestr(f"cloud_assets_{ts}.pdf", generate_pdf(cloud_export, "Cloud Assets Report", "cloud_assets_report").body)

        # --- 7. Attack Surface Reduction ---
        asr_items, _ = _get_asr_data(session, user, for_export=True, status_filter=status_filter)
        asr_export = [{"Domain": i["domain"], "Issue Type": i["type"], "Details": i["issue"], "Recommendation": i["recommendation"], "Severity": i["severity"].upper()} for i in asr_items]
        zf.writestr(f"attack_surface_{ts}.xlsx", generate_excel(asr_export, "asr_report").body)
        zf.writestr(f"attack_surface_{ts}.pdf", generate_pdf(asr_export, "Attack Surface Reduction Report", "asr_report").body)

        # --- 8. Sensitive Data / Secrets ---
        secrets_findings, _ = _get_secrets_data(session, user, for_export=True, status_filter=status_filter)
        secrets_export = []
        for f in secrets_findings.get("credentials", []):
            secrets_export.append({"Type": "Credential", "Name": f["name"], "Domain": f["target_domain"], "Severity": "High", "Scanner": f["scanner"]})
        for f in secrets_findings.get("configs", []):
            secrets_export.append({"Type": "Configuration", "Name": f["name"], "Domain": f["target_domain"], "Severity": f.get("severity", "Unknown"), "Scanner": f["scanner"]})
        zf.writestr(f"sensitive_data_{ts}.xlsx", generate_excel(secrets_export, "secrets_audit_report").body)
        zf.writestr(f"sensitive_data_{ts}.pdf", generate_pdf(secrets_export, "Sensitive Data Report", "secrets_audit_report").body)

        # --- 9. Broken Link Hijacking ---
        hijacking_items = _get_hijacking_data(session, user, status_filter=status_filter)
        hijacking_export = [{"Target Domain": i["target_domain"], "Broken Link": i["broken_link"], "Detected At": i["detected_at"]} for i in hijacking_items]
        zf.writestr(f"broken_link_hijacking_{ts}.xlsx", generate_excel(hijacking_export, "broken_link_hijacking_report").body)
        zf.writestr(f"broken_link_hijacking_{ts}.pdf", generate_pdf(hijacking_export, "Broken Link Hijacking Report", "broken_link_hijacking_report").body)

        # --- 10. HTTP Traffic (after hijacking) ---
        traffic_query = select(HTTPTraffic).join(Target)
        if user.tenant_id:
            traffic_query = traffic_query.where(Target.tenant_id == user.tenant_id)
        elif user.role != "admin":
            traffic_query = traffic_query.where(Target.tenant_id == None)
        traffic = session.exec(traffic_query.order_by(HTTPTraffic.timestamp.desc())).all()
        zf.writestr(f"http_traffic_{ts}.xlsx", _gen_traffic_excel(traffic, "tenant_http_traffic").body)
        zf.writestr(f"http_traffic_{ts}.pdf", _gen_traffic_pdf(traffic, "Tenant Infrastructure", "tenant_http_traffic").body)

        # --- 10. Infrastructure PDF (Analytics) ---
        infra_data = _get_infrastructure_data(session, user)
        from yads.models import AIAnalysisResult
        ai_analysis = None
        stored = session.exec(
            select(AIAnalysisResult).where(AIAnalysisResult.tenant_id == user.tenant_id).order_by(AIAnalysisResult.created_at.desc())
        ).first()
        if stored:
            import json as _json
            ai_analysis = {
                "risk_rating": stored.risk_rating,
                "risk_score": stored.risk_score,
                "executive_summary": stored.executive_summary,
                "key_findings": _json.loads(stored.key_findings or "[]"),
                "recommendations": _json.loads(stored.recommendations or "[]"),
            }
        tenant_name = "Global"
        if user.tenant_id:
            from yads.models import Tenant
            t = session.get(Tenant, user.tenant_id)
            if t:
                tenant_name = t.name
        infra_pdf = generate_infrastructure_report(infra_data, tenant_name, ai_analysis=ai_analysis)
        zf.writestr(f"infrastructure_executive_{ts}.pdf", bytes(infra_pdf))

        # --- 11. External Links PDF ---
        scope_count, ext_links_list, ext_tenant_name = _get_external_links_data(session, user, status_filter=status_filter)
        ext_pdf = generate_external_links_report(scope_count, ext_links_list, ext_tenant_name)
        zf.writestr(f"external_links_{ts}.pdf", bytes(ext_pdf))

    buf.seek(0)
    filename = f"yads_full_export_{ts}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


def _targets_csv(data) -> bytes:
    """Helper to generate CSV bytes from targets export data."""
    output = io.StringIO()
    writer = csv.writer(output)
    if data:
        writer.writerow(list(data[0].keys()))
        for row in data:
            writer.writerow(list(row.values()))
    return output.getvalue().encode("utf-8")

