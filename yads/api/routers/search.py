from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, select, or_, text
from yads.database import get_session
from yads.core.module_registry import REGISTRY, CATEGORIES
from yads.models import Target, ScanResult, User
from yads.auth.deps import get_current_user_html
from yads.config import settings

router = APIRouter(prefix="/api/search", tags=["search"])

@router.get("/suggestions")
async def get_search_suggestions(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    """
    Returns a dynamic list of search suggestions/commands for Ctrl+K.
    Groups: Suggetions, Actions (>), Navigation (@), Triage (!), Management (/)
    """
    suggestions = [
        # --- 💡 Suggestions ---
        { "group": "Suggestions", "prefix": "", "title": ">scan profile=dashboard", "desc": "Trigger standard scan queue", "hint": "Action", "url": "/queue" },
        { "group": "Suggestions", "prefix": "", "title": "@global-search", "desc": "Search targets & IPs", "hint": "Search", "url": "/search?q=" },
        { "group": "Suggestions", "prefix": "", "title": "!critical !new", "desc": "View critical incidents", "hint": "Filter", "url": "/security-findings?severity=critical" },

        # --- 🚀 Actions (>) ---
        { "prefix": ">", "title": "Start Active Campaign", "desc": "Manage and execute scan campaigns", "hint": "Execute", "url": "/targets/table", "icon": "M13 10V3L4 14h7v7l9-11h-7z" },
        { "prefix": ">", "title": "System Logs", "desc": "Unified infrastructure and worker logs", "hint": "System", "url": "/logs", "icon": "M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" },
        { "prefix": ">", "title": "Export Latest PDF", "desc": "Jump to report downloads", "hint": "Export", "url": "/reports", "icon": "M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" },
        { "prefix": ">", "title": "Operations Center", "desc": "Infrastructure health and worker status", "hint": "Ops", "url": "/system/health", "icon": "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" },
        { "prefix": ">", "title": "Active Queue & Jobs", "desc": "Real-time task processing status", "hint": "Queue", "url": "/queue", "icon": "M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" },
    ]

    # --- 🎯 Navigation (@) - Static Pages ---
    pages = [
        { "title": "Asset Intelligence", "url": "/discovery", "hint": "Asset", "icon": "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" },
        { "title": "Attack Surface", "url": "/attack-surface/", "hint": "Recon", "icon": "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m-9 9a9 9 0 019-9" },
        { "title": "Cloud Assets", "url": "/cloud-assets", "hint": "Cloud", "icon": "M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" },
        { "title": "OSINT & Brand", "url": "/osint", "hint": "Brand", "icon": "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" },
        { "title": "PQC Readiness", "url": "/pqc", "hint": "Crypto", "icon": "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
        { "title": "SSL Inventory", "url": "/cert-timeline/inventory", "hint": "Cert", "icon": "M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" },
        { "title": "Network Spiderweb", "url": "/visualizations/network-graph", "hint": "Graph", "icon": "M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" },
        { "title": "Analytics Dashboard", "url": "/analytics", "hint": "Data", "icon": "M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" },
        { "title": "Report Hub", "url": "/reports", "hint": "Reports", "icon": "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" },
        { "title": "AI Intelligence", "url": "/ai-assistant", "hint": "AI", "icon": "M13 10V3L4 14h7v7l9-11h-7z" },
    ]
    for p in pages:
        suggestions.append({ "prefix": "@", **p })

    # --- 🎯 Navigation (@) - Dynamic Addons (Modules) ---
    for name, defn in REGISTRY.items():
        suggestions.append({
            "prefix": "@",
            "title": f"Add-on: {defn.label}",
            "desc": f"Scanner module: {defn.worker_note or ''}",
            "hint": "Addon",
            "url": defn.get_report_url(),
            "icon": "M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z"
        })

    # --- ⚠️ Triage (!) ---
    triage = [
        { "title": "Unified Findings", "desc": "Complete list of security findings", "hint": "Findings", "url": "/security-findings", "icon": "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
        { "title": "High Severity Findings", "desc": "Show findings CVSS > 7.0", "hint": "Filter", "url": "/security-findings?severity=high", "icon": "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
        { "title": "Exposed Secrets", "desc": "Passwords and tokens in code", "hint": "Leak", "url": "/secrets", "icon": "M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" },
        { "title": "Cleanup Recommendations", "desc": "Attack surface reduction tips", "hint": "ASR", "url": "/asr", "icon": "M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" },
    ]
    for tr in triage:
        suggestions.append({ "prefix": "!", **tr })

    # --- ⚙️ Management (/) ---
    mgmt = [
        { "title": "Extension Hub", "desc": "Install and manage scanner modules", "hint": "Add-ons", "url": "/addons", "icon": "M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" },
        { "title": "User Settings", "desc": "Manage access and team members", "hint": "Users", "url": "/users", "icon": "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197" },
        { "title": "Tenant Settings", "desc": "Branding and global platform config", "hint": "Config", "url": "/tenant-settings", "icon": "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0" },
    ]
    for m in mgmt:
        suggestions.append({ "prefix": "/", **m })

    # --- 📄 Recent Reports (Dynamic) ---
    recent_reports = session.exec(
        select(ScanResult, Target.domain)
        .join(Target)
        .where(Target.tenant_id == user.tenant_id)
        .order_by(ScanResult.scanned_at.desc())
        .limit(10)
    ).all()
    
    for res, domain in recent_reports:
        suggestions.append({
            "prefix": "@",
            "title": f"Report: {domain} ({res.module_name})",
            "desc": f"Completed on {res.scanned_at.strftime('%Y-%m-%d')}",
            "hint": "Report",
            "url": f"/reports/module/{res.module_name}?target_id={res.target_id}",
            "icon": "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        })

    return suggestions

@router.get("")
async def global_search(
    q: str, 
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html)
):
    if not q or len(q) < 2:
        return {"targets": [], "findings": []}
        
    query = q.lower().strip()
    
    # 1. Search Targets (Domain match)
    targets_stmt = select(Target).where(
        Target.tenant_id == user.tenant_id,
        Target.domain.contains(query)
    ).limit(10)
    
    targets = session.exec(targets_stmt).all()
    target_results = [{"id": t.id, "domain": t.domain} for t in targets]
    
    # 2. Search Findings (Deep Search in JSONB)
    # This is heavy, limit to key modules
    # We use text-based search on the JSON column or specific keys
    
    findings = []
    
    # Postgres specific JSONB search would be better, but we strive for generic SQLModel or strings
    # Simple formatting: CAST(data AS TEXT) ILIKE %query%
    
    # modules to search
    modules = ["web_analyzer", "cve_scanner", "nuclei_scanner"]
    
    # We restrict to targets of this tenant
    # Subquery for target IDs?
    
    # Optimization: Only search recent results? Or search all?
    # Let's limit to 20 matches
    
    sql = text("""
        SELECT s.id, s.target_id, s.module_name, t.domain
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE t.tenant_id = :tenant_id
        AND s.module_name IN ('web_analyzer', 'cve_scanner', 'nuclei_scanner')
        AND CAST(s.data AS TEXT) ILIKE :query
        ORDER BY s.scanned_at DESC
        LIMIT 20
    """)
    
    raw_findings = session.exec(sql, params={"tenant_id": user.tenant_id, "query": f"%{query}%"}).all()
    
    for f in raw_findings:
        findings.append({
            "target_id": f[1],
            "module": f[2],
            "target": f[3]
        })
        
    return {
        "targets": target_results,
        "findings": findings
    }
