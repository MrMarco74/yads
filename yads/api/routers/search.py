from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, select, or_, text
from yads.database import get_session
from yads.core.module_registry import REGISTRY, CATEGORIES
from yads.models import Target, ScanResult, User, ChangelogEntry, DiscoveryCandidate, DiscoverySession
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
        # Reconnaissance & Discovery
        { "title": "Asset Intelligence", "url": "/discovery", "hint": "Asset", "icon": "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" },
        { "title": "Discovery Blocklist", "url": "/discovery/blocklist", "hint": "Blocklist", "icon": "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" },
        { "title": "Attack Surface", "url": "/attack-surface/", "hint": "Recon", "icon": "M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m-9 9a9 9 0 019-9" },
        { "title": "Attack Path Analysis", "url": "/attack-path", "hint": "Recon", "icon": "M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" },
        { "title": "Cloud Assets", "url": "/cloud-assets", "hint": "Cloud", "icon": "M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" },
        { "title": "OSINT & Brand", "url": "/osint", "hint": "Brand", "icon": "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" },
        { "title": "Leak Monitor", "url": "/leak-monitor", "hint": "Leak", "icon": "M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" },
        # Scanning & Intelligence
        { "title": "SSL Certificate Timeline", "url": "/cert-timeline", "hint": "Cert", "icon": "M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" },
        { "title": "SSL Inventory", "url": "/cert-timeline/inventory", "hint": "Cert", "icon": "M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" },
        { "title": "Port Overview", "url": "/ports", "hint": "Network", "icon": "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" },
        { "title": "Tech Stack", "url": "/tech-stack", "hint": "Tech", "icon": "M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" },
        { "title": "Tech Drift", "url": "/tech-drift", "hint": "Tech", "icon": "M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" },
        { "title": "WAF Analysis", "url": "/waf-analysis", "hint": "WAF", "icon": "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
        { "title": "Email Security", "url": "/email-security", "hint": "Email", "icon": "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" },
        { "title": "WHOIS History", "url": "/whois-history", "hint": "WHOIS", "icon": "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" },
        { "title": "Cloud Storage", "url": "/storage", "hint": "Cloud", "icon": "M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" },
        { "title": "PQC Readiness", "url": "/pqc", "hint": "Crypto", "icon": "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
        { "title": "Compliance", "url": "/compliance", "hint": "Compliance", "icon": "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" },
        # Visualization & Analytics
        { "title": "Network Spiderweb", "url": "/visualizations/network-graph", "hint": "Graph", "icon": "M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" },
        { "title": "Target Graph", "url": "/targets/graph", "hint": "Graph", "icon": "M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" },
        { "title": "Scan Compare", "url": "/scan-compare/", "hint": "Diff", "icon": "M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" },
        { "title": "Analytics Dashboard", "url": "/analytics", "hint": "Data", "icon": "M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" },
        { "title": "Executive Report", "url": "/executive-report", "hint": "Report", "icon": "M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" },
        # Reports & Export
        { "title": "Report Hub", "url": "/reports", "hint": "Reports", "icon": "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" },
        { "title": "Report Builder", "url": "/reports/builder", "hint": "Reports", "icon": "M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" },
        # AI
        { "title": "AI Intelligence", "url": "/ai-assistant", "hint": "AI", "icon": "M13 10V3L4 14h7v7l9-11h-7z" },
        # Infrastructure
        { "title": "Worker Monitor", "url": "/workers", "hint": "Infra", "icon": "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" },
        { "title": "Scanner Import", "url": "/scanner-import", "hint": "Import", "icon": "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" },
        { "title": "Tags", "url": "/tags", "hint": "Tags", "icon": "M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" },
        { "title": "Integrations", "url": "/integrations", "hint": "Config", "icon": "M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z" },
        { "title": "Changelog", "url": "/changes/", "hint": "Info", "icon": "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" },
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
        { "title": "Critical Findings", "desc": "Nur kritische Findings anzeigen", "hint": "Filter", "url": "/security-findings?severity=critical", "icon": "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
        { "title": "High Severity Findings", "desc": "Show findings CVSS > 7.0", "hint": "Filter", "url": "/security-findings?severity=high", "icon": "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
        { "title": "Overdue Findings", "desc": "Findings deren SLA überschritten ist", "hint": "SLA", "url": "/tenant-settings/findings?overdue=1", "icon": "M12 8v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" },
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
        { "title": "Findings verwalten", "desc": "Alle Security Findings filtern, exportieren und bearbeiten", "hint": "Findings", "url": "/tenant-settings/findings", "icon": "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" },
        { "title": "Scan Profiles", "desc": "Scan-Profile erstellen und verwalten", "hint": "Config", "url": "/scan-profiles", "icon": "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" },
        { "title": "Schedules", "desc": "Automatische Scan-Zeitpläne", "hint": "Config", "url": "/schedules", "icon": "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" },
        { "title": "System Settings", "desc": "Globale Plattform-Konfiguration", "hint": "Config", "url": "/settings", "icon": "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0" },
        { "title": "Tenants", "desc": "Mandanten und Tenant-Verwaltung", "hint": "Admin", "url": "/tenants", "icon": "M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" },
        { "title": "Notifications", "desc": "Admin-Benachrichtigungen verwalten", "hint": "Admin", "url": "/notifications/admin", "icon": "M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" },
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

    # 3. Search Tags (#38): Target.tags is a JSONB list, no dedicated Tag
    # table — match targets whose tag list contains a tag matching the query.
    tags_sql = text("""
        SELECT id, domain, tags FROM target
        WHERE tenant_id = :tenant_id
        AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(tags) AS tag WHERE tag ILIKE :query)
        LIMIT 10
    """)
    tag_matches = session.exec(tags_sql, params={"tenant_id": user.tenant_id, "query": f"%{query}%"}).all()
    tags = [{"target_id": t[0], "domain": t[1], "tags": t[2]} for t in tag_matches]

    # 4. Search Discovery Candidates (#38)
    disc_stmt = (
        select(DiscoveryCandidate.id, DiscoveryCandidate.domain, DiscoveryCandidate.session_id, DiscoveryCandidate.status)
        .join(DiscoverySession, DiscoveryCandidate.session_id == DiscoverySession.id)
        .where(DiscoverySession.tenant_id == user.tenant_id, DiscoveryCandidate.domain.contains(query))
        .limit(10)
    )
    discovery_candidates = [
        {"id": r[0], "domain": r[1], "session_id": r[2], "status": r[3]}
        for r in session.exec(disc_stmt).all()
    ]

    # 5. Search Changelog Entries (#38) — platform-wide, not tenant-scoped
    changelog_stmt = select(ChangelogEntry).where(
        or_(ChangelogEntry.title.contains(query), ChangelogEntry.content.contains(query))
    ).order_by(ChangelogEntry.published_at.desc()).limit(10)
    changelog = [
        {"id": c.id, "title": c.title, "version": c.version, "published_at": c.published_at.isoformat()}
        for c in session.exec(changelog_stmt).all()
    ]

    return {
        "targets": target_results,
        "findings": findings,
        "tags": tags,
        "discovery_candidates": discovery_candidates,
        "changelog": changelog,
    }
