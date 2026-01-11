from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func, text
from typing import Dict, List, Any
from datetime import datetime
from yads.database import engine
from yads.database import engine
from yads.models import Target, ScanResult, User
from yads.auth.deps import get_current_active_user

router = APIRouter(prefix="/api/stats", tags=["analytics"])

def get_session():
    with Session(engine) as session:
        yield session

@router.get("/infrastructure")
async def get_infrastructure_stats(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Aggregates infrastructure data for the Analytics Dashboard.
    Includes:
    - Cloud Provider Distribution (Pie)
    - Status Code Distribution (Bar)
    - Geo Location (Map)
    - Tech Stack (Bar)
    - Vulnerability Stats (Bar)
    - Critical Risk Feed (Table)
    """
    
    # 1. Fetch relevant scan results
    # We want the LATEST result for each module per target.
    # For efficiency, we might just query all and process in python for small datasets (<1000).
    # Or use DISTINCT ON in Postgres.
    
    # Let's fetch all scan results for active modules
    # Ideally filtering by "latest" per target/module.
    
    query = text("""
        SELECT DISTINCT ON (s.target_id, s.module_name) 
            s.target_id, s.module_name, s.data, s.scanned_at 
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE s.module_name IN ('infrastructure_scanner', 'web_analyzer', 'tld_scanner', 'cve_scanner')
          AND t.tenant_id = :tenant_id
        ORDER BY s.target_id, s.module_name, s.scanned_at DESC
    """)
    
    results = session.exec(query, params={"tenant_id": user.tenant_id}).all()
    
    # Pre-fetch Targets for name lookup (Tenant Scoped)
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id)).all()
    target_map = {t.id: t.domain for t in targets}
    
    # Data Containers
    cloud_providers = {}  # {ProviderName: Count}
    cloud_details = []    # List of {target, provider, ip}
    
    status_codes = {}     # {Code: Count}
    countries = {}        # {CountryCode: Count}
    
    tech_stack = {}       # {TechName: Count}
    tech_details = []     # List of {target, technologies, server_header}
    
    vuln_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_feed = []        # List of {severity, type, title, desc, target_id}
    
    vulnerabilities = []  # List of CVEs
    
    for row in results:
        # row is a tuple/object with accessors? SQLModel result usually row objects if mapped.
        # But we used raw text query, so it returns tuples (target_id, module_name, data, scanned_at)
        tid, mod, data, ts = row
        t_name = target_map.get(tid, f"Target #{tid}")
        
        if not data: continue
        
        # --- Infrastructure Scanner ---
        if mod == 'infrastructure_scanner':
            # Cloud Provider
            provider = data.get("cloud_provider") or "Unknown"
            # Cleanup synonyms (e.g. Amazon.com vs AWS)
            # Simple normalization
            if "amazon" in provider.lower(): provider = "AWS"
            elif "google" in provider.lower(): provider = "GCP"
            elif "microsoft" in provider.lower() or "azure" in provider.lower(): provider = "Azure"
            elif "cloudflare" in provider.lower(): provider = "Cloudflare"
            elif "hetzner" in provider.lower(): provider = "Hetzner"
            
            cloud_providers[provider] = cloud_providers.get(provider, 0) + 1
            
            ip = data.get("ip")
            
            # Add to details list (Include Unknowns and those without IPs if provider is detected)
            cloud_details.append({
                "id": tid,
                "target": t_name,
                "provider": provider,
                "ip": ip or "N/A"
            })
                
            # Geo
            country = data.get("geoip", {}).get("country_name") or "Unknown"
            if country != "Unknown":
                countries[country] = countries.get(country, 0) + 1

        # --- Web Analyzer ---
        elif mod == 'web_analyzer':
            # Status Codes
            code = str(data.get("status_code", 0))
            if code != "0":
                status_codes[code] = status_codes.get(code, 0) + 1
            
            # Tech Stack
            techs = data.get("tech_stack", [])
            for tech in techs:
                tech_stack[tech] = tech_stack.get(tech, 0) + 1
                
            server = data.get("http_headers", {}).get("Server")
            if server:
                # server often has version "Apache/2.4.41", sanitize to "Apache"
                srv_name = server.split('/')[0]
                tech_stack[srv_name] = tech_stack.get(srv_name, 0) + 1
            
            tech_details.append({
                "id": tid,
                "target": t_name,
                "technologies": techs,
                "server_header": server
            })
            
            # CVEs within Web Analyzer result?
            cves = data.get("cves", [])
            for cve in cves:
                # Add to Vulnerabilities List (aggregated)
                severity = "LOW"
                try: 
                    score = float(cve.get("cvss", 0))
                    if score >= 9.0: severity = "CRITICAL"
                    elif score >= 7.0: severity = "HIGH"
                    elif score >= 4.0: severity = "MEDIUM"
                except: pass
                
                vulnerabilities.append({
                    "target": t_name,
                    "target_id": tid,
                    "id": cve.get("id"),
                    "description": cve.get("description"),
                    "severity": severity,
                    "product": cve.get("package_name") or "Web"
                })
                
                # Stats
                vuln_stats[severity.lower()] += 1
                
                # Risk Feed (Only High/Crit)
                if severity in ["CRITICAL", "HIGH"]:
                    risk_feed.append({
                        "severity": severity.title(),
                        "type": "CVE",
                        "title": cve.get("id"),
                        "desc": cve.get("description"),
                        "target_id": tid
                    })

            # Secrets
            secrets = data.get("secrets", [])
            if secrets:
                risk_feed.append({
                    "severity": "Critical",
                    "type": "Secret Leak",
                    "title": f"{len(secrets)} Secrets Found",
                    "desc": f"Exposed tokens/keys in {t_name}",
                    "target_id": tid
                })
    
    # Sort Risk Feed by Severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    risk_feed.sort(key=lambda x: severity_order.get(x["severity"], 99))
    
    return {
        "cloud_providers": cloud_providers,
        "cloud_details": cloud_details,
        "status_codes": status_codes,
        "countries": countries,
        "tech_stack": tech_stack,
        "tech_details": tech_details,
        "vuln_stats": vuln_stats,
        "risk_feed": risk_feed[:10], # Top 10 risks
        "vulnerabilities": vulnerabilities
    }

@router.get("/security-risks")
async def get_security_risks(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Aggregates security risks for visualizations:
    - SSL Expiry Timeline
    - Reputation Monitor (Blacklists)
    - Open Buckets
    - Secrets Leaks
    - Vulnerabilities (Detailed Table)
    """
    query = text("""
        SELECT DISTINCT ON (s.target_id, s.module_name) 
            s.target_id, s.module_name, s.data 
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE s.module_name IN ('ssl_scanner', 'infrastructure_scanner', 'web_analyzer')
          AND t.tenant_id = :tenant_id
        ORDER BY s.target_id, s.module_name, s.scanned_at DESC
    """)
    results = session.exec(query, params={"tenant_id": user.tenant_id}).all()
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id)).all()
    target_map = {t.id: t.domain for t in targets}
    
    ssl_timeline = []
    reputation_issues = []
    open_buckets = []
    secrets_leaks = []
    vulnerabilities = []
    
    for row in results:
        tid, mod, data = row
        t_name = target_map.get(tid, f"Target #{tid}")
        if not data: continue
        
        if mod == 'ssl_scanner':
            not_after = data.get("notAfter")
            if not_after:
                try:
                    # Clean up multiple spaces
                    clean_date = " ".join(not_after.split()) 
                    # Try common formats
                    dt = None
                    for fmt in ["%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                        try:
                            dt = datetime.strptime(clean_date, fmt)
                            break
                        except: continue
                    
                    if dt:
                        days_left = (dt - datetime.utcnow()).days
                        status = "ok"
                        if days_left < 0: status = "expired"
                        elif days_left < 7: status = "critical"
                        elif days_left < 30: status = "warning"
                        
                        ssl_timeline.append({
                            "target": t_name,
                            "target_id": tid,
                            "days_left": days_left,
                            "expiry_date": dt.strftime("%Y-%m-%d"),
                            "status": status
                        })
                except: pass

        elif mod == 'infrastructure_scanner':
            # Buckets
            for bucket in data.get("buckets", []):
                if bucket.get("status") == "Public":
                    open_buckets.append({
                        "target": t_name,
                        "url": bucket.get("url"),
                        "code": bucket.get("code")
                    })
            # Reputation
            rep = data.get("reputation", [])
            if rep:
                 reputation_issues.append({
                    "target": t_name,
                    "ip": data.get("ip", "Unknown"),
                    "issues": rep
                })

        elif mod == 'web_analyzer':
            # Secrets
            secrets = data.get("secrets", [])
            if secrets:
                secrets_leaks.append({
                    "target": t_name,
                    "target_id": tid,
                    "count": len(secrets),
                    "secrets": secrets # list of {type, value, snippet}
                })
            
            # Vulnerabilities (Already in infra stats but also needed here for the dedicated table?)
            # The frontend calls security-risks for "features-vuln-container" table?
            # Checking analytics.html: 
            #   renderSecurityCharts -> data.vulnerabilities (line 570)
            # So yes, we need to supply vulnerabilities here too.
            cves = data.get("cves", [])
            for cve in cves:
                 severity = "LOW"
                 try: 
                    score = float(cve.get("cvss", 0))
                    if score >= 9.0: severity = "CRITICAL"
                    elif score >= 7.0: severity = "HIGH"
                    elif score >= 4.0: severity = "MEDIUM"
                 except: pass
                 
                 vulnerabilities.append({
                    "target": t_name,
                    "target_id": tid,
                    "id": cve.get("id"),
                    "description": cve.get("description"),
                    "severity": severity,
                    "product": cve.get("package_name")
                 })
    
    # Sort
    ssl_timeline.sort(key=lambda x: x["days_left"])
    
    return {
        "ssl_timeline": ssl_timeline,
        "reputation_issues": reputation_issues,
        "open_buckets": open_buckets,
        "secrets_leaks": secrets_leaks,
        "vulnerabilities": vulnerabilities
    }
