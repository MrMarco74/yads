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
    
    tenant_clause = ""
    params = {}
    
    if user.tenant_id:
        tenant_clause = "AND t.tenant_id = :tenant_id"
        params["tenant_id"] = user.tenant_id
    elif user.role == "admin":
        # Admin sees all tenants if no explicit context switch
        pass
    else:
        # Non-admin user without tenant? Valid?
        tenant_clause = "AND t.tenant_id IS NULL"

    query_str = f"""
        SELECT DISTINCT ON (s.target_id, s.module_name) 
            s.target_id, s.module_name, s.data, s.scanned_at 
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE s.module_name IN ('infrastructure_scanner', 'web_analyzer', 'tld_scanner', 'cve_scanner', 'dns_scanner', 'subdomain_scanner', 'port_scanner')
          {tenant_clause}
        ORDER BY s.target_id, s.module_name, s.scanned_at DESC
    """
    
    results = session.exec(text(query_str), params=params).all()
    
    # Pre-fetch Targets for name lookup
    target_statement = select(Target)
    if user.tenant_id:
        target_statement = target_statement.where(Target.tenant_id == user.tenant_id)
    # If admin and no tenant_id, fetch all
    elif user.role != "admin":
        target_statement = target_statement.where(Target.tenant_id == None)
        
    targets = session.exec(target_statement).all()
    target_map = {t.id: t.domain for t in targets}
    
    # Data Containers
    cloud_providers = {}  # {ProviderName: Count}
    cloud_details = []    # List of {target, provider, ip}
    
    status_codes = {}     # {Code: Count}
    countries = {}        # {CountryCode: Count}
    geo_stats = {}        # {Country: {City: Count}}
    
    tech_stack = {}       # {TechName: Count}
    tech_details = []     # List of {target, technologies, server_header}
    
    vuln_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_feed = []        # List of {severity, type, title, desc, target_id}
    
    vulnerabilities = []  # List of CVEs
    
    attack_surface_stats = [] # List of {target, count}
    service_distribution_stats = {"HTTP Only": 0, "HTTPS Only": 0, "Both": 0, "None": 0}
    
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
            city = data.get("geoip", {}).get("city") or "Unknown"

            if country != "Unknown":
                countries[country] = countries.get(country, 0) + 1
                
                # Data structure: {Country: {City: {count: N, lat: X, lon: Y}}}
                if country not in geo_stats:
                    geo_stats[country] = {}
                
                if city not in geo_stats[country]:
                     # Initialize
                     geo_stats[country][city] = {
                         'count': 0, 
                         'lat': data.get("geoip", {}).get("lat", 0),
                         'lon': data.get("geoip", {}).get("lon", 0)
                     }
                
                geo_stats[country][city]['count'] += 1
            
            # Debug Log
            # print(f"DEBUG GEO: {country} -> {city}")


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
        
        # --- DNS & Subdomain Scanners ---
        elif mod in ['dns_scanner', 'subdomain_scanner']:
            count = len(data.get("subdomains", []))
            if count > 0:
                attack_surface_stats.append({"target": t_name, "count": count})
                
        # --- Port Scanner ---
        elif mod == 'port_scanner':
            http_open = data.get("http", {}).get("open", False)
            https_open = data.get("https", {}).get("open", False)
            
            if http_open and https_open:
                service_distribution_stats["Both"] += 1
            elif http_open:
                service_distribution_stats["HTTP Only"] += 1
            elif https_open:
                service_distribution_stats["HTTPS Only"] += 1
            else:
                service_distribution_stats["None"] += 1
    
    # Sort Risk Feed by Severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    risk_feed.sort(key=lambda x: severity_order.get(x["severity"], 99))
    
    # Sort Attack Surface Stats (Top 10)
    attack_surface_stats.sort(key=lambda x: x["count"], reverse=True)
    attack_surface_stats = attack_surface_stats[:10]
    
    return {
        "cloud_providers": cloud_providers,
        "cloud_details": cloud_details,
        "status_codes": status_codes,
        "countries": countries,
        "tech_stack": tech_stack,
        "tech_details": tech_details,
        "vuln_stats": vuln_stats,
        "risk_feed": risk_feed[:10], # Top 10 risks
        "vulnerabilities": vulnerabilities,
        "attack_surface_stats": attack_surface_stats,
        "service_distribution_stats": service_distribution_stats,
        "geo_stats": geo_stats
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
    tenant_clause = ""
    params = {}
    
    if user.tenant_id:
        tenant_clause = "AND t.tenant_id = :tenant_id"
        params["tenant_id"] = user.tenant_id
    elif user.role == "admin":
        pass
    else:
        tenant_clause = "AND t.tenant_id IS NULL"

    query_str = f"""
        SELECT DISTINCT ON (s.target_id, s.module_name) 
            s.target_id, s.module_name, s.data 
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE s.module_name IN ('ssl_scanner', 'infrastructure_scanner', 'web_analyzer')
          {tenant_clause}
        ORDER BY s.target_id, s.module_name, s.scanned_at DESC
    """
    results = session.exec(text(query_str), params=params).all()
    
    target_statement = select(Target)
    if user.tenant_id:
        target_statement = target_statement.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_statement = target_statement.where(Target.tenant_id == None)
        
    targets = session.exec(target_statement).all()
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

@router.get("/best-entrypoint")
async def get_best_entrypoint(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Analyzes all targets (tenant-scoped) to find the best entrypoint based on findings.
    """
    # Tenant Scope
    query = select(Target)
    if user.tenant_id:
        query = query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin": 
        # Non-admin without tenant seeing only unassigned? Or restricted.
        # Platform Admin (admin + no tenant) can see all.
        query = query.where(Target.tenant_id == None)

    targets = session.exec(query).all()
    
    if not targets:
        return {"error": "No targets found"}

    scored_targets = []

    for t in targets:
        score = 0
        reasons = []

        # Get latest results
        # Optimization: Fetch all results for these targets in one go? 
        # Keeping original logic for low risk migration, but adding safety.
        results = session.exec(select(ScanResult).where(ScanResult.target_id == t.id).order_by(ScanResult.scanned_at.desc())).all()
        
        # Subdomains (+1 each)
        dns = next((r for r in results if r.module_name in ['subdomain_scanner', 'dns_scanner']), None)
        if dns and dns.data:
            subs = dns.data.get("subdomains", [])
            sub_count = len(subs)
            if sub_count > 0:
                points = sub_count * 1
                score += points
                reasons.append(f"+{points} from {sub_count} subdomains")

        # Web Tech (+2 each)
        web = next((r for r in results if r.module_name == 'web_analyzer'), None)
        if web and web.data:
            techs = web.data.get("technologies", [])
            tech_count = len(techs)
            if tech_count > 0:
                points = tech_count * 2
                score += points
                reasons.append(f"+{points} from {tech_count} detected technologies")

        # Cloud Buckets (+5 each)
        infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
        if infra and infra.data:
            buckets = infra.data.get("buckets", [])
            bucket_count = len(buckets)
            if bucket_count > 0:
                points = bucket_count * 5
                score += points
                reasons.append(f"+{points} from {bucket_count} exposed storage buckets")

        # SSL Issues (+3 if expired/error)
        ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
        if ssl and ssl.data:
            if ssl.data.get("error") or ssl.data.get("expired"): 
                points = 3
                score += points
                reasons.append(f"+{points} from SSL configuration issues")

        if score > 0:
            scored_targets.append({
                "target": t.domain,
                "target_id": t.id,
                "score": score,
                "reasons": reasons
            })

    if not scored_targets:
        return {"message": "No suitable entrypoints found yet. Run more scans."}

    # Sort by score desc
    scored_targets.sort(key=lambda x: x["score"], reverse=True)
    
    return {
        "best_target": scored_targets[0],
        "all_scores": scored_targets[:5]
    }
