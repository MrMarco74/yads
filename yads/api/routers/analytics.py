from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlmodel import Session, select, func, text
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
from yads.database import engine
from yads.models import Target, ScanResult, User
from yads.auth.deps import get_current_active_user
from yads.config import settings
from yads.core.comparisons import ComparisonEngine
from yads.utils.license_deps import require_feature

router = APIRouter(prefix="/api/analytics", tags=["analytics"], dependencies=[Depends(require_feature("analytics"))])

def get_session():
    with Session(engine) as session:
        yield session

def _get_infrastructure_data(session: Session, user: User) -> Dict[str, Any]:
    """
    Helper to fetch and aggregate infrastructure data for a user context.
    Reuse this for the API endpoint and the PDF export.
    """
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

    # 1. Targets in Scope
    target_query = select(Target)
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)
        
    targets = session.exec(target_query).all()
    target_map = {t.id: t for t in targets}
    target_ids = list(target_map.keys())
    
    if not target_ids:
        # Return empty structure if no targets
        return {
            "cloud_providers": {}, "cloud_details": [], "status_codes": {},
            "countries": {}, "tech_stack": {}, "tech_details": [],
            "vuln_stats": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "risk_feed": [], "vulnerabilities": [], "attack_surface_stats": [],
            "service_distribution_stats": {"HTTP Only": 0, "HTTPS Only": 0, "Both": 0, "None": 0},
            "geo_stats": {}
        }

    # 2. Results
    results = session.exec(select(ScanResult).where(
        ScanResult.module_name.in_(['infrastructure_scanner', 'web_analyzer', 'tld_scanner', 'cve_scanner', 'dns_scanner', 'subdomain_scanner', 'port_scanner']),
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.desc())).all()
    
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
    
    seen_results = set()
    
    for res in results:
        # Access ORM attributes
        tid = res.target_id
        mod = res.module_name
        data = res.data
        ts = res.scanned_at
        
        # Dedupe: (target_id, module_name)
        if (tid, mod) in seen_results:
            continue
        seen_results.add((tid, mod))
        
        t_name = target_map.get(tid) or f"Target #{tid}"
        
        if not data: continue
        
        # Defensive JSON parsing for SQLite compatibility
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                data = {}

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
            geoip = data.get("geoip") or {}
            country = geoip.get("country_name") or "Unknown"
            city = geoip.get("city") or "Unknown"

            if country != "Unknown":
                countries[country] = countries.get(country, 0) + 1
                
                # Data structure: {Country: {City: {count: N, lat: X, lon: Y}}}
                if country not in geo_stats:
                    geo_stats[country] = {}
                
                if city not in geo_stats[country]:
                     # Initialize
                     geo_stats[country][city] = {
                         'count': 0, 
                         'lat': geoip.get("lat", 0),
                         'lon': geoip.get("lon", 0)
                     }
                
                geo_stats[country][city]['count'] += 1

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
                
            server = (data.get("http_headers") or {}).get("Server")
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
            count = len(data.get("subdomains") or [])
            if count > 0:
                attack_surface_stats.append({"target": t_name, "count": count})
                
        # --- Port Scanner ---
        elif mod == 'port_scanner':
            http_open = (data.get("http") or {}).get("open", False)
            https_open = (data.get("https") or {}).get("open", False)
            
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
    return _get_infrastructure_data(session, user)

@router.get("/trend/security")
async def get_security_trend(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns historical security trend data.
    """
    # 1. Scope
    target_ids = []
    if user.tenant_id:
        targets = session.exec(select(Target.id).where(Target.tenant_id == user.tenant_id)).all()
        target_ids = targets
    elif user.role != "admin":
        targets = session.exec(select(Target.id).where(Target.tenant_id == None)).all()
        target_ids = targets
    else:
        # Admin - fetch all for global trend
        targets = session.exec(select(Target.id)).all()
        target_ids = targets

    if not target_ids:
        return {"labels": [], "data": []}

    # 2. Fetch Historical Results (Infrastructure Scanner contains 'security_score')
    # Limit to last 30 days
    results = session.exec(select(ScanResult).where(
        ScanResult.module_name == 'infrastructure_scanner',
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.asc())).all()

    # 3. Aggregate by Date
    # { "YYYY-MM-DD": [score1, score2, ...] }
    daily_scores = {}
    
    for res in results:
        if not res.data: continue
        
        # Parse data
        data = res.data
        if isinstance(data, str):
            try: data = json.loads(data)
            except: continue
            
        score = data.get("security_score")
        if score is None: continue
        
        date_str = res.scanned_at.strftime("%Y-%m-%d")
        if date_str not in daily_scores:
            daily_scores[date_str] = []
        
        daily_scores[date_str].append(score)

    # 4. Calculate Average per Day
    labels = []
    data_points = []
    
    for date_str in sorted(daily_scores.keys()):
        scores = daily_scores[date_str]
        avg_score = sum(scores) / len(scores)
        labels.append(date_str)
        data_points.append(round(avg_score, 1))

    return {
        "labels": labels[-30:], # Last 30 entries
        "data": data_points[-30:] 
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
        SELECT s.target_id, s.module_name, s.data 
        FROM scanresult s
        JOIN target t ON s.target_id = t.id
        WHERE s.module_name IN ('ssl_scanner', 'infrastructure_scanner', 'web_analyzer')
          {tenant_clause}
        ORDER BY s.scanned_at DESC
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
    
    seen_results = set()

    for res in results:
        tid = res.target_id
        mod = res.module_name
        data = res.data
        
        if (tid, mod) in seen_results: continue
        seen_results.add((tid, mod))
        
        t_name = target_map.get(tid) or f"Target #{tid}"
        if not data: continue

        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                data = {}
        
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

def _get_hijacking_data(session: Session, user: User) -> List[Dict[str, Any]]:
    """
    Fetches targets with broken external links (potential hijacking).
    Rewritten for stability and robust error handling.
    """
    # 1. Scope Resolution
    stmt = select(Target)
    if user.tenant_id:
        stmt = stmt.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        stmt = stmt.where(Target.tenant_id == None)
        
    targets = session.exec(stmt).all()
    if not targets:
        return []
        
    target_map = {t.id: t for t in targets}
    target_ids = list(target_map.keys())

    # 2. Fetch Results (Web Analyzer only)
    # Using specific query to minimize data transfer
    results = session.exec(select(ScanResult).where(
        ScanResult.module_name == 'web_analyzer',
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.desc())).all()
    
    hijacking_candidates = []
    seen_targets = set()
    
    for res in results:
        # Deduplication: One result per target (latest)
        if res.target_id in seen_targets:
            continue
        seen_targets.add(res.target_id)
        
        # 3. Data Extraction with Strict Validation
        if not res.data:
            continue
            
        data = res.data
        # Handle SQLite JSON string issue
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                # Log error if needed, but safe continue
                continue
                
        if not isinstance(data, dict):
            continue

        # 4. Business Logic
        broken_links = data.get("broken_links")
        if not broken_links or not isinstance(broken_links, list):
            continue
            
        target = target_map.get(res.target_id)
        if not target:
            continue
            
        for link in broken_links:
            if not isinstance(link, str): continue
            
            hijacking_candidates.append({
                "target_id": res.target_id,
                "target_domain": target.domain,
                "broken_link": link,
                "detected_at": res.scanned_at.strftime("%Y-%m-%d") if res.scanned_at else "Unknown"
            })
                
    return hijacking_candidates

def _get_tech_radar_data(session: Session, user: User) -> Dict[str, Any]:
    """
    Aggregates technology stacks for the radar charts.
    Rewritten to be standalone and decoupled from infrastructure logic.
    """
    # 1. Scope Resolution
    stmt = select(Target)
    if user.tenant_id:
        stmt = stmt.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        stmt = stmt.where(Target.tenant_id == None)
        
    targets = session.exec(stmt).all()
    if not targets:
        # Return empty safe structure
        empty_chart = {"labels": [], "data": []}
        return {
            "all_tech": empty_chart, "servers": empty_chart,
            "frameworks": empty_chart, "cms": empty_chart,
            "total_targets": 0
        }
        
    target_ids = [t.id for t in targets]

    # 2. Fetch Results (Web Analyzer only)
    results = session.exec(select(ScanResult).where(
        ScanResult.module_name == 'web_analyzer',
        ScanResult.target_id.in_(target_ids)
    ).order_by(ScanResult.scanned_at.desc())).all()
    
    # 3. Aggregation Containers
    tech_stack: Dict[str, int] = {}
    servers: Dict[str, int] = {}
    frameworks: Dict[str, int] = {}
    cms: Dict[str, int] = {}
    
    seen_targets = set()
    
    # Heuristics
    server_names = ["Apache", "Nginx", "IIS", "Cloudflare", "LiteSpeed", "Caddy", "Express", "Tornado", "Gunicorn"]
    framework_names = ["React", "Vue", "Angular", "Django", "Flask", "Laravel", "Symfony", "Spring", "ASP.NET", "Next.js", "Nuxt"]
    cms_names = ["WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix", "Squarespace"]

    for res in results:
        # Deduplication
        if res.target_id in seen_targets:
            continue
        seen_targets.add(res.target_id)
        
        # 4. Data Extraction with Strict Validation
        if not res.data: continue
        
        data = res.data
        if isinstance(data, str):
            try: data = json.loads(data)
            except: continue
            
        if not isinstance(data, dict): continue
        
        # Extract Techs
        techs = data.get("tech_stack")
        if not techs or not isinstance(techs, list):
            # Fallback: maybe just server header?
            pass
        else:
            for tech in techs:
                if not isinstance(tech, str): continue
                tech_stack[tech] = tech_stack.get(tech, 0) + 1
                
                # Categorize
                found = False
                lower_tech = tech.lower()
                
                for s in server_names:
                    if s.lower() in lower_tech:
                        servers[s] = servers.get(s, 0) + 1
                        found = True
                        break
                
                if not found:
                    for f in framework_names:
                        if f.lower() in lower_tech:
                            frameworks[f] = frameworks.get(f, 0) + 1
                            found = True
                            break
                            
                if not found:
                    for c in cms_names:
                        if c.lower() in lower_tech:
                            cms[c] = cms.get(c, 0) + 1
                            break

        # Extract Server Header explicitly if not in stack
        server_header = (data.get("http_headers") or {}).get("Server")
        if server_header and isinstance(server_header, str):
             # Simple clean
             srv_name = server_header.split('/')[0]
             # Add to stats if not already counted via tech_stack? 
             # For simplicity, let's just add it to 'servers' if it matches known list
             # preventing double counting is hard without per-target accounting, but this is aggregate stats
             pass

    # 5. Format for Chart.js
    def format_chart(d: Dict[str, int]) -> Dict[str, List[Any]]:
        # Sort by count desc
        sorted_d = sorted(d.items(), key=lambda x: x[1], reverse=True)
        return {
            "labels": [k for k, v in sorted_d],
            "data": [v for k, v in sorted_d]
        }
        
    return {
        "all_tech": format_chart(tech_stack),
        "servers": format_chart(servers),
        "frameworks": format_chart(frameworks),
        "cms": format_chart(cms),
        "total_targets": len(seen_targets)
    }

@router.get("/hijacking")
async def get_hijacking_stats(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    return _get_hijacking_data(session, user)

@router.get("/tech-radar")
async def get_tech_radar_stats(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    return _get_tech_radar_data(session, user)



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

# -- UI Router --
ui_router = APIRouter(prefix="/analytics", dependencies=[Depends(require_feature("analytics"))])
templates = Jinja2Templates(directory="yads/api/templates")

# Inject Globals
templates.env.globals['settings'] = settings
from datetime import datetime
templates.env.globals['now_utc'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

# Custom Filters
def timestamp_to_time(value):
    if not value:
        return "-"
    try:
        dt = datetime.fromtimestamp(float(value))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(value)

templates.env.filters["timestamp_to_time"] = timestamp_to_time

# Helper for templates (needed for base.html)
def get_all_tenants():
    from sqlmodel import Session, select
    from yads.database import engine
    from yads.models import Tenant
    with Session(engine) as session:
        return session.exec(select(Tenant).order_by(Tenant.name)).all()

templates.env.globals['get_available_tenants'] = get_all_tenants
templates.env.globals['settings'] = settings


@ui_router.get("/hijacking", response_class=HTMLResponse)
async def view_hijacking(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    items = _get_hijacking_data(session, user)
    return templates.TemplateResponse("analytics_hijacking.html", {
        "request": request, 
        "user": user,
        "items": items,
        "settings": settings
    })

@ui_router.get("/tech-radar", response_class=HTMLResponse)
async def view_tech_radar(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    stats = _get_tech_radar_data(session, user)
    return templates.TemplateResponse("analytics_tech_radar.html", {
        "request": request,
        "user": user,
        "stats": stats,
        "settings": settings
    })


def _get_external_links_data(session: Session, user: User):
    """
    Helper to fetch and process external links data for given user context.
    Returns: (scope_count, final_list, tenant_name)
    """
    # 1. Define Scope (Tenant Targets)
    target_query = select(Target)
    tenant_name = "Global"
    
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
        if user.tenant:
             tenant_name = user.tenant.name
        else:
             # Fetch if lazy loading issue
             from yads.models import Tenant
             t = session.get(Tenant, user.tenant_id)
             if t: tenant_name = t.name
             
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)
        tenant_name = "Personal"
        
    targets = session.exec(target_query).all()
    scope_domains = set(t.domain for t in targets)
    target_map = {t.id: t.domain for t in targets}
    
    # 2. Collect Data
    # Fetch results from crawler and dns_scanner
    if not targets:
        return 0, [], tenant_name
        
        
    print(f"[DEBUG_EXT_LINKS] Fetching scan results for {len(targets)} targets...")
    # ORM Query (Safer than raw SQL string injection)
    statement = select(ScanResult.target_id, ScanResult.module_name, ScanResult.data).where(
        ScanResult.module_name.in_(['crawler', 'dns_scanner']),
        ScanResult.target_id.in_([t.id for t in targets])
    )
    results = session.exec(statement).all()
    print(f"[DEBUG_EXT_LINKS] Fetched {len(results)} scan results. Starting processing...")
        
    external_links = {} # {domain: {count: int, sources: set, types: set}}
    
    from urllib.parse import urlparse
    
    # Optimization: Use set for fast lookup of internal scopes
    # Check if domain or any of its parents are in scope
    def is_internal(domain):
        if domain in scope_domains:
            return True
        
        parts = domain.split('.')
        # Check all parent domains
        # e.g. sub.example.com -> check example.com
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in scope_domains:
                return True
        return False
    
    for idx, row in enumerate(results):
        tid, mod, data = row
        t_domain = target_map.get(tid)
        
        if not data: continue
        
        # Debug loop progress for large datasets
        # output every 100 rows
        if idx % 100 == 0:
             print(f"[DEBUG_EXT_LINKS] Processing row {idx}/{len(results)} (Module: {mod})")

        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                data = {}

        found_domains = []
        
        if mod == 'crawler':
            edges = data.get("edges", [])
            for edge in edges:
                dst = edge.get("target", "")
                try:
                    parsed = urlparse(dst)
                    if parsed.netloc:
                        # Strip port if present
                        d = parsed.netloc.split(':')[0]
                        if d: found_domains.append((d, "link"))
                except: pass
                
        elif mod == 'dns_scanner':
            records = data.get("records", {})
            # MX
            for mx in records.get("MX", []):
                # "10 mail.example.com"
                parts = mx.split()
                val = parts[-1] if parts else mx
                found_domains.append((val.rstrip('.'), "MX"))
            # NS
            for ns in records.get("NS", []):
                found_domains.append((ns.rstrip('.'), "NS"))
            # CNAME
            for cn in records.get("CNAME", []):
                found_domains.append((cn.rstrip('.'), "CNAME"))
                
        # Process Found
        for domain, link_type in found_domains:
            domain = domain.lower()
            if not is_internal(domain):
                if domain not in external_links:
                    external_links[domain] = {
                        "domain": domain,
                        "count": 0,
                        "sources": set(),
                        "types": set()
                    }
                
                external_links[domain]["count"] += 1
                external_links[domain]["sources"].add(t_domain)
                external_links[domain]["types"].add(link_type)
                
    # Convert sets to lists
    final_list = []
    for d, info in external_links.items():
        final_list.append({
            "domain": d,
            "count": info["count"],
            "sources": sorted(list(info["sources"])),
            "types": sorted(list(info["types"]))
        })
        
    # Sort by count desc
    final_list.sort(key=lambda x: x["count"], reverse=True)
    
    print(f"[DEBUG_EXT_LINKS] Finished processing. Returning {len(final_list)} external domains.")
    return len(scope_domains), final_list, tenant_name

@ui_router.get("/external-links", response_class=HTMLResponse)
async def view_external_links(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Renders the shell page for External Links. Data is loaded via HTMX.
    """
    # Just render the shell. Counters will be updated via OOB.
    return templates.TemplateResponse("analytics_external_links.html", {
        "request": request,
        "external_links": [], # Empty initially
        "user": user,
        "scope_count": "-", # Placeholder
        "settings": settings
    })

@ui_router.get("/external-links/rows", response_class=HTMLResponse)
async def get_external_links_rows(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    HTMX endpoint calculates heavy data and returns table rows + OOB counters.
    """
    try:
        scope_count, final_list, _ = _get_external_links_data(session, user)
        
        return templates.TemplateResponse("_external_links_rows.html", {
            "request": request,
            "external_links": final_list,
            "scope_count": scope_count
        })
    except Exception as e:
        import traceback
        error_msg = f"Error in get_external_links_rows: {str(e)}\n{traceback.format_exc()}"
        print(error_msg) # Print to stdout to ensure capture
        # return a safe error row
        return HTMLResponse(f"""
        <tr>
            <td colspan="4" class="px-6 py-12 text-center text-red-500">
                <p class="font-bold">Server Error</p>
                <p class="text-xs mt-2 text-left font-mono whitespace-pre-wrap bg-red-950/30 p-4 rounded">{error_msg}</p>
            </td>
        </tr>
        """)

@ui_router.get("/external-links/export")
async def export_external_links(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Exports the External Links report to PDF.
    """
    from fastapi.responses import Response
    from yads.modules.report_generator import generate_external_links_report
    
    scope_count, final_list, tenant_name = _get_external_links_data(session, user)
    
    pdf_bytes = generate_external_links_report(scope_count, final_list, tenant_name)
    
    return Response(content=bytes(pdf_bytes), media_type="application/pdf", headers={
        "Content-Disposition": 'attachment; filename="external_links_report.pdf"'
    })


def _get_dead_links_data(session: Session, user: User):
    """
    Helper to identify Dead (Unreachable) and Unlinked (Orphan) targets.
    """
    # 1. Tenant Scope
    target_query = select(Target)
    if user.tenant_id:
        target_query = target_query.where(Target.tenant_id == user.tenant_id)
    elif user.role != "admin":
        target_query = target_query.where(Target.tenant_id == None)
        
    targets = session.exec(target_query).all()
    targets_map = {t.id: t for t in targets}
    target_ids = set(targets_map.keys())
    
    dead_links = []
    
    # --- A. Unreachable Targets ---
    # Targets with latest web/infra scan indicating failure
    # We fetch latest web_analyzer results
    unreachable_ids = set()
    
    scan_stmt = select(ScanResult).where(
        ScanResult.target_id.in_(target_ids),
        ScanResult.module_name == 'web_analyzer'
    ).order_by(ScanResult.scanned_at.desc())
    
    # Efficient: Group by target in python or DISTINCT ON in SQL
    # DISTINCT ON is Postgres specific but supported by YADS stack
    from sqlalchemy import text
    # Let's use python loop for safety and detailed analysis
    results = session.exec(scan_stmt).all()
    processed_targets = set()
    
    for res in results:
        if res.target_id in processed_targets: continue
        processed_targets.add(res.target_id)
        
        # Check status
        if not res.data: continue
        
        data = res.data
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                data = {}
        
        status = data.get("status_code")
        
        is_dead = False
        details = ""
        
        if status == 0 or status is None:
            is_dead = True
            details = "No HTTP Response"
        elif str(status).startswith("5"):
            is_dead = True
            details = f"Server Error ({status})"
            
        if is_dead:
            unreachable_ids.add(res.target_id)
            dead_links.append({
                "id": res.target_id,
                "domain": targets_map[res.target_id].domain,
                "type": "unreachable",
                "details": details,
                "last_checked": res.scanned_at.strftime("%Y-%m-%d")
            })
            
    # --- B. Orphaned Targets ---
    # Targets that are NOT linked to by any other target in the system (within scope)
    # 1. Build set of ALL referenced domains from 'crawler' results of in-scope targets
    referenced_domains = set()
    
    crawler_results = session.exec(select(ScanResult).where(
        ScanResult.target_id.in_(target_ids),
        ScanResult.module_name == 'crawler'
    )).all()
    
    from urllib.parse import urlparse
    
    for res in crawler_results:
        # Get edges
        data = res.data or {}
        edges = data.get("edges", [])
        for edge in edges:
            dst = edge.get("target")
            if not dst: continue
            try:
                # Extract domain
                parsed = urlparse(dst)
                if parsed.netloc:
                     d = parsed.netloc.split(':')[0]
                     referenced_domains.add(d)
            except: pass
            
    # 2. Check each target if it is in referenced_domains
    unlinked_count = 0
    for tid, t in targets_map.items():
        if tid in unreachable_ids: continue # Don't double count if it's dead anyway (optional decision)
        
        # Check if domain or any subdomain variant is in referenced list?
        # Exact match for now
        if t.domain not in referenced_domains:
            # Also check if www.domain is there
            if f"www.{t.domain}" not in referenced_domains:
                 unlinked_count += 1
                 dead_links.append({
                    "id": t.id,
                    "domain": t.domain,
                    "type": "orphan",
                    "details": "Not linked from any other scanned target",
                    "last_checked": "-"
                 })

    # Stats
    unreachable_count = len(unreachable_ids)
    
    # Sort: Unreachable first, then Orphans
    dead_links.sort(key=lambda x: (x["type"] != "unreachable", x["domain"]))
    
    return len(targets), unreachable_count, unlinked_count, dead_links


@ui_router.get("/dead-links", response_class=HTMLResponse)
async def view_dead_links(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Renders the shell for Dead Links Analysis.
    """
    return templates.TemplateResponse("analytics_dead_links.html", {
        "request": request,
        "user": user,
        "settings": settings,
    })

@ui_router.get("/dead-links/rows", response_class=HTMLResponse)
async def get_dead_links_rows(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    HTMX endpoint for table rows.
    """
    scope_count, unreachable_count, orphan_count, dead_links = _get_dead_links_data(session, user)
    
    return templates.TemplateResponse("_dead_links_rows.html", {
        "request": request,
        "dead_links": dead_links,
        "scope_count": scope_count,
        "unreachable_count": unreachable_count,
        "orphan_count": orphan_count
    })


@ui_router.get("/external-links/export-csv")
async def export_external_links_csv(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Exports the External Links report to CSV.
    """
    from fastapi.responses import Response
    import csv
    import io

    scope_count, final_list, tenant_name = _get_external_links_data(session, user)
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Domain", "Type", "Sources", "Count"])
    
    # Rows
    for item in final_list:
        sources_str = ", ".join(item.get("sources", []))
        types_str = ", ".join(item.get("types", []))
        writer.writerow([
            item.get("domain", ""),
            types_str,
            sources_str,
            item.get("count", 0)
        ])
        
    output.seek(0)
    csv_content = output.getvalue()
    
    filename = f"external_links_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    
    return Response(
        content=csv_content, 
        media_type="text/csv", 
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@ui_router.get("/dead-links/export-csv")
async def export_dead_links_csv(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Exports the Dead Links report to CSV.
    """
    from fastapi.responses import Response
    import csv
    import io

    scope_count, unreachable_count, orphan_count, dead_links = _get_dead_links_data(session, user)
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Target Domain", "Status", "Issue Type", "Details", "Last Check"])
    
    # Rows
    for item in dead_links:
        writer.writerow([
            item.get("domain", ""),
            "Dead" if item.get("type") == "unreachable" else "Orphan",
            item.get("type", "").title(),
            item.get("details", ""),
            item.get("last_checked", "")
        ])
        
    output.seek(0)
    csv_content = output.getvalue()
    
    filename = f"dead_links_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    
    return Response(
        content=csv_content, 
        media_type="text/csv", 
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@ui_router.get("/export-pdf")
async def export_infrastructure_pdf(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Exports the Analytics Infrastructure report to PDF.
    """
    from fastapi.responses import Response
    from yads.modules.report_generator import generate_infrastructure_report
    from yads.models import Tenant
    
    data = _get_infrastructure_data(session, user)
    
    tenant_name = "Global"
    if user.tenant_id:
         t = session.get(Tenant, user.tenant_id)
         if t: tenant_name = t.name
         
    pdf_bytes = generate_infrastructure_report(data, tenant_name)
    
    filename = f"analytics_report_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    
    
    return Response(content=bytes(pdf_bytes), media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })

from fastapi import Form
from yads.auth.deps import RoleChecker

@ui_router.post("/external-links/add-targets")
async def add_targets_from_links(
    request: Request,
    domains: List[str] = Form(...),
    tag: str = Form(default="external"),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin"]))
):
    """
    Adds selected domains as new targets.
    """
    # 1. Determine Tenant Scope
    tenant_id = user.tenant_id
    # Admin without tenant context? Warn or forbid? 
    # For now, allow but they become global targets (tenant_id=None) unless explicitly switched.
    
    count = 0
    skipped = 0
    
    for domain in domains:
        domain = domain.strip().lower()
        if not domain: continue
        
        # Check existence
        query = select(Target).where(Target.domain == domain)
        if tenant_id:
            query = query.where(Target.tenant_id == tenant_id)
        else:
            query = query.where(Target.tenant_id == None)
            
        existing = session.exec(query).first()
        
        if existing:
            # Update Tag only?
            if tag and tag not in existing.tags:
                existing.tags.append(tag)
                session.add(existing)
                count += 1 # Count as processed/updated
            else:
                skipped += 1
        else:
            # Create New
            new_target = Target(
                domain=domain,
                tenant_id=tenant_id,
                tags=[tag] if tag else [],
                scan_status="idle",
                is_active=True
            )
            session.add(new_target)
            count += 1
            
    session.commit()
    
    # Return success message (HTMX Toast equivalent or Redirect)
    # Using simple redirect back with a query param for now, or just re-render row?
    # Better: Hx-Response-Header to trigger client side toast
    
    # Redirecting to target list or staying here?
    # User probably wants to stay here.
    return HTMLResponse(
        f"""
        <div class="fixed bottom-4 right-4 bg-emerald-900 border border-emerald-700 text-emerald-100 px-4 py-3 rounded shadow-lg z-50 animate-bounce" 
             _="on load wait 3s then remove me">
             Successfully processed {count} targets ({skipped} skipped).
        </div>
        """, headers={"HX-Trigger": "reload-targets"} # Optional trigger
    )

# -----------------------------------------------------------------------------
# DIFF VIEW ENDPOINTS
# -----------------------------------------------------------------------------

@ui_router.get("/targets/{target_id}/history", response_model=List[Dict[str, Any]])
async def get_target_history(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Returns available scan history for a target.
    """
    results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc()).limit(50)).all()
    
    history = []
    for r in results:
        history.append({
            "id": r.id,
            "module": r.module_name,
            "timestamp": r.scanned_at.isoformat(),
            "hash": r.result_hash
        })
    return history

@ui_router.get("/compare", response_class=HTMLResponse)
async def view_comparison(
    request: Request,
    target_id: int,
    scan_a: int, 
    scan_b: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Renders the comparison view.
    """
    res_a = session.get(ScanResult, scan_a)
    res_b = session.get(ScanResult, scan_b)
    
    if not res_a or not res_b:
        return "Scan results not found" # Simple error for now
        
    diff = ComparisonEngine.compare(res_a.data, res_b.data, target_id, scan_a, scan_b)
    target = session.get(Target, target_id)

    return templates.TemplateResponse("analytics_compare.html", {
        "request": request,
        "user": user,
        "diff": diff,
        "target": target,
        "res_a": res_a,
        "res_b": res_b,
        "settings": settings
    })
