from datetime import datetime
from typing import Dict, List, Tuple, Any
import json

# Every module_name calculate_target_score() actually reads below. Several
# callers historically pre-filtered their ScanResult query to a stale, much
# shorter hardcoded list (missing graphql_scanner/websocket_scanner and other
# newer modules — #34), silently starving the scorer of their findings. Use
# this as the single source of truth for "which modules affect the score" so
# adding a new scoring factor here doesn't require hunting down every caller.
SCORED_MODULE_NAMES = [
    "ssl_scanner", "port_scanner", "web_analyzer", "leaked_credentials",
    "phishing_scanner", "open_redirect_scanner", "tls_deep_scanner",
    "dependency_confusion", "api_security_scanner", "subdomain_takeover",
    "waf_detector", "graphql_scanner", "websocket_scanner", "password_spray_mapper",
    "catchall_detector",
]

def get_grade(score: int) -> str:
    """Maps a numeric score (0-100) to a letter grade."""
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"

def get_grade_color(grade: str) -> str:
    """Returns a tailwind color class for the grade."""
    if grade == "A": return "text-emerald-400 bg-emerald-400/10 border-emerald-400/20"
    if grade == "B": return "text-cyan-400 bg-cyan-400/10 border-cyan-400/20"
    if grade == "C": return "text-yellow-400 bg-yellow-400/10 border-yellow-400/20"
    if grade == "D": return "text-orange-400 bg-orange-400/10 border-orange-400/20"
    return "text-red-400 bg-red-400/10 border-red-400/20"

def calculate_target_score(target: Any, latest_results: Dict[str, Any]) -> Tuple[int, str, List[str]]:
    """
    Calculates a security score for a target based on scan findings.
    Returns: (score, grade, factors)
    """
    score = 100
    factors = []

    # 1. SSL Analysis
    ssl_res = latest_results.get("ssl_scanner")
    if ssl_res and ssl_res.data:
        data = ssl_res.data
        if isinstance(data, str):
            try: data = json.loads(data)
            except: data = {}
            
        if data.get("error"):
            score -= 20
            factors.append("SSL Error/Invalid")
        else:
            # Check expiration
            not_after = data.get("notAfter")
            if not_after:
                try:
                    import dateutil.parser
                    expiry = dateutil.parser.parse(not_after).replace(tzinfo=None)
                    days_left = (expiry - datetime.now()).days
                    
                    if days_left < 0:
                        score -= 40
                        factors.append("SSL Expired")
                    elif days_left < 30:
                        score -= 15
                        factors.append("SSL Expiring Soon")
                except:
                    pass
    else:
        # If no SSL data found but it's a domain/subdomain, maybe penalize slightly or ignore?
        # Let's assume neutral if not scanned, but maybe web_analyzer says it's HTTP
        pass

    # 2. Port Analysis
    port_res = latest_results.get("port_scanner")
    if port_res and port_res.data:
        data = port_res.data
        if isinstance(data, str):
            try: data = json.loads(data)
            except: data = {}
            
        open_ports = data.get("open_ports", [])
        critical_ports = [21, 23, 3389, 445, 139, 5900]
        
        found_critical = False
        for p in open_ports:
            port_num = p if isinstance(p, int) else int(p.get("port", 0))
            if port_num in critical_ports:
                score -= 20
                if not found_critical: # Dedup factor text
                    factors.append(f"Critical Port {port_num} Open")
                    found_critical = True
                else:
                    # Penalize cumulative but don't spam text
                    pass
    
    # 3. Web Analysis (HTTP vs HTTPS)
    web_res = latest_results.get("web_analyzer")
    if web_res and web_res.data:
        data = web_res.data
        if isinstance(data, str):
            try: data = json.loads(data)
            except: data = {}

        scheme = data.get("scheme")
        if scheme == "http":
            score -= 10
            factors.append("Plain HTTP")

    # 4. Leaked Credentials (critical)
    lc_res = latest_results.get("leaked_credentials")
    if lc_res and lc_res.data:
        data = lc_res.data if not isinstance(lc_res.data, str) else {}
        breaches = data.get("breach_details", [])
        if breaches:
            score -= min(25, len(breaches) * 8)
            factors.append(f"Leaked Credentials ({len(breaches)} breach(es))")

    # 5. Phishing listed
    ph_res = latest_results.get("phishing_scanner")
    if ph_res and ph_res.data:
        data = ph_res.data if not isinstance(ph_res.data, str) else {}
        if data.get("phishing_listed"):
            score -= 20
            factors.append("Domain Listed in Phishing Database")

    # 6. Open Redirect
    or_res = latest_results.get("open_redirect_scanner")
    if or_res and or_res.data:
        data = or_res.data if not isinstance(or_res.data, str) else {}
        vuln = data.get("summary", {}).get("vulnerable_params", 0)
        if vuln:
            score -= min(15, vuln * 5)
            factors.append(f"Open Redirect ({vuln} parameter(s))")

    # 7. TLS Deep Scan — penalize by grade
    tls_res = latest_results.get("tls_deep_scanner")
    if tls_res and tls_res.data:
        data = tls_res.data if not isinstance(tls_res.data, str) else {}
        grade = data.get("summary", {}).get("grade", "A")
        penalty = {"A+": 0, "A": 0, "B": 5, "C": 10, "D": 15, "F": 20}.get(grade, 0)
        if penalty:
            score -= penalty
            factors.append(f"TLS Configuration Grade {grade}")

    # 8. Dependency Confusion — supply chain risk
    dc_res = latest_results.get("dependency_confusion")
    if dc_res and dc_res.data:
        data = dc_res.data if not isinstance(dc_res.data, str) else {}
        high_findings = [f for f in data.get("findings", []) if f.get("severity") in ("critical", "high")]
        if high_findings:
            score -= min(20, len(high_findings) * 8)
            factors.append(f"Dependency Confusion Risk ({len(high_findings)} package(s))")

    # 9. API Security — critical/high findings
    api_res = latest_results.get("api_security_scanner")
    if api_res and api_res.data:
        data = api_res.data if not isinstance(api_res.data, str) else {}
        crit = [f for f in data.get("findings", []) if f.get("severity") == "critical"]
        high = [f for f in data.get("findings", []) if f.get("severity") == "high"]
        if crit:
            score -= min(20, len(crit) * 10)
            factors.append(f"Critical API Security Issues ({len(crit)})")
        elif high:
            score -= min(10, len(high) * 5)
            factors.append(f"High API Security Issues ({len(high)})")

    # 10. Generic finding modules — deduct for critical/high findings
    _generic_penalize = {
        "subdomain_takeover": (15, "Subdomain Takeover Risk"),
        "waf_detector": (0, ""),  # WAF is good, no penalty
        "graphql_scanner": (8, "GraphQL Security Issues"),
        "websocket_scanner": (8, "WebSocket Security Issues"),
        "password_spray_mapper": (5, "Password Spray Surface Exposed"),
        "catchall_detector": (20, "Domain Is Parked / Not In Active Use"),
    }
    for mod_name, (max_pen, label) in _generic_penalize.items():
        if max_pen == 0:
            continue
        mod_res = latest_results.get(mod_name)
        if mod_res and mod_res.data:
            data = mod_res.data if not isinstance(mod_res.data, str) else {}
            crit_high = [f for f in data.get("findings", []) if f.get("severity") in ("critical", "high")]
            if crit_high:
                score -= min(max_pen, len(crit_high) * 4)
                factors.append(f"{label} ({len(crit_high)} finding(s))")

    # Cap score
    score = max(0, min(100, score))

    return score, get_grade(score), factors
