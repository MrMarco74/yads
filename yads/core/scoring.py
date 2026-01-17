from datetime import datetime
from typing import Dict, List, Tuple, Any
import json

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

    # Cap score
    score = max(0, min(100, score))
    
    return score, get_grade(score), factors
