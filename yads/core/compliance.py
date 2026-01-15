
from typing import Dict, Any, List

def calculate_security_grade(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates an aggregated security grade (A-F) and score (0-100).
    Input `results` is a dictionary of the latest scan objects (e.g. {'web': ..., 'ssl': ...}).
    """
    score = 100
    deductions = []

    # 1. SSL/TLS (Weight: High)
    ssl = results.get("ssl_result")
    if ssl and ssl.data:
        grade = ssl.data.get("grade", "F") # Default to F if missing
        if grade in ["A+", "A"]: pass
        elif grade == "B": score -= 10; deductions.append("SSL Grade is B (-10)")
        elif grade == "C": score -= 20; deductions.append("SSL Grade is C (-20)")
        elif grade in ["D", "E"]: score -= 30; deductions.append("SSL Grade is Poor (-30)")
        elif grade in ["F", "T", "M"]: score -= 50; deductions.append("SSL Grade is Failing (-50)")
    else:
        # If web is active but no SSL -> Big penalty
        web = results.get("web_result")
        if web and web.data.get("http_status") and not web.data.get("https_status"):
             score -= 40
             deductions.append("No HTTPS detected (-40)")

    # 2. Vulnerabilities (Nuclei) (Weight: Critical)
    nuclei = results.get("nuclei_result")
    if nuclei and nuclei.data and nuclei.data.get("stats"):
        stats = nuclei.data["stats"]
        crit = stats.get("critical", 0)
        high = stats.get("high", 0)
        med = stats.get("medium", 0)
        
        if crit > 0: 
            score -= 100 # Instant F
            deductions.append(f"{crit} Critical Vulnerabilities (-100)")
        elif high > 0:
            score -= 40 * high
            deductions.append(f"{high} High Vulnerabilities (-{40*high})")
        
        if med > 0:
            score -= 10 * med
            deductions.append(f"{med} Medium Vulnerabilities (-{10*med})")

    # 3. Web Security Headers (Weight: Medium)
    web = results.get("web_result")
    if web and web.data and web.data.get("http_headers"):
        headers = web.data["http_headers"]
        # Basic check
        security_headers = {
            "Strict-Transport-Security": 5,
            "Content-Security-Policy": 10,
            "X-Frame-Options": 5,
            "X-Content-Type-Options": 5
        }
        for h, weight in security_headers.items():
            if not any(k.lower() == h.lower() for k in headers.keys()):
                score -= weight
                deductions.append(f"Missing {h} (-{weight})")
    
    # 4. Open Ports (Nmap) (Weight: Variable)
    nmap = results.get("nmap_result")
    if nmap and nmap.data and nmap.data.get("open_ports"):
        open_ports = nmap.data["open_ports"]
        # Allow 80, 443 without penalty usually
        allowed = [80, 443]
        unexpected = [p for p in open_ports if p['port'] not in allowed]
        if unexpected:
            pen = len(unexpected) * 5
            score -= pen
            deductions.append(f"{len(unexpected)} Unexpected Open Ports (-{pen})")

    # 5. Secrets Exposure (Weight: High)
    if web and web.data.get("secrets"):
        count = len(web.data["secrets"])
        score -= 20 * count
        deductions.append(f"{count} Exposed Secrets (-{20*count})")

    # Normalize
    score = max(0, min(100, score))

    # Determine Letter
    if score >= 90: letter = "A"
    elif score >= 80: letter = "B"
    elif score >= 70: letter = "C"
    elif score >= 60: letter = "D"
    else: letter = "F"

    return {
        "score": score,
        "grade": letter,
        "deductions": deductions
    }

def generate_compliance_report(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Maps findings to compliance standards (OWASP, GDPR, etc.).
    """
    issues = []

    web = results.get("web_result")
    ssl = results.get("ssl_result")
    nuclei = results.get("nuclei_result")

    # OWASP A05:2021 - Security Misconfiguration (Headers)
    if web and web.data.get("http_headers"):
        headers = {k.lower(): v for k, v in web.data["http_headers"].items()}
        missing = []
        if "strict-transport-security" not in headers: missing.append("HSTS")
        if "content-security-policy" not in headers: missing.append("CSP")
        
        if missing:
            issues.append({
                "standard": "OWASP Top 10 (2021)",
                "control": "A05: Security Misconfiguration",
                "finding": f"Missing Security Headers: {', '.join(missing)}",
                "severity": "Medium"
            })

    # OWASP A02:2021 - Cryptographic Failures (SSL)
    if ssl and ssl.data:
        grade = ssl.data.get("grade", "F")
        if grade in ["F", "T", "M", "D"]:
            issues.append({
                "standard": "OWASP Top 10 (2021)",
                "control": "A02: Cryptographic Failures",
                "finding": f"Weak SSL Configuration (Grade {grade})",
                "severity": "High"
            })
    
    # GDPR - Data Exposure (PII / Secrets)
    if web:
        secrets = web.data.get("secrets", [])
        emails = web.data.get("emails", [])
        
        if secrets:
            issues.append({
                "standard": "GDPR / ISO 27001",
                "control": "A.5.12 Information Classification",
                "finding": f"Exposure of Sensitive Keys/Tokens ({len(secrets)} found)",
                "severity": "Critical"
            })
        
        if len(emails) > 5: # Arbitrary threshold for "Mass PII"
            issues.append({
                "standard": "GDPR",
                "control": "Art. 5(1)(f) Integrity and Confidentiality",
                "finding": "Large amount of publicly visible email addresses (Potential PII exposure)",
                "severity": "Low"
            })

    # Nuclei Mapping (Generic)
    if nuclei and nuclei.data.get("findings"):
        for f in nuclei.data["findings"]:
            sev = f.get("severity", "low").lower()
            if sev in ["critical", "high"]:
                issues.append({
                    "standard": "OWASP Top 10 (2021)",
                    "control": "A06: Vulnerable and Outdated Components",
                    "finding": f"Known Vulnerability: {f.get('name')}",
                    "severity": sev.title()
                })

    return issues
