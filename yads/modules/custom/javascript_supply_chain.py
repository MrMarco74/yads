import requests
import re
from typing import Any, Dict, Optional
from yads.core.base import BaseScannerModule

class JavascriptSupplyChainScanner(BaseScannerModule):
    """
    Checks for suspicious third-party script usage and CDN drift.
    """
    
    @property
    def module_name(self) -> str:
        return "javascript_supply_chain"

    @property
    def label(self) -> str:
        return "JS Supply Chain Audit"

    @property
    def description(self) -> str:
        return "Analyzes external JS dependencies for known malicious CDNs and suspicious patterns."

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        results = {
            "critical_cdns": [],
            "suspicious_scripts": [],
            "findings_count": 0,
            "status": "Healthy"
        }
        
        try:
            url = f"https://{target}"
            resp = requests.get(url, timeout=10, verify=False)
            html = resp.text
            
            # 1. Malicious CDNs (Static List)
            MALICIOUS_CDNS = [
                r"polyglot\.io", r"cdn\.staticaly\.xyz", r"raw\.githubusercontent\.com/hacker"
            ]
            for pattern in MALICIOUS_CDNS:
                if re.search(pattern, html, re.I):
                    results["critical_cdns"].append(pattern)
            
            # 2. Suspicious Inline Scripts (Heuristics)
            # Look for obfuscated data or eval()
            if "eval(atob(" in html or "String.fromCharCode(" in html:
                results["suspicious_scripts"].append("Potential obfuscated script detected")

            results["findings_count"] = len(results["critical_cdns"]) + len(results["suspicious_scripts"])
            if results["findings_count"] > 0:
                results["status"] = "Risk Detected"
                
        except Exception as e:
            results["error"] = str(e)
            
        return results
