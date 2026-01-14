from typing import List, Dict, Any
from datetime import datetime
from yads.models import Target, ScanResult

class ComplianceScorer:
    """
    Calculates a 'SOC2 Readiness' score based on security findings.
    This is a heuristic score, not a legal certification.
    
    Scoring Model (0-100):
    - Start at 100.
    - Deductions apply for security failures.
    - Cannot go below 0.
    """
    
    def __init__(self):
        self.rules = [
            self._check_ssl,
            self._check_cves,
            self._check_headers,
            self._check_buckets,
            self._check_open_ports
        ]
        
    def calculate_score(self, targets: List[Target], scan_results: List[ScanResult]) -> Dict[str, Any]:
        """
        Returns:
            {
                "score": int,
                "grade": str, 
                "passing_controls": int,
                "failing_controls": int,
                "failures": List[str] # Top reasons
            }
        """
        if not targets:
            return {
                "score": 100, 
                "grade": "A", 
                "passing_controls": 5, 
                "failing_controls": 0,
                "failures": []
            }

        # Map results by target for easier lookup
        # {target_id: {module_name: data}}
        target_data = {t.id: {} for t in targets}
        target_map = {t.id: t.domain for t in targets}
        
        for res in scan_results:
            if res.target_id in target_data:
                # Assuming results are sorted by date desc, so we see latest first if not handled outside
                # But to be safe, we typically want the latest. 
                # The caller should ideally provide only latest results.
                if res.module_name not in target_data[res.target_id]:
                    target_data[res.target_id][res.module_name] = res.data

        current_score = 100
        failures = []
        
        # Rule Execution
        for rule in self.rules:
            deduction, reasons = rule(target_data, target_map)
            current_score -= deduction
            failures.extend(reasons)
            
        current_score = max(0, int(current_score))
        
        grade = "A"
        if current_score < 90: grade = "B"
        if current_score < 80: grade = "C"
        if current_score < 70: grade = "D"
        if current_score < 60: grade = "F"
        
        return {
            "score": current_score,
            "grade": grade,
            "passing_controls": len(self.rules) - (1 if current_score < 100 else 0), # Simplified Metric
            "failing_controls": len(failures),
            "failures": failures[:5] # Top 5
        }

    def _check_ssl(self, data: Dict[int, Dict], target_map: Dict[int, str]):
        deduction = 0
        reasons = []
        
        for tid, modules in data.items():
            ssl = modules.get("ssl_scanner")
            if not ssl: continue
            
            # Check Expiry
            if ssl.get("expired"):
                deduction += 20
                reasons.append(f"Expired SSL certificate on {target_map[tid]}")
            elif ssl.get("grade") in ["F", "T", "M"]: # Hypothetical grade from ssl scanner
                deduction += 10
                reasons.append(f"Weak SSL configuration on {target_map[tid]}")
                
        return deduction, reasons

    def _check_cves(self, data: Dict[int, Dict], target_map: Dict[int, str]):
        deduction = 0
        reasons = []
        
        for tid, modules in data.items():
            web = modules.get("web_analyzer") or modules.get("cve_scanner") # cves might be in either
            if not web: continue
            
            cves = web.get("cves", [])
            for cve in cves:
                try:
                    score = float(cve.get("cvss", 0))
                    if score >= 9.0:
                        deduction += 15
                        reasons.append(f"Critical Vulnerability ({cve.get('id')}) on {target_map[tid]}")
                    elif score >= 7.0:
                        deduction += 5
                        # Don't spam reasons for every high, maybe aggregate?
                        # reasons.append(f"High Vulnerability on {target_map[tid]}")
                except: pass
                
        return deduction, reasons

    def _check_headers(self, data: Dict[int, Dict], target_map: Dict[int, str]):
        deduction = 0
        reasons = []
        
        for tid, modules in data.items():
            web = modules.get("web_analyzer")
            if not web: continue
            
            headers = web.get("http_headers", {})
            # Check simple key presence (case insensitive usually handled by requests, but here dict)
            keys = [k.lower() for k in headers.keys()]
            
            if "strict-transport-security" not in keys:
                deduction += 2
                # reasons.append(f"Missing HSTS on {target_map[tid]}") 
                # Small deduction, maybe don't clutter reasons unless score is low
            
            if "content-security-policy" not in keys:
                deduction += 1
                
        return deduction, reasons

    def _check_buckets(self, data: Dict[int, Dict], target_map: Dict[int, str]):
        deduction = 0
        reasons = []
        
        for tid, modules in data.items():
            infra = modules.get("infrastructure_scanner")
            if not infra: continue
            
            buckets = infra.get("buckets", [])
            open_buckets = [b for b in buckets if b.get("status") == "Public"]
            
            if open_buckets:
                deduction += 25
                reasons.append(f"Public Cloud Storage Bucket exposed on {target_map[tid]}")
                
        return deduction, reasons

    def _check_open_ports(self, data: Dict[int, Dict], target_map: Dict[int, str]):
        deduction = 0
        reasons = []
        
        risky_ports = [21, 23, 25, 3306, 5432, 3389] # FTP, Telnet, SMTP, MySQL, Postgres, RDP
        
        for tid, modules in data.items():
            # Support port_scanner or infrastructure_scanner structure
            ports = []
            
            port_mod = modules.get("port_scanner")
            if port_mod:
                # structure: {"open_ports": [80, 443], "details": ...}
                ports = port_mod.get("open_ports", [])
                
            for p in ports:
                if p in risky_ports:
                    deduction += 10
                    reasons.append(f"Risky open port {p} on {target_map[tid]}")
                    
        return deduction, reasons
