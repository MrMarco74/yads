import requests
from typing import Any, Dict, Optional
from yads.core.base import BaseScannerModule

class ExposedAdminPanelScanner(BaseScannerModule):
    """
    Checks for common administrative interfaces that might be exposed.
    """
    
    @property
    def module_name(self) -> str:
        return "exposed_admin_panel"

    @property
    def label(self) -> str:
        return "Admin Panel Detection"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        panels = [
            "/admin", "/wp-admin", "/phpmyadmin", "/wp-login.php",
            "/portal", "/controlpanel", "/manage", "/cpanel",
            "/directadmin", "/plesk"
        ]
        
        findings = []
        for p in panels:
            try:
                url = f"https://{target}{p}"
                resp = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                # 200, 301, 302 can indicate presence
                if resp.status_code in [200, 301, 302]:
                    findings.append({
                        "path": p,
                        "status_code": resp.status_code,
                        "severity": "Medium"
                    })
            except:
                continue
                
        return {
            "panels": findings,
            "findings_count": len(findings),
            "summary": f"Found {len(findings)} potential admin panels."
        }
