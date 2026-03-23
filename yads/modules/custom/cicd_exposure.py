import requests
from typing import Any, Dict, Optional
from yads.core.base import BaseScannerModule

class CicdExposureScanner(BaseScannerModule):
    """
    Checks for exposed CI/CD configuration files that might leak environment variables or secrets.
    """
    
    @property
    def module_name(self) -> str:
        return "cicd_exposure"

    @property
    def label(self) -> str:
        return "CI/CD Pipeline Exposure"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        paths = [
            ".gitlab-ci.yml",
            ".github/workflows/main.yml",
            "circleci/config.yml",
            "Jenkinsfile",
            "deploy.sh",
            ".env"
        ]
        
        findings = []
        for p in paths:
            try:
                url = f"https://{target}/{p}"
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    findings.append({
                        "path": p,
                        "size": len(resp.text),
                        "severity": "High" if p == ".env" else "Medium"
                    })
            except:
                continue
                
        return {
            "exposed_files": findings,
            "findings_count": len(findings),
            "summary": f"Detected {len(findings)} exposed pipeline files."
        }
