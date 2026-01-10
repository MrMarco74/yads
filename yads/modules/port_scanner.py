import requests
import logging
from typing import Any, Dict
import urllib3
from yads.core.base import BaseScannerModule
from yads.config import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PortScanner(BaseScannerModule):
    """
    Lightweight Port Scanner / Web Probe.
    Checks if ports 80 (HTTP) and 443 (HTTPS) are open and returns basic server info.
    Use this to quickly filter for active webservers before running heavy scans.
    """
    @property
    def module_name(self) -> str:
        return "port_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.port_scanner")

    def run_scan(self, target: str) -> Dict[str, Any]:
        results = {
            "http": {"open": False, "status": 0, "server": None},
            "https": {"open": False, "status": 0, "server": None},
            "is_active": False
        }
        
        # Use a short timeout for rapidity
        timeout = 5 
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; YADS/1.0; +http://yads.local)"
        }
        
        # HTTP Check
        try:
            r = requests.get(f"http://{target}", timeout=timeout, allow_redirects=False, headers=headers)
            results["http"] = {
                "open": True,
                "status": r.status_code,
                "server": r.headers.get("Server")
            }
            results["is_active"] = True
        except Exception:
            pass

        # HTTPS Check
        try:
            # verify=False is crucial as many internal/test targets have self-signed certs
            r = requests.get(f"https://{target}", timeout=timeout, allow_redirects=False, headers=headers, verify=False)
            results["https"] = {
                "open": True,
                "status": r.status_code,
                "server": r.headers.get("Server")
            }
            results["is_active"] = True
        except Exception:
            pass
            
        return results
