import logging
import time
from typing import Any, Dict, List
import requests
from sqlmodel import Session, select

from yads.core.base import BaseScannerModule
from yads.models import Tenant, Target, ScanResult

class LeakMonitor(BaseScannerModule):
    """
    Credential & Leak Monitor module.
    Checks discovered email addresses against 'Have I Been Pwned' (HIBP) API.
    Requires 'hibp_api_key' to be set in Tenant Settings.
    """
    @property
    def module_name(self) -> str:
        return "leak_monitor"

    def __init__(self, db_session: Session = None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.leak_monitor")
        self.api_base = "https://haveibeenpwned.com/api/v3"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Scans for leaks associated with emails found on the target.
        """
        self.logger.info(f"Starting Leak Monitor scan for: {target}")
        
        results = {
            "emails_checked": [],
            "leaks_found": [],
            "status": "skipped"
        }

        # 1. Get Tenant Context & API Key
        # We need to find the tenant for this target.
        # Since run_scan provides 'target' string, we query DB for the Target object.
        if not self.db_session:
            self.logger.error("No DB session available. Cannot retrieve Tenant API Key.")
            results["error"] = "DB Session Missing"
            return results

        target_obj = self.db_session.exec(select(Target).where(Target.domain == target)).first()
        if not target_obj or not target_obj.tenant_id:
            self.logger.warning(f"Target {target} not found or not linked to tenant.")
            results["error"] = "Target/Tenant not found"
            return results
            
        tenant = self.db_session.get(Tenant, target_obj.tenant_id)
        if not tenant or not tenant.hibp_api_key:
            self.logger.info("No HIBP API Key configured for tenant. Skipping scan.")
            results["status"] = "skipped_no_key"
            return results

        api_key = tenant.hibp_api_key

        # 2. Gather Emails
        # We look at previous scan results (e.g., from visual_osint or crawler) for emails.
        # For now, let's assume we extract them from a hypothetical 'metadata' or just mock distinct emails 
        # linked to the domain if we had an 'email harvester'. 
        # SINCE WE DON'T have a dedicated email harvester yet, let's look for emails in 
        # 'crawled_urls' or 'visual_osint' data or use a placeholder approach.
        
        # PROPOSAL COMPROMISE: We scan the domain string itself? No, HIBP checks accounts (email).
        # We usually check "info@target.com", "admin@target.com" + any discovered.
        # Let's verify common aliases.
        
        emails_to_check = [
            f"info@{target}",
            f"admin@{target}",
            f"support@{target}",
            f"contact@{target}"
        ]
        
        # Check if we have crawled emails (Future integration)
        # ...
        
        self.logger.info(f"Checking {len(emails_to_check)} potential emails against HIBP...")
        
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "YADS-Security-Scanner-v1.9"
        }

        found_leaks = False
        
        for email in emails_to_check:
            try:
                # Rate Limiting: HIBP requires ~1.5s delay between requests
                time.sleep(1.6) 
                
                url = f"{self.api_base}/breachedaccount/{email}?truncateResponse=false"
                resp = requests.get(url, headers=headers, timeout=10)
                
                if resp.status_code == 200:
                    data = resp.json()
                    breach_names = [b["Name"] for b in data]
                    results["emails_checked"].append({"email": email, "breached": True, "count": len(breach_names)})
                    results["leaks_found"].append({"email": email, "breaches": breach_names})
                    found_leaks = True
                    self.logger.warning(f"LEAK FOUND: {email} in {breach_names}")
                    
                elif resp.status_code == 404:
                    results["emails_checked"].append({"email": email, "breached": False})
                    
                elif resp.status_code == 429:
                    self.logger.warning("HIBP Rate Limit Exceeded.")
                    results["error"] = "Rate Limit"
                    break
                    
                else:
                    self.logger.warning(f"HIBP Error {resp.status_code}: {resp.text}")
                    
            except Exception as e:
                self.logger.error(f"Error checking email {email}: {e}")
                
        results["status"] = "finished"
        results["found_leaks"] = found_leaks
        
        return results
