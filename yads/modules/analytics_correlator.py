import re
import requests
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from yads.core.base import BaseScannerModule
from yads.models import Tenant

class AnalyticsCorrelator(BaseScannerModule):
    """
    Analytics & Tracker Correlation Module.
    Extracts Tracking IDs (GA, GTM, AdSense) to identify related domains 
    (Vertical Domain Correlation).
    """
    
    # Regex patterns for common trackers
    TRACKER_PATTERNS = {
        "Google Analytics (UA)": r"UA-[0-9]{4,10}-[0-9]{1,4}",
        "Google Analytics 4 (G)": r"G-[A-Z0-9]{8,12}",
        "Google Tag Manager": r"GTM-[A-Z0-9]{4,10}",
        "Google AdSense": r"pub-[0-9]{10,20}",
        "Facebook Pixel": r"fbq\(['\"]init['\"],\s*['\"]([0-9]{10,20})['\"]",
        "Hotjar": r"hjid\s*[:=]\s*([0-9]{4,10})",
        "New Relic": r"applicationID\s*[:=]\s*['\"]([0-9]{4,15})['\"]"
    }

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.analytics_correlator")

    @property
    def module_name(self) -> str:
        return "analytics_correlator"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        self.logger.info(f"Starting Analytics Correlation for: {target}")
        
        results = {
            "trackers": [],
            "pivots": [],
            "status": "completed",
            "scanned_at": datetime.utcnow().isoformat()
        }

        # 1. Fetch Page Content
        url = f"https://{target}"
        try:
            # Fake browser UA to avoid blocking
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            resp = requests.get(url, timeout=10, headers=headers, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            content = resp.text
        except Exception as e:
            # Try HTTP Fallback
            try:
                url = f"http://{target}"
                resp = requests.get(url, timeout=10, headers=headers, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
                content = resp.text
            except Exception as e2:
                results["error"] = f"Failed to fetch page: {e2}"
                return results

        # 2. Extract Trackers
        found_ids = set()
        for name, pattern in self.TRACKER_PATTERNS.items():
            matches = re.findall(pattern, content)
            for m in matches:
                # Handle group capture if regex has groups
                val = m if isinstance(m, str) else m[0]
                
                # Deduplicate
                key = f"{name}:{val}"
                if key not in found_ids:
                    found_ids.add(key)
                    results["trackers"].append({
                        "type": name,
                        "id": val,
                        "source": "regex_body"
                    })
                    
                    # 3. Generate Pivots (Search Links)
                    # These help the analyst find OTHER domains with the same ID
                    results["pivots"].append(self._generate_pivot(name, val))

        self.logger.info(f"Found {len(results['trackers'])} trackers on {target}")
        return results

    def _generate_pivot(self, tracker_type: str, tracker_id: str) -> Dict[str, str]:
        """
        Generates pivot links for common OSINT tools.
        """
        pivots = {
            "tracker_id": tracker_id,
            "type": tracker_type,
            "queries": {}
        }
        
        if "Google" in tracker_type:
            # BuiltWith / PublicWWW are best for these
            pivots["queries"]["PublicWWW"] = f'https://publicwww.com/websites/"{tracker_id}"/'
            pivots["queries"]["BuiltWith"] = f"https://builtwith.com/relationships/{tracker_id}"
            pivots["queries"]["Shodan"] = f'http.html:"{tracker_id}"'
            
        elif "Facebook" in tracker_type:
             pivots["queries"]["PublicWWW"] = f'https://publicwww.com/websites/"{tracker_id}"/'
             
        return pivots
