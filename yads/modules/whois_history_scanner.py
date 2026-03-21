"""
WHOIS History Scanner

Retrieves WHOIS registration records to reveal:
- Registrar and registrant details
- Domain creation and expiration dates
- Name servers
- Domain ownership changes over time (persists state to OSINT intelligence graph)
"""

import logging
import json
from datetime import datetime
from typing import Any, Dict, Optional

import whois

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

def _clean_domain(target: str) -> str:
    return target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

class WhoisHistoryScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "whois_history_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "whois_data": {},
            "findings": [],
            "summary": {
                "score": 100
            }
        }

        try:
            w = whois.whois(domain)
            
            def _serialize(v):
                if isinstance(v, list):
                    return [_serialize(x) for x in v]
                if isinstance(v, datetime):
                    return v.isoformat()
                return str(v) if v else None
                
            whois_data = {k: _serialize(v) for k, v in dict(w).items() if v}
            result["whois_data"] = whois_data
            
            # Extrapolate Security Findings
            exp_date = w.get("expiration_date")
            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            if isinstance(exp_date, datetime):
                days_left = (exp_date - datetime.utcnow()).days
                if days_left < 30:
                    result["findings"].append({
                        "severity": "medium",
                        "title": f"Domain expires in {days_left} days",
                        "description": f"The domain {domain} is set to expire soon. Monitor to ensure renewals prevent domain takeovers."
                    })
                    result["summary"]["score"] -= 10

            # Store to OSINTIntelligence
            if target_id and whois_data:
                from yads.models import OSINTIntelligence
                
                # Query newest record to detect ownership shift
                latest = self.db.query(OSINTIntelligence).filter_by(
                    target_id=target_id, module_name=self.module_name, data_type="whois_record"
                ).order_by(OSINTIntelligence.timestamp.desc()).first()
                
                # Identify notable changes
                current_registrar = whois_data.get("registrar")
                latest_registrar = latest.data_json.get("registrar") if latest else None
                
                updated_at = whois_data.get("updated_date")
                latest_updated_at = latest.data_json.get("updated_date") if latest else None

                # Persist if this is the first ever record or if the updated_date / registrar drifted
                if not latest or current_registrar != latest_registrar or updated_at != latest_updated_at:
                    is_change = bool(latest)
                    self.db.add(OSINTIntelligence(
                        target_id=target_id,
                        module_name=self.module_name,
                        data_type="whois_record",
                        data_json=whois_data,
                        severity="low" if is_change else "info"
                    ))
                     
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            result["error"] = str(e)
            
        return result
