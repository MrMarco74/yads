
import logging
import dns.resolver
import requests
import concurrent.futures
import socket
from typing import Any, Dict, List
import tldextract

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

# Cache TLD list in memory to avoid fetching every time
_TLD_CACHE = []

def get_tld_list() -> List[str]:
    global _TLD_CACHE
    if _TLD_CACHE:
        return _TLD_CACHE
    
    try:
        # Fetch from IANA
        # Using a timeout to not hang forever
        resp = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=10)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            # Skip comments and header (IANA header starts with #)
            tlds = [line.strip().lower() for line in lines if line and not line.startswith('#')]
            _TLD_CACHE = tlds
            return tlds
    except Exception as e:
        logger.error(f"Failed to fetch TLD list: {e}")
    
    # Fallback to a common list if fetch fails
    return ["com", "net", "org", "info", "biz", "de", "uk", "co.uk", "fr", "it", "es", "eu", "nl", "cn", "ru", "br", "au", "io", "co", "me", "tv"]

class TLDScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "tld_scanner"

    def run_scan(self, domain: str) -> Dict[str, Any]:
        """
        Scans for the same SLD across all known TLDs.
        Counts:
        - Free (NXDOMAIN)
        - Registered (Different IP/ASN)
        """
        
        # 1. Parse Domain to get SLD
        # Using tldextract is best for accuracy (e.g. co.uk)
        ext = tldextract.extract(domain)
        sld = ext.domain
        
        if not sld:
            return {"error": "Could not extract SLD from domain"}
            
        # 2. Resolve Original Domain to get Reference IP/ASN
        # We need this to check "is different from main tld"
        ref_ips = []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ref_ips = [str(r) for r in answers]
        except Exception:
            pass # Maybe only AAAA or whatever, but we proceed
            
        # 3. Get TLD List
        all_tlds = get_tld_list()
        
        results = {
            "sld": sld,
            "scanned_count": len(all_tlds),
            "free_count": 0,
            "registered_count_diff_owner": 0,
            "registered_count_same": 0,
            "details": []
        }
        
        def check_tld(tld):
            # Skip if it matches the original domain extension
            if tld == ext.suffix:
                return None
                
            candidate = f"{sld}.{tld}"
            
            try:
                # Resolve
                res = dns.resolver.Resolver()
                res.timeout = 2
                res.lifetime = 2
                
                # We check A records basically
                answers = res.resolve(candidate, 'A')
                ips = [str(r) for r in answers]
                
                # It exists!
                # Check if matches reference
                match = False
                if ref_ips:
                    # If any IP shares commonality? Or exact match?
                    # Usually squatter/different owner has totally diff IP.
                    # "different from the main tld" -> strict difference
                    if any(ip in ref_ips for ip in ips):
                        match = True
                
                return {
                    "tld": tld,
                    "domain": candidate,
                    "status": "registered",
                    "ips": ips,
                    "same_owner": match
                }
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Free!
                return {
                    "tld": tld,
                    "domain": candidate,
                    "status": "free"
                }
            except Exception:
                # Timeout or other error -> ignore or treat as unknown
                return None

        # Concurrency is key here
        # Limit to maybe 50-100 threads? IANA list has ~1500 TLDs. 
        # 1500/100 = 15 batches. 2s timeout. ~30s scan. Acceptable.
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_tld = {executor.submit(check_tld, tld): tld for tld in all_tlds}
            
            for future in concurrent.futures.as_completed(future_to_tld):
                res = future.result()
                if res:
                    results["details"].append(res)
                    
                    if res["status"] == "free":
                        results["free_count"] += 1
                    elif res["status"] == "registered":
                        if res["same_owner"]:
                            results["registered_count_same"] += 1
                        else:
                            results["registered_count_diff_owner"] += 1

        return results
