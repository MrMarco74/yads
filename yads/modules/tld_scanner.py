
import logging
import dns.resolver
import requests
import concurrent.futures
import socket
from typing import Any, Dict, List, Optional
import tldextract

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

# Cache TLD list in memory to avoid fetching every time
_TLD_CACHE = []

def get_tld_list() -> List[str]:
    # Reduced default list for much faster scanning
    return ["com", "net", "org", "info", "biz", "de", "com.de", "eu", "at", "ch", "it", "fr", "es", "uk", "co.uk", "us", "io", "co", "me", "cloud", "app", "dev", "tech", "online", "store", "shop"]

class TLDScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "tld_scanner"

    def run_scan(self, domain: str, target_id: Optional[int] = None) -> Dict[str, Any]:
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
        
        # Cache for ASN lookups to avoid rate limits
        ip_asn_cache = {}
        
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
                primary_ip = ips[0]
                
                # It exists!
                
                # Disable IPWhois - it's too slow for bulk scans
                asn_info = {"asn": None, "org": "Unknown", "country": "Unknown"}
                
                # 2. Server Header (HTTP Request)
                server_header = None
                try:
                    # Quick HEAD request
                    h = requests.head(f"http://{candidate}", timeout=2, allow_redirects=True)  # nosec B113 — scanner probes typosquat candidate over http
                    server_header = h.headers.get("Server")
                except Exception:
                    pass

                # Check if matches reference
                match = False
                if ref_ips:
                    # If any IP shares commonality
                    if any(ip in ref_ips for ip in ips):
                        match = True
                
                return {
                    "tld": tld,
                    "domain": candidate,
                    "status": "registered",
                    "ips": ips,
                    "primary_ip": primary_ip,
                    "asn": asn_info,
                    "server": server_header,
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
        
        # Increase concurrency for faster DNS checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
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
