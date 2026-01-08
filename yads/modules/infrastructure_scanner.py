import socket
import logging
import dns.resolver
from typing import Any, Dict, List
from ipwhois import IPWhois

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

class InfrastructureScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "infrastructure_scanner"

    def run_scan(self, domain: str) -> Dict[str, Any]:
        """
        Performs infrastructure analysis:
        1. Resolve IP
        2. ASN/Geo Lookup (ipwhois)
        3. Cloud Provider Guess
        4. Basic Reputation Check (Placeholder)
        """
        results = {
            "ip": None,
            "asn": {},
            "cloud_provider": None,
            "reputation": [],
            "buckets": []
        }

        # 1. Resolve IP
        try:
            ip = socket.gethostbyname(domain)
            results["ip"] = ip
        except Exception as e:
            results["error"] = f"Could not resolve domain: {e}"
            return results

        # 2. ASN & Geo Lookup
        try:
            obj = IPWhois(ip)
            # using asn_methods=['dns', 'whois', 'http'] can be slow, default is usually fine
            rdap = obj.lookup_rdap(depth=1)
            
            results["asn"] = {
                "asn": rdap.get("asn"),
                "asn_description": rdap.get("asn_description"),
                "asn_cidr": rdap.get("asn_cidr"),
                "country": rdap.get("asn_country_code"),
                "registry": rdap.get("asn_registry")
            }
            
            # 3. Simple Cloud Provider Map
            desc = (rdap.get("asn_description") or "").lower()
            if "amazon" in desc or "aws" in desc:
                results["cloud_provider"] = "AWS"
            elif "google" in desc:
                results["cloud_provider"] = "Google Cloud"
            elif "microsoft" in desc or "azure" in desc:
                results["cloud_provider"] = "Azure"
            elif "digitalocean" in desc:
                results["cloud_provider"] = "DigitalOcean"
            elif "hetzner" in desc:
                results["cloud_provider"] = "Hetzner"
            elif "cloudflare" in desc:
                results["cloud_provider"] = "Cloudflare"

        except Exception as e:
            logger.error(f"Error in IPWhois: {e}")
            results["asn_error"] = str(e)

        # 4. Reputation Check
        if results["ip"]:
            results["reputation"] = self._check_reputation(results["ip"])

        # 4. Storage Bucket Check (AWS S3)
        # Check standard public bucket patterns
        import requests
        import concurrent.futures
        
        bucket_name = domain.split('.')[0] # e.g. "example" from "example.com"
        # Also try full domain
        candidates = [bucket_name, domain.replace('.', '-'), domain]
        
        def check_bucket(cand):
            s3_url = f"http://{cand}.s3.amazonaws.com"
            try:
                resp = requests.head(s3_url, timeout=2)
                if resp.status_code != 404:
                    # 403 means exists but private (still interesting), 200 means public!
                    status = "Public" if resp.status_code == 200 else "Protected"
                    return {
                        "url": s3_url,
                        "status": status,
                        "code": resp.status_code
                    }
            except:
                pass
            return None

        # Run checks in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_cand = {executor.submit(check_bucket, c): c for c in candidates}
            for future in concurrent.futures.as_completed(future_to_cand):
                res = future.result()
                if res:
                    results["buckets"].append(res)

        return results

    def _check_reputation(self, ip: str) -> List[str]:
        """
        Checks IP against common DNSBLs.
        """
        findings = []
        reversed_ip = ".".join(reversed(ip.split(".")))
        
        dnsbls = {
            "zen.spamhaus.org": "Spamhaus (Zen)",
            "bl.spamcop.net": "SpamCop"
        }
        
        # Shared/Cached Resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for dnsbl_domain, name in dnsbls.items():
            query = f"{reversed_ip}.{dnsbl_domain}"
            try:
                resolver.resolve(query, 'A')
                # If we get an answer, it's listed
                findings.append(f"Listed in {name}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception as e:
                pass
                
        return findings
