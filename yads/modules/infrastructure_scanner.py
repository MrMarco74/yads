import socket
import logging
import dns.resolver
import datetime
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
        
        candidates = []
        # 1. Full domain with dashes
        candidates.append(domain.replace('.', '-'))
        # 2. Full domain as is
        candidates.append(domain)
        # 3. Domain without TLD (if possible) -> specific enough
        if '.' in domain:
            no_tld = domain.rsplit('.', 1)[0]
            candidates.append(no_tld.replace('.', '-'))
            candidates.append(no_tld)
        
        candidates = list(set(candidates))
        
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
        
        # 5. Whois & Expiration Monitor
        results["whois"] = {}
        try:
            import whois
            w = whois.whois(domain)
            
            # Format dates (handle list or single obj)
            def fmt_date(d):
                val = d
                if isinstance(d, list):
                     val = d[0] if d else None
                
                if not val:
                    return None
                    
                if hasattr(val, 'strftime'):
                    return val.strftime('%Y-%m-%d')
                return str(val)

            results["whois"] = {
                "registrar": w.registrar,
                "creation_date": fmt_date(w.creation_date),
                "expiration_date": fmt_date(w.expiration_date),
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            }
            
            # Calculate Days to Expire
            if w.expiration_date:
                exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if hasattr(exp, 'date'):
                    now = datetime.datetime.now().date()
                    delta = (exp.date() - now).days
                else:
                    now = datetime.datetime.now()
                    delta = (exp - now).days
                results["whois"]["days_to_expire"] = delta

        except Exception as e:
            logger.error(f"Whois Error: {e}")
            results["whois_error"] = str(e)

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
                
                link = "#"
                if "spamhaus" in dnsbl_domain:
                    link = f"https://check.spamhaus.org/listed/?searchterm={ip}"
                elif "spamcop" in dnsbl_domain:
                    link = f"https://www.spamcop.net/w3m?action=checkblock&ip={ip}"
                    
                findings.append({
                    "source": name, 
                    "message": f"Listed in {name}",
                    "link": link
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception as e:
                pass
                
        return findings
