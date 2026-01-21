import socket
import logging
import dns.resolver
import datetime
from typing import Any, Dict, List, Optional
from ipwhois import IPWhois

from yads.core.base import BaseScannerModule
from yads.core.utils import check_stop_signal, StopSignalError
from sqlmodel import select
from yads.models import Target, ScanResult

logger = logging.getLogger(__name__)

class InfrastructureScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "infrastructure_scanner"

    def run_scan(self, domain: str, target_id: Optional[int] = None) -> Dict[str, Any]:
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
        # 1. Resolve IP
        ip = None
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            pass

        # Fallback to DB if failed or 0.0.0.0
        if not ip or ip == "0.0.0.0":
             if self.db:
                 try:
                     # Find target ID
                     t = self.db.exec(select(Target).where(Target.domain == domain)).first()
                     if t:
                         # Get latest DNS result
                         dns_res = self.db.exec(select(ScanResult).where(
                             ScanResult.target_id == t.id, 
                             ScanResult.module_name == "dns_scanner"
                         ).order_by(ScanResult.scanned_at.desc())).first()
                         
                         if dns_res and dns_res.data and "records" in dns_res.data:
                             a_records = dns_res.data["records"].get("A", [])
                             if a_records:
                                 ip = a_records[0]
                 except Exception as e:
                     logger.error(f"DB DNS Fallback failed: {e}")

        if not ip or ip == "0.0.0.0":
            results["error"] = "Could not resolve IP (and DNS fallback failed)"
            return results
            
        results["ip"] = ip

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

        # 3.5 GeoIP Lookup (IP-API)
        # Re-adding functionality for "Global Map" as requested.
        try:
            import requests
            # Limited to 45 requests per minute. Fine for single threaded worker or slow queue.
            # If high concurrency, we need a local DB.
            geo_resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,timezone,isp,org,as", timeout=3)
            if geo_resp.status_code == 200:
                geo_data = geo_resp.json()
                if geo_data.get("status") == "success":
                    results["geoip"] = {
                        "country_name": geo_data.get("country"),
                        "country_code": geo_data.get("countryCode"),
                        "city": geo_data.get("city"),
                        "lat": geo_data.get("lat"),
                        "lon": geo_data.get("lon"),
                        "isp": geo_data.get("isp"),
                        "org": geo_data.get("org")
                    }
                    
                    # Enhanced Cloud Provider Detection via ISP/Org from GeoIP
                    # Sometimes better than WHOIS desc
                    isp_org = (geo_data.get("isp") or "") + " " + (geo_data.get("org") or "")
                    isp_org = isp_org.lower()
                    
                    if not results["cloud_provider"]:
                         if "amazon" in isp_org or "aws" in isp_org: results["cloud_provider"] = "AWS"
                         elif "google" in isp_org: results["cloud_provider"] = "GCP"
                         elif "microsoft" in isp_org or "azure" in isp_org: results["cloud_provider"] = "Azure"
                         elif "hetzner" in isp_org: results["cloud_provider"] = "Hetzner"
                         elif "digitalocean" in isp_org: results["cloud_provider"] = "DigitalOcean"
                         elif "cloudflare" in isp_org: results["cloud_provider"] = "Cloudflare"

        except Exception as e:
            logger.error(f"GeoIP Lookup Failed: {e}") 
        
        # 3.6 Fallback Logic (Prevent Data Loss if API fails)
        # If we have an IP, but no GeoIP/Cloud Provider (due to rate limit/timeout), 
        # check if we have a previous result for this IP and reuse it.
        if results["ip"] and (not results.get("geoip") or not results.get("cloud_provider")):
            if self.db:
                try:
                    # Find target ID (we need it to query scanresult)
                    # Note: We rely on domain matching here.
                    t_obj = self.db.exec(select(Target).where(Target.domain == domain)).first()
                    if t_obj:
                         prev_res = self.db.exec(select(ScanResult).where(
                             ScanResult.target_id == t_obj.id,
                             ScanResult.module_name == "infrastructure_scanner"
                         ).order_by(ScanResult.scanned_at.desc())).first()
                         
                         if prev_res and prev_res.data:
                             prev_ip = prev_res.data.get("ip")
                             
                             # Only reuse if IP hasn't changed!
                             if prev_ip == results["ip"]:
                                 # Reuse GeoIP if missing
                                 if not results.get("geoip") and prev_res.data.get("geoip"):
                                     results["geoip"] = prev_res.data.get("geoip")
                                     logger.info(f"Reused cached GeoIP for {domain} (API failed)")
                                     
                                 # Reuse Cloud Provider if missing
                                 if not results.get("cloud_provider") and prev_res.data.get("cloud_provider"):
                                     results["cloud_provider"] = prev_res.data.get("cloud_provider")
                                     logger.info(f"Reused cached CloudProvider for {domain}")
                                     
                except Exception as ex:
                    logger.error(f"Fallback logic failed: {ex}")


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
            for i, future in enumerate(concurrent.futures.as_completed(future_to_cand)):
                if i % 5 == 0:
                     check_stop_signal(self.db)
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
