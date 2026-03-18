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
            "buckets": [],
            "spf_dmarc": {},
            "whois": {}
        }

        # 1. Resolve IP
        ip = self._resolve_ip(domain)
        if not ip:
            results["error"] = "Could not resolve IP (and DNS fallback failed)"
            return results
        results["ip"] = ip

        # 2. ASN & Geo Lookup
        asn_data = self._lookup_asn_and_cloud(ip)
        results.update(asn_data)

        # 3. GeoIP Lookup (IP-API)
        geo_data = self._lookup_geoip_enhanced(ip)
        if geo_data.get("geoip"):
            results["geoip"] = geo_data["geoip"]
        if geo_data.get("cloud_provider_geoip") and not results["cloud_provider"]:
            results["cloud_provider"] = geo_data["cloud_provider_geoip"]

        # 3.1 Fallback Logic (Prevent Data Loss if API fails)
        self._apply_infrastructure_fallback(domain, ip, results)

        # 4. Reputation Check
        results["reputation"] = self._check_reputation(ip)

        # 5. SPF/DMARC Pivot
        results["spf_dmarc"] = self._check_spf_dmarc(domain)

        # 6. Storage Bucket Check (AWS S3)
        results["buckets"] = self._check_s3_buckets(domain)
        
        # 7. Whois & Expiration Monitor
        results["whois"] = self._get_whois_details(domain)
        if "error" in results["whois"]:
            results["whois_error"] = results["whois"].pop("error")

        return results

    def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolves IP with DB fallback."""
        ip = None
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            logger.debug(f"IP resolution failed for {domain}: {e}")

        if not ip or ip == "0.0.0.0":
            if self.db:
                try:
                    t = self.db.exec(select(Target).where(Target.domain == domain)).first()
                    if t:
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
        return ip if ip and ip != "0.0.0.0" else None

    def _lookup_asn_and_cloud(self, ip: str) -> Dict[str, Any]:
        """ASN lookup and initial cloud provider detection."""
        res = {"asn": {}, "cloud_provider": None}
        try:
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)
            res["asn"] = {
                "asn": rdap.get("asn"),
                "asn_description": rdap.get("asn_description"),
                "asn_cidr": rdap.get("asn_cidr"),
                "country": rdap.get("asn_country_code"),
                "registry": rdap.get("asn_registry")
            }
            desc = (rdap.get("asn_description") or "").lower()
            cloud_map = {
                "amazon": "AWS", "aws": "AWS", "google": "Google Cloud",
                "microsoft": "Azure", "azure": "Azure", "digitalocean": "DigitalOcean",
                "hetzner": "Hetzner", "cloudflare": "Cloudflare"
            }
            for key, provider in cloud_map.items():
                if key in desc:
                    res["cloud_provider"] = provider
                    break
        except Exception as e:
            logger.error(f"Error in IPWhois: {e}")
            res["asn_error"] = str(e)
        return res

    def _lookup_geoip_enhanced(self, ip: str) -> Dict[str, Any]:
        """Enhanced GeoIP and provider detection via IP-API."""
        import requests
        res = {"geoip": None, "cloud_provider_geoip": None}
        try:
            geo_resp = requests.get(f"https://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,timezone,isp,org,as", timeout=3)
            if geo_resp.status_code == 200:
                geo_data = geo_resp.json()
                if geo_data.get("status") == "success":
                    res["geoip"] = {
                        "country_name": geo_data.get("country"),
                        "country_code": geo_data.get("countryCode"),
                        "city": geo_data.get("city"),
                        "lat": geo_data.get("lat"),
                        "lon": geo_data.get("lon"),
                        "isp": geo_data.get("isp"),
                        "org": geo_data.get("org")
                    }
                    isp_org = ((geo_data.get("isp") or "") + " " + (geo_data.get("org") or "")).lower()
                    cloud_map = {
                        "amazon": "AWS", "aws": "AWS", "google": "GCP",
                        "microsoft": "Azure", "azure": "Azure", "hetzner": "Hetzner",
                        "digitalocean": "DigitalOcean", "cloudflare": "Cloudflare"
                    }
                    for key, provider in cloud_map.items():
                        if key in isp_org:
                            res["cloud_provider_geoip"] = provider
                            break
        except Exception as e:
            logger.error(f"GeoIP Lookup Failed: {e}")
        return res

    def _apply_infrastructure_fallback(self, domain: str, ip: str, results: Dict[str, Any]):
        """Reuses cached infrastructure data if APIs fail."""
        if not ip or not self.db or (results.get("geoip") and results.get("cloud_provider")):
            return
        try:
            t_obj = self.db.exec(select(Target).where(Target.domain == domain)).first()
            if t_obj:
                prev_res = self.db.exec(select(ScanResult).where(
                    ScanResult.target_id == t_obj.id,
                    ScanResult.module_name == "infrastructure_scanner"
                ).order_by(ScanResult.scanned_at.desc())).first()
                if prev_res and prev_res.data and prev_res.data.get("ip") == ip:
                    if not results.get("geoip") and prev_res.data.get("geoip"):
                        results["geoip"] = prev_res.data.get("geoip")
                    if not results.get("cloud_provider") and prev_res.data.get("cloud_provider"):
                        results["cloud_provider"] = prev_res.data.get("cloud_provider")
        except Exception as ex:
            logger.error(f"Infrastructure fallback failed: {ex}")

    def _check_bucket_status(self, cand: str) -> Optional[Dict[str, Any]]:
        """Checks if a specific S3 bucket candidate exists/is public."""
        import requests
        s3_url = f"http://{cand}.s3.amazonaws.com"
        try:
            resp = requests.head(s3_url, timeout=2)
            if resp.status_code != 404:
                status = "Public" if resp.status_code == 200 else "Protected"
                return {"url": s3_url, "status": status, "code": resp.status_code}
        except Exception as e:
            logger.debug(f"S3 bucket check failed for {cand}: {e}")
        return None

    def _check_s3_buckets(self, domain: str) -> List[Dict[str, Any]]:
        """Enumerates S3 bucket candidates in parallel."""
        import concurrent.futures
        candidates = list(set([domain.replace('.', '-'), domain]))
        if '.' in domain:
            no_tld = domain.rsplit('.', 1)[0]
            candidates.extend([no_tld.replace('.', '-'), no_tld])
        candidates = list(set(candidates))
        buckets = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_cand = {executor.submit(self._check_bucket_status, c): c for c in candidates}
            for i, future in enumerate(concurrent.futures.as_completed(future_to_cand)):
                if i % 5 == 0:
                    check_stop_signal(self.db)
                res = future.result()
                if res:
                    buckets.append(res)
        return buckets

    def _format_whois_date(self, d: Any) -> Optional[str]:
        """Formats whois date objects/lists to string."""
        val = d[0] if isinstance(d, list) and d else d
        if not val: return None
        if hasattr(val, 'strftime'): return val.strftime('%Y-%m-%d')
        return str(val)

    def _get_whois_details(self, domain: str) -> Dict[str, Any]:
        """Fetches and parses Whois data."""
        try:
            import whois
            w = whois.whois(domain)
            res = {
                "registrar": w.registrar,
                "creation_date": self._format_whois_date(w.creation_date),
                "expiration_date": self._format_whois_date(w.expiration_date),
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            }
            if w.expiration_date:
                exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                now = datetime.datetime.now().date() if hasattr(exp, 'date') else datetime.datetime.now()
                delta = (exp.date() - now).days if hasattr(exp, 'date') else (exp - now).days
                res["days_to_expire"] = delta
            return res
        except Exception as e:
            logger.error(f"Whois Error: {e}")
            return {"error": str(e)}

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
                logger.debug(f"DNSBL check failed for {query}: {e}")
                
        return findings

    def _check_spf_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Extracts domains from SPF and DMARC records for pivoting.
        """
        results = {
            "spf_includes": [],
            "dmarc_emails": []
        }
        
        # 1. SPF Check
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    # Parse includes and redirects
                    parts = txt.split()
                    for part in parts:
                        if part.startswith("include:"):
                            val = part.split(":", 1)[1]
                            results["spf_includes"].append(val)
                        elif part.startswith("redirect="):
                            val = part.split("=", 1)[1]
                            results["spf_includes"].append(val)
        except Exception as e:
            logger.debug(f"SPF check failed for {domain}: {e}")
            
        # 2. DMARC Check
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    # Parse RUA/RUF
                    # Example: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
                    parts = txt.split(";")
                    for part in parts:
                        part = part.strip()
                        if part.startswith("rua=") or part.startswith("ruf="):
                            if "mailto:" in part:
                                email = part.split("mailto:", 1)[1]
                                if "@" in email:
                                    d_domain = email.split("@")[1]
                                    if d_domain not in results["dmarc_emails"]:
                                        results["dmarc_emails"].append(d_domain)
        except Exception as e:
            logger.debug(f"DMARC check failed for {domain}: {e}")
            
        return results
