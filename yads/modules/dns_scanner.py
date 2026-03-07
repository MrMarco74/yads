import dns.resolver
import dns.reversename
import os
import requests
import logging
import time
import random
import uuid
from typing import Any, Dict, List, Set, Optional

from yads.core.base import BaseScannerModule
from yads.core.utils import check_stop_signal, StopSignalError

logger = logging.getLogger(__name__)

class DNSRecordScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "dns_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"DNS Record Scan started for {target}")
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        
        # Apply Custom DNS
        custom_ns = self._get_custom_nameservers()
        if custom_ns:
            resolver.nameservers = custom_ns
            logger.info(f"Using Custom DNS Servers: {custom_ns}")
        
        return self._scan_records(target, resolver, logger)

    def _get_custom_nameservers(self) -> List[str]:
        try:
            from yads.models import SystemConfig
            if self.db:
                conf = self.db.get(SystemConfig, "CUSTOM_DNS_SERVERS")
                if conf and conf.value:
                    return [ip.strip() for ip in conf.value.split(',') if ip.strip()]
        except Exception as e:
            logger.debug(f"Failed to load custom nameservers: {e}")
        return []

    def _scan_records(self, target: str, resolver: dns.resolver.Resolver, logger: logging.Logger) -> Dict[str, Any]:
        results = {
            "records": {},
            "dangling_cnames": [],
            "nameservers": [],
            "wildcard_detected": False
        }
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'SPF', 'DMARC', 'NS', 'CNAME', 'SRV', 'SOA']

        # 0. Wildcard Detection
        wildcard_ips = self._detect_wildcard(target, resolver)
        if wildcard_ips:
            logger.warning(f"Wildcard DNS detected for {target}. IPs: {wildcard_ips}.")
            results["wildcard_detected"] = True
        
        # 1. Fetch Records
        for rtype in record_types:
            try:
                query_target = f"_dmarc.{target}" if rtype == 'DMARC' else target
                q_type = 'TXT' if rtype == 'DMARC' else rtype

                answers = resolver.resolve(query_target, q_type)
                results["records"][rtype] = [str(r).strip('"') for r in answers]
                
                if rtype == 'NS':
                     results["nameservers"] = [str(r).strip('.') for r in answers]

                if rtype == 'CNAME':
                    for cname_val in answers:
                        cname_str = str(cname_val).rstrip('.')
                        if self._is_dangling(cname_str):
                            results["dangling_cnames"].append(cname_str)
                            logger.info(f"Possible dangling CNAME found: {cname_str}")

                        takeover = self._check_takeover(cname_str)
                        if takeover:
                            if "takeover_risks" not in results:
                                results["takeover_risks"] = []
                            takeover["subdomain"] = target
                            results["takeover_risks"].append(takeover)
                            logger.warning(f"Takeover Risk detected! {target} -> {cname_str} ({takeover['provider']})")
                            
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception:
                pass

        # 2. Email Security Data
        results["email_security"] = {
            "spf": self._parse_spf(results["records"].get('TXT', [])),
            "dmarc": self._parse_dmarc(results["records"].get('DMARC', []))
        }
                    
        return results

    def _parse_spf(self, txt_records: List[str]) -> Dict[str, Any]:
        """Parses SPF records from TXT results."""
        res = {"present": False, "record": None, "status": "missing"}
        for r in txt_records:
            if r.startswith("v=spf1") or "v=spf1" in r:
                res["present"] = True
                res["record"] = r
                if "-all" in r: res["status"] = "strong"
                elif "~all" in r: res["status"] = "softfail"
                elif "+all" in r: res["status"] = "insecure"
                elif "?all" in r: res["status"] = "neutral"
                else: res["status"] = "moderate"
                break
        return res

    def _parse_dmarc(self, dmarc_records: List[str]) -> Dict[str, Any]:
        """Parses DMARC records."""
        res = {"present": False, "record": None, "policy": "none", "status": "missing"}
        for r in dmarc_records:
            if r.startswith("v=DMARC1") or "v=DMARC1" in r:
                res["present"] = True
                res["record"] = r
                import re
                p_match = re.search(r"p=(none|quarantine|reject)", r)
                if p_match:
                    policy = p_match.group(1)
                    res["policy"] = policy
                    if policy == "reject": res["status"] = "secure"
                    elif policy == "quarantine": res["status"] = "moderate"
                    else: res["status"] = "monitoring"
                else:
                    res["status"] = "invalid"
                break
        return res
    
    def _detect_wildcard(self, domain: str, resolver: dns.resolver.Resolver) -> Set[str]:
        wildcard_ips = set()
        try:
            random_sub = f"{uuid.uuid4().hex[:8]}.{domain}"
            answers = resolver.resolve(random_sub, 'A')
            for r in answers:
                wildcard_ips.add(str(r))
        except Exception as e:
            logger.debug(f"Wildcard detection failed for {domain}: {e}")
        return wildcard_ips

    def _check_takeover(self, cname: str) -> Dict[str, str]:
        """
        Checks if a CNAME points to a known cloud provider and if the resource is unclaimed.
        """
        signatures = {
            "github.io": {"provider": "GitHub Pages", "fingerprint": "There isn't a GitHub Pages site here."},
            "herokuapp.com": {"provider": "Heroku", "fingerprint": "Heroku | No such app"},
            "s3.amazonaws.com": {"provider": "AWS S3", "fingerprint": "NoSuchBucket"},
            "azurewebsites.net": {"provider": "Azure", "fingerprint": "404 Web Site not found"},
            "bitbucket.org": {"provider": "Bitbucket", "fingerprint": "Repository not found"},
            "unbouncepages.com": {"provider": "Unbounce", "fingerprint": "The requested URL was not found on this server."},
            "ghs.google.com": {"provider": "Google Cloud", "fingerprint": "404. That’s an error."},
            "pantheonsite.io": {"provider": "Pantheon", "fingerprint": "404 Not Found"},
            "readme.io": {"provider": "Readme.io", "fingerprint": "Project doesnt exist... yet!"},
            "myshopify.com": {"provider": "Shopify", "fingerprint": "Sorry, this shop is currently unavailable."}
        }

        try:
            for domain, sig in signatures.items():
                if domain in cname:
                    # Potential match, verify fingerprint
                    # We presume http unless it handles https well. most takeover checks are http.
                    try:
                        resp = requests.get(f"http://{cname}", timeout=5, headers={"User-Agent": "YADS-Security-Scanner/1.19 (+https://yads-security.com)"})
                        if sig["fingerprint"] in resp.text:
                            return {"provider": sig["provider"], "cname": cname, "status": "VULNERABLE"}
                    except Exception as e:
                        logger.debug(f"Takeover fingerprint request failed for {cname}: {e}")
        except Exception as e:
            logger.debug(f"Takeover check outer error for {cname}: {e}")
        return None

    def _is_dangling(self, cname_target: str) -> bool:
        try:
            dns.resolver.resolve(cname_target, 'A')
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception as e:
            logger.debug(f"Dangling CNAME check failed for {cname_target}: {e}")
            return False

class SubdomainScanner(DNSRecordScanner):
    def __init__(self, db_session, use_ct_logs=True):
        super().__init__(db_session)
        self.use_ct_logs = use_ct_logs

    @property
    def module_name(self) -> str:
        return "subdomain_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """Performs deep DNS analysis: Records + Subdomain Enumeration."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0 
        
        custom_ns = self._get_custom_nameservers()
        if custom_ns: resolver.nameservers = custom_ns

        # 1. Base Scan
        results = self._scan_records(target, resolver, logger)
        results.update({"subdomains": [], "reverse_dns": {}})
        wildcard_ips = self._detect_wildcard(target, resolver)
        
        # 2. Enumeration Prep
        potential_full_domains = set()
        if self.use_ct_logs:
            potential_full_domains.update(self._fetch_ct_logs(target))

        # CT Org Cross-Query: find other apex domains owned by same org
        results["ct_related_domains"] = self._fetch_ct_related_domains(target)
        
        wordlist_subs = self._load_subdomain_wordlist()
        for sub in wordlist_subs:
            potential_full_domains.add(target if sub == '@' else f"{sub}.{target}")

        # 3. Parallel Discovery
        results["subdomains"] = self._verify_subdomains_parallel(potential_full_domains, wildcard_ips, custom_ns, logger)
        results["subdomains"].sort(key=lambda x: x['subdomain'])

        # 4. Takeover Risks
        if "takeover_risks" not in results: results["takeover_risks"] = []
        results["takeover_risks"].extend(self._check_subdomain_takeovers_parallel(results["subdomains"], custom_ns, logger))

        # 5. Reverse DNS
        all_ips = set(results["records"].get('A', []))
        for sub in results["subdomains"]: all_ips.update(sub.get('ips', []))
        results["reverse_dns"] = self._perform_reverse_dns(all_ips, resolver, logger)

        return results

    def _load_subdomain_wordlist(self) -> List[str]:
        """Loads subdomain wordlist from file or defaults."""
        defaults = ['www', 'mail', 'blog', 'dev', 'api', 'test', 'remote', 'vpn', 'stage', 'staging', 'shop', 'cloud', 'portal', 'secure', 'admin', 'auth', 'm', 'mobile']
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "subdomains.txt")
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return list(set(defaults + [line.strip() for line in f.read().splitlines() if line.strip()]))
            except Exception:
                pass
        return defaults

    def _verify_subdomains_parallel(self, domains: Set[str], wildcard_ips: Set[str], custom_ns: List[str], logger: logging.Logger) -> List[Dict[str, Any]]:
        """Verifies subdomains in parallel."""
        import concurrent.futures
        verified = []
        res = dns.resolver.Resolver()
        if custom_ns: res.nameservers = custom_ns
        
        def check(d):
            try:
                ans = res.resolve(d, 'A')
                ips = [str(r) for r in ans]
                if wildcard_ips and any(ip in wildcard_ips for ip in ips): return None
                return {"subdomain": d, "ips": ips}
            except dns.resolver.NoAnswer: return {"subdomain": d, "ips": []}
            except (dns.resolver.NXDOMAIN, Exception): return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            fut = {executor.submit(check, d): d for d in domains}
            for i, f in enumerate(concurrent.futures.as_completed(fut)):
                if i % 10 == 0: check_stop_signal(self.db)
                val = f.result()
                if val: verified.append(val)
        return verified

    def _check_subdomain_takeovers_parallel(self, sub_entries: List[Dict[str, Any]], custom_ns: List[str], logger: logging.Logger) -> List[Dict[str, Any]]:
        """Checks discovered subdomains for takeover risks."""
        import concurrent.futures
        risks = []
        res = dns.resolver.Resolver()
        if custom_ns: res.nameservers = custom_ns

        def check_sub(entry):
            sub = entry['subdomain']
            try:
                ans = res.resolve(sub, 'CNAME')
                for c in ans:
                    risk = self._check_takeover(str(c).rstrip('.'))
                    if risk:
                        risk["subdomain"] = sub
                        return risk
            except Exception: pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            fut = {executor.submit(check_sub, s): s for s in sub_entries}
            for f in concurrent.futures.as_completed(fut):
                val = f.result()
                if val: risks.append(val)
        return risks

    def _perform_reverse_dns(self, ips: Set[str], resolver: dns.resolver.Resolver, logger: logging.Logger) -> Dict[str, Any]:
        """Performs PTR lookups for a set of IPs."""
        rev_res = {}
        for i, ip in enumerate(list(ips)[:200]): # Limit to 200 IPs
            try:
                ptr = resolver.resolve(dns.reversename.from_address(ip), "PTR")
                hosts = [str(r).rstrip('.') for r in ptr]
                entry = {"hostnames": hosts, "verified": False}
                for h in hosts:
                    try:
                        fwd = resolver.resolve(h, "A")
                        if ip in [str(r) for r in fwd]:
                            entry["verified"] = True
                            break
                    except Exception: continue
                rev_res[ip] = entry
            except Exception: pass
        return rev_res

        return results

    def _fetch_ct_logs(self, domain: str) -> List[str]:
        """
        Queries crt.sh via PostgreSQL (Direct Connection) to find subdomains.
        Includes fallback to Hackertarget if PostgreSQL fails.
        """
        try:
            from yads.modules.crtSH_client import search_domain
            subs = search_domain(domain)
            if subs:
                return subs
        except ImportError:
            logging.getLogger("yads.modules.dns").error("Could not import crtSH_client. is psycopg2 installed?")
        except Exception as e:
             logging.getLogger("yads.modules.dns").warning(f"crt.sh (PG) failed: {e}")

        # If we get here, crt.sh failed or returned nothing. Try Fallback.
        logging.getLogger("yads.modules.dns").warning("crt.sh exhaustion/failure. Attempting Fallback: Hackertarget.")
        return self._fetch_hackertarget(domain)

    def _fetch_hackertarget(self, domain: str) -> List[str]:
        """
        Fallback source: Hackertarget API
        """
        subs = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    # Format: hostname,ip
                    parts = line.split(',')
                    if len(parts) >= 1:
                        hostname = parts[0].strip()
                        if hostname.endswith(domain):
                            subs.add(hostname)
                logging.getLogger("yads.modules.dns").info(f"Hackertarget found {len(subs)} subdomains.")
        except Exception as e:
             logging.getLogger("yads.modules.dns").error(f"Hackertarget fallback failed: {e}")

        return list(subs)

    def _fetch_ct_related_domains(self, domain: str) -> List[str]:
        """
        Queries crt.sh for other apex domains owned by the same organisation
        or e-mail address found in the target's TLS certificate.
        Returns a sorted list of related domains (excluding the target itself).
        """
        log = logging.getLogger("yads.modules.dns")
        try:
            from yads.modules.ssl_scanner import SSLScanner
            from yads.modules.crtSH_client import search_by_org

            ssl_data = SSLScanner().run_scan(domain)
            org = ssl_data.get("ct_org")
            email = ssl_data.get("ct_email")

            if not org and not email:
                log.info(f"CT org query skipped for {domain}: no org/email in cert")
                return []

            log.info(f"CT org query for {domain}: org='{org}' email='{email}'")
            return search_by_org(org_name=org, email=email, exclude_domain=domain)

        except Exception as e:
            log.warning(f"CT org cross-query failed for {domain}: {e}")
            return []


    def _detect_wildcard(self, domain: str, resolver: dns.resolver.Resolver) -> Set[str]:
        """
        Detects if a wildcard record exists for the domain.
        Returns a set of IPs that wildcard subdomains resolve to.
        """
        wildcard_ips = set()
        try:
            # Generate a random subdomain that definitely shouldn't exist
            random_sub = f"{uuid.uuid4().hex[:8]}.{domain}"
            answers = resolver.resolve(random_sub, 'A')
            for r in answers:
                wildcard_ips.add(str(r))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass # No wildcard
        except Exception as e:
            logger.debug(f"Wildcard detection error for {domain}: {e}")
            
        return wildcard_ips

    def _is_dangling(self, cname_target: str) -> bool:
        """
        Checks if a CNAME target does not verify.
        """
        try:
            dns.resolver.resolve(cname_target, 'A')
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception as e:
            # Other errors (timeout etc.) don't necessarily mean dangling
            logger.debug(f"Dangling CNAME check error for {cname_target}: {e}")
            return False

