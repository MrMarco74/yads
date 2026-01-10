import dns.resolver
import dns.reversename
import os
import requests
import logging
import time
import random
import uuid
from typing import Any, Dict, List, Set

from yads.core.base import BaseScannerModule
from yads.core.utils import check_stop_signal, StopSignalError

class DNSRecordScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "dns_scanner"

    def run_scan(self, target: str) -> Dict[str, Any]:
        logger = logging.getLogger("yads.modules.dns")
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
            if self.db_session:
                conf = self.db_session.get(SystemConfig, "CUSTOM_DNS_SERVERS")
                if conf and conf.value:
                    return [ip.strip() for ip in conf.value.split(',') if ip.strip()]
        except Exception:
            pass
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
                # Handle special cases for DMARC
                query_target = f"_dmarc.{target}" if rtype == 'DMARC' else target
                
                answers = resolver.resolve(query_target, rtype)
                results["records"][rtype] = [str(r) for r in answers]
                
                if rtype == 'NS':
                     results["nameservers"] = [str(r) for r in answers]

                # Check for Dangling CNAMEs
                if rtype == 'CNAME':
                    for cname_val in answers:
                        cname_str = str(cname_val).rstrip('.')
                        
                        # 1. Check Dangling
                        if self._is_dangling(cname_str):
                            results["dangling_cnames"].append(cname_str)
                            logger.info(f"Possible dangling CNAME found: {cname_str}")

                        # 2. Check Takeover
                        takeover = self._check_takeover(cname_str)
                        if takeover:
                            if "takeover_risks" not in results:
                                results["takeover_risks"] = []
                            # Add subdomain context if we knew it (here we are scanning target itself)
                            takeover["subdomain"] = target # The record we are querying IS the target here
                            results["takeover_risks"].append(takeover)
                            logger.warning(f"Takeover Risk detected! {target} -> {cname_str} ({takeover['provider']})")
                            
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                pass # Silent ignore for standard record missing

        # 1b. SPF fallback (from TXT)
        if 'TXT' in results["records"] and isinstance(results["records"]['TXT'], list):
            spf_records = [r for r in results["records"]['TXT'] if "v=spf1" in r]
            if spf_records:
                if 'SPF' not in results["records"] or not results["records"]['SPF']:
                    results["records"]['SPF'] = spf_records
                    
        return results
    
    def _detect_wildcard(self, domain: str, resolver: dns.resolver.Resolver) -> Set[str]:
        wildcard_ips = set()
        try:
            random_sub = f"{uuid.uuid4().hex[:8]}.{domain}"
            answers = resolver.resolve(random_sub, 'A')
            for r in answers:
                wildcard_ips.add(str(r))
        except:
            pass
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
                        resp = requests.get(f"http://{cname}", timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                        if sig["fingerprint"] in resp.text:
                            return {"provider": sig["provider"], "cname": cname, "status": "VULNERABLE"}
                    except:
                        pass
        except:
            pass
        return None

    def _is_dangling(self, cname_target: str) -> bool:
        try:
            dns.resolver.resolve(cname_target, 'A')
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except:
            return False

class SubdomainScanner(DNSRecordScanner):
    def __init__(self, db_session, use_ct_logs=True):
        super().__init__(db_session)
        self.use_ct_logs = use_ct_logs

    @property
    def module_name(self) -> str:
        return "subdomain_scanner"

    def run_scan(self, target: str) -> Dict[str, Any]:
        """
        Performs deep DNS analysis: Records + Subdomain Enumeration.
        """
        logger = logging.getLogger("yads.modules.subdomain")
        logger.info(f"Subdomain Scanner started for {target}")
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0 
        
        # Apply Custom DNS (Main Resolver)
        custom_ns = self._get_custom_nameservers()
        if custom_ns:
            resolver.nameservers = custom_ns
            logger.info(f"Using Custom DNS Servers: {custom_ns}")

        # 1. Scan Records first (Inherited logic reused manually or called)
        # We can call the helper
        results = self._scan_records(target, resolver, logger)
        
        # Initialize Subdomain specific fields
        results["subdomains"] = []
        results["reverse_dns"] = {}
        
        # Check Wildcard again for usage in enumeration (fetched in scan_records but not returned directly)
        # We can re-detect or modify _scan_records to return it. 
        # For simplicity, re-detect or rely on results["wildcard_detected"] but need IPs.
        wildcard_ips = self._detect_wildcard(target, resolver)
        
        # 2. Enhanced Subdomain Enumeration
        logger.info("Starting enhanced subdomain enumeration...")
        
        # A. Wordlist Enumeration
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "subdomains.txt")
        subs_to_scan = []
        defaults = [
            'www', 'mail', 'blog', 'dev', 'api', 'test', 'remote', 'vpn', 'stage', 'staging',
            'shop', 'cloud', 'portal', 'secure', 'admin', 'auth', 'm', 'mobile'
        ]
        
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    subs_to_scan = [line.strip() for line in f.read().splitlines() if line.strip()]
                for d in defaults:
                    if d not in subs_to_scan:
                        subs_to_scan.append(d)
            except:
                subs_to_scan = defaults
        else:
            subs_to_scan = defaults

        subs_to_scan = list(set(subs_to_scan))

        # B. Certificate Transparency (CRT.sh)
        # ONLY if enabled
        ct_subs = []
        if self.use_ct_logs:
            ct_subs = self._fetch_ct_logs(target)
        else:
            logger.info("Skipping CRT.sh (CT Logs) as SSL Scanner/CT is disabled.")
            
        potential_full_domains = set(ct_subs)
        
        for sub in subs_to_scan:
            if sub == '@':
                potential_full_domains.add(target)
            else:
                potential_full_domains.add(f"{sub}.{target}")
                
        # C. Parallel Verification
        import concurrent.futures
        verified_results = []
        shared_resolver = dns.resolver.Resolver()
        if custom_ns:
            shared_resolver.nameservers = custom_ns
        
        def verify_domain(full_domain):
            try:
                answers = shared_resolver.resolve(full_domain, 'A')
                ips = [str(r) for r in answers]
                if wildcard_ips:
                    if any(ip in wildcard_ips for ip in ips):
                         return None
                return {"subdomain": full_domain, "ips": ips}
            except dns.resolver.NoAnswer:
                # Domain exists (e.g. only has SOA/NS/AAAA) but no A record
                return {"subdomain": full_domain, "ips": []}
            except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
                return None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_sub = {executor.submit(verify_domain, sub): sub for sub in potential_full_domains}
            total_subs = len(potential_full_domains)
            completed_count = 0
            
            for future in concurrent.futures.as_completed(future_to_sub):
                completed_count += 1
                
                # Check for Stop Signal
                if completed_count % 10 == 0:
                    try:
                        check_stop_signal(self.db_session)
                    except StopSignalError:
                        logger.warning("Stop All detected during subdomain enumeration. Aborting.")
                        # Cancel remaining futures?
                        executor.shutdown(wait=False, cancel_futures=True)
                        raise

                # Log progress every 50 or 10%
                if completed_count % 50 == 0 or completed_count == total_subs:
                    logger.info(f"Subdomain Discovery Progress: {completed_count}/{total_subs} verified.")
                    
                res = future.result()
                if res:
                    verified_results.append(res)

        verified_results.sort(key=lambda x: x['subdomain'])
        results["subdomains"] = verified_results

        # 2b. Check Takeovers on Discovered Subdomains
        logger.info("Checking subdomains for takeover risks...")
        if "takeover_risks" not in results:
            results["takeover_risks"] = []
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            # Helper to check a single sub
            def check_sub_cname(sub_entry):
                sub_domain = sub_entry['subdomain']
                try:
                    cname_answers = shared_resolver.resolve(sub_domain, 'CNAME')
                    for cname_val in cname_answers:
                        cname_str = str(cname_val).rstrip('.')
                        risk = self._check_takeover(cname_str)
                        if risk:
                            risk["subdomain"] = sub_domain
                            return risk
                except:
                    pass
                return None

            future_to_cname = {executor.submit(check_sub_cname, sub): sub for sub in verified_results}
            for future in concurrent.futures.as_completed(future_to_cname):
                res = future.result()
                if res:
                    results["takeover_risks"].append(res)
                    logger.warning(f"Takeover Risk detected on subdomain! {res['subdomain']} -> {res['cname']} ({res['provider']})")

        # 3. Reverse DNS
        all_ips = set()
        if 'A' in results["records"] and results["records"]['A']:
             all_ips.update(results["records"]['A'])
        for sub in verified_results:
            all_ips.update(sub.get('ips', []))
            
        if len(all_ips) > 0:
            for i, ip in enumerate(all_ips):
                if i > 200: break
                entry = {"hostnames": [], "verified": False}
                try:
                    rev_name = dns.reversename.from_address(ip)
                    ptr_answers = resolver.resolve(rev_name, "PTR")
                    hostnames = [str(r).rstrip('.') for r in ptr_answers]
                    entry["hostnames"] = hostnames
                    for hostname in hostnames:
                        try:
                            fwd_answers = resolver.resolve(hostname, "A")
                            if ip in [str(r) for r in fwd_answers]:
                                entry["verified"] = True
                                break
                        except:
                            continue
                except:
                    pass
                if entry["hostnames"]:
                    results["reverse_dns"][ip] = entry

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
        except Exception:
            pass # Error during check, assume no wildcard to be safe or maybe log it?
            
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
        except Exception:
            # Other errors (timeout etc) don't necessarily mean dangling
            return False

