import dns.resolver
import dns.reversename
import os
from typing import Any, Dict, List

from yads.core.base import BaseScannerModule

class DNSScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "dns_scanner"

    def run_scan(self, target: str) -> Dict[str, Any]:
        """
        Performs deep DNS analysis.
        """
        results = {
            "records": {},
            "dangling_cnames": [],
            "nameservers": []
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'SPF', 'DMARC', 'NS', 'CNAME', 'SRV']
        
        import logging
        logger = logging.getLogger("yads.modules.dns")
        logger.info(f"DNS Scanner started for {target}")


        # 1. Fetch Records
        for rtype in record_types:
            try:
                logger.info(f"Querying {rtype} records...")
                # Handle special cases for DMARC (needs _dmarc. prefix)
                query_target = f"_dmarc.{target}" if rtype == 'DMARC' else target
                
                answers = resolver.resolve(query_target, rtype)
                results["records"][rtype] = [str(r) for r in answers]
                
                # Check for Dangling CNAMEs (Simplified: CNAME exists but points to NXDOMAIN)
                if rtype == 'CNAME':
                    for cname_val in answers:
                        cname_str = str(cname_val).rstrip('.')
                        if self._is_dangling(cname_str):
                            results["dangling_cnames"].append(cname_str)
                            
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # Fallback: Extract SPF from TXT if SPF record type allows (obsolete but techinically exists in lib) or isn't found
                if rtype == 'SPF':
                    # We might have found it in TXT already or will find it.
                    pass
                continue
            except Exception as e:
                results["records"][rtype] = f"Error: {str(e)}"

        # 1b. SPF fallback (common) - Check TXT records for 'v=spf1'
        if 'TXT' in results["records"] and isinstance(results["records"]['TXT'], list):
            spf_records = [r for r in results["records"]['TXT'] if "v=spf1" in r]
            if spf_records:
                # If we have SPF in TXT, map it to SPF key if empty
                if 'SPF' not in results["records"] or not results["records"]['SPF']:
                    results["records"]['SPF'] = spf_records

        # 2. Subdomain Enumeration
        logger.info("Starting subdomain enumeration...")
        # Expanded list based on user feedback + commons
        common_subdomains = [
            'www', 'mail', 'blog', 'dev', 'api', 'test', 'remote', 'vpn', 'stage', 'staging',
            'stefanie', 'marco', 'parkinson', 'lux', 'shop', 'cloud', 'portal', 'secure'
        ]
        results["subdomains"] = []
        
        # 2. Subdomain Enumeration
        logger.info("Starting subdomain enumeration...")
        results["subdomains"] = []
        
        # Load Wordlist
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "subdomains.txt")
        subs_to_scan = []
        
        # Default/Fallback list
        defaults = [
            'www', 'mail', 'blog', 'dev', 'api', 'test', 'remote', 'vpn', 'stage', 'staging',
            'stefanie', 'marco', 'parkinson', 'lux', 'shop', 'cloud', 'portal', 'secure'
        ]
        
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    # Read top 500 for performance balance
                    file_subs = [line.strip() for line in f.read().splitlines() if line.strip()]
                    subs_to_scan = file_subs[:500] 
                    # Ensure defaults are included
                    for d in defaults:
                        if d not in subs_to_scan:
                            subs_to_scan.append(d)
                logger.info(f"Loaded {len(subs_to_scan)} subdomains from wordlist (limited to top 500 + defaults)")
            except Exception as e:
                logger.error(f"Failed to load wordlist: {e}")
                subs_to_scan = defaults
        else:
            logger.warning("Wordlist not found, using defaults.")
            subs_to_scan = defaults

        # Parallel Execution
        import concurrent.futures
        
        def check_subdomain(sub):
            if sub == '@':
                full_domain = target
            else:
                full_domain = f"{sub}.{target}"
            
            try:
                # Use a fresh resolver instance for threads to be safe/clean
                t_resolver = dns.resolver.Resolver()
                t_resolver.timeout = 2.0
                t_resolver.lifetime = 2.0
                answers = t_resolver.resolve(full_domain, 'A')
                return {"subdomain": full_domain, "ips": [str(r) for r in answers]}
            except:
                return None

        # Add apex marker
        if '@' not in subs_to_scan:
             subs_to_scan.insert(0, '@')

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in subs_to_scan}
            completed_count = 0
            for future in concurrent.futures.as_completed(future_to_sub):
                completed_count += 1
                if completed_count % 50 == 0:
                    logger.info(f"Progress: {completed_count}/{len(subs_to_scan)} subdomains checked...")
                
                result = future.result()
                if result:
                    results["subdomains"].append(result)
                    logger.info(f"Found subdomain: {result['subdomain']}")

        # 3. Reverse DNS Round-Trip Verification
        if 'A' in results["records"] and isinstance(results["records"]['A'], list):
            results["reverse_dns"] = {}
            for ip in results["records"]['A']:
                entry = {"hostnames": [], "verified": False}
                try:
                    # 1. Reverse: IP -> Hostname (PTR)
                    rev_name = dns.reversename.from_address(ip)
                    ptr_answers = resolver.resolve(rev_name, "PTR")
                    hostnames = [str(r).rstrip('.') for r in ptr_answers]
                    entry["hostnames"] = hostnames
                    
                    # 2. Forward: Hostname -> IP
                    # Consistency check: Does one of the PTR hostnames resolve back to the original IP?
                    for hostname in hostnames:
                        try:
                            fwd_answers = resolver.resolve(hostname, "A")
                            fwd_ips = [str(r) for r in fwd_answers]
                            if ip in fwd_ips:
                                entry["verified"] = True
                                break
                        except:
                            continue
                            
                except Exception as e:
                    entry["error"] = str(e)
                
                results["reverse_dns"][ip] = entry

        return results

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
