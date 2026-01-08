import dns.resolver
import dns.reversename
import os
import requests
import logging
from typing import Any, Dict, List, Set

from yads.core.base import BaseScannerModule

class DNSScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "dns_scanner"

    def run_scan(self, target: str) -> Dict[str, Any]:
        """
        Performs deep DNS analysis including Certificate Transparency log enumeration.
        """
        results = {
            "records": {},
            "dangling_cnames": [],
            "nameservers": [],
            "subdomains": []
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'SPF', 'DMARC', 'NS', 'CNAME', 'SRV', 'SOA']
        
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
                
                if rtype == 'NS':
                     results["nameservers"] = [str(r) for r in answers]

                # Check for Dangling CNAMEs
                if rtype == 'CNAME':
                    for cname_val in answers:
                        cname_str = str(cname_val).rstrip('.')
                        if self._is_dangling(cname_str):
                            results["dangling_cnames"].append(cname_str)
                            logger.info(f"Possible dangling CNAME found: {cname_str}")
                            
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                results["records"][rtype] = f"Error: {str(e)}"

        # 1b. SPF fallback
        if 'TXT' in results["records"] and isinstance(results["records"]['TXT'], list):
            spf_records = [r for r in results["records"]['TXT'] if "v=spf1" in r]
            if spf_records:
                if 'SPF' not in results["records"] or not results["records"]['SPF']:
                    results["records"]['SPF'] = spf_records

        # 2. Enhanced Subdomain Enumeration
        logger.info("Starting enhanced subdomain enumeration...")
        
        # A. Wordlist Enumeration
        found_subs_set = set() # Store plain subdomains here (e.g., 'www.example.com')
        
        # Load Wordlist (Unlimited)
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "subdomains.txt")
        subs_to_scan = []
        
        # Default list
        defaults = [
            'www', 'mail', 'blog', 'dev', 'api', 'test', 'remote', 'vpn', 'stage', 'staging',
            'shop', 'cloud', 'portal', 'secure', 'admin', 'auth', 'm', 'mobile'
        ]
        
        if os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    # No limit, read all
                    subs_to_scan = [line.strip() for line in f.read().splitlines() if line.strip()]
                # Add defaults
                for d in defaults:
                    if d not in subs_to_scan:
                        subs_to_scan.append(d)
                logger.info(f"Loaded {len(subs_to_scan)} potential subdomains from wordlist.")
            except Exception as e:
                logger.error(f"Failed to load wordlist: {e}")
                subs_to_scan = defaults
        else:
            subs_to_scan = defaults

        # Filter duplicates in scan list
        subs_to_scan = list(set(subs_to_scan))

        # B. Certificate Transparency (CRT.sh)
        logger.info("Querying crt.sh for CT logs...")
        ct_subs = self._fetch_ct_logs(target)
        logger.info(f"Retrieved {len(ct_subs)} unique subdomains from CT logs.")
        
        # Add found CT subs directly to candidacy for IP resolution
        # Note: CT logs give full domains (e.g., 'test.target.com')
        potential_full_domains = set(ct_subs)
        
        # Create full domains from wordlist
        for sub in subs_to_scan:
            if sub == '@':
                potential_full_domains.add(target)
            else:
                potential_full_domains.add(f"{sub}.{target}")
                
        logger.info(f"Total unique candidates to verify: {len(potential_full_domains)}")

        # C. Parallel Verification (Resolve IPs)
        import concurrent.futures
        
        verified_results = []
        
        def verify_domain(full_domain):
            try:
                # Use a fresh resolver
                t_resolver = dns.resolver.Resolver()
                t_resolver.timeout = 2.0
                t_resolver.lifetime = 2.0
                # Resolve A record
                answers = t_resolver.resolve(full_domain, 'A')
                return {"subdomain": full_domain, "ips": [str(r) for r in answers]}
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_sub = {executor.submit(verify_domain, sub): sub for sub in potential_full_domains}
            completed = 0
            for future in concurrent.futures.as_completed(future_to_sub):
                completed += 1
                if completed % 100 == 0:
                    logger.info(f"Verified {completed}/{len(potential_full_domains)}...")
                
                res = future.result()
                if res:
                    verified_results.append(res)

        logger.info(f"Verification complete. Found {len(verified_results)} active subdomains.")
        
        # Sort by subdomain name
        verified_results.sort(key=lambda x: x['subdomain'])
        results["subdomains"] = verified_results

        # 3. Reverse DNS (keep existing logic)
        # Flatten IPs from subdomains into a set to reverse scan all interesting IPs
        all_ips = set()
        if 'A' in results["records"] and results["records"]['A']:
             all_ips.update(results["records"]['A'])
        
        for sub in verified_results:
            all_ips.update(sub.get('ips', []))
            
        results["reverse_dns"] = {}
        # Limit reverse DNS to avoid taking forever if hundreds of IPs
        # maybe top 20 or just do all? 500 IPs is okay-ish.
        if len(all_ips) > 0:
            logger.info("Starting Reverse DNS checks...")
            
        for i, ip in enumerate(all_ips):
            if i > 200: break # Hard cap to prevent timeout
            
            entry = {"hostnames": [], "verified": False}
            try:
                # 1. Reverse
                rev_name = dns.reversename.from_address(ip)
                ptr_answers = resolver.resolve(rev_name, "PTR")
                hostnames = [str(r).rstrip('.') for r in ptr_answers]
                entry["hostnames"] = hostnames
                
                # 2. Forward verify
                for hostname in hostnames:
                    try:
                        fwd_answers = resolver.resolve(hostname, "A")
                        fwd_ips = [str(r) for r in fwd_answers]
                        if ip in fwd_ips:
                            entry["verified"] = True
                            break
                    except:
                        continue
            except:
                pass # Silent fail for PTR
            
            if entry["hostnames"]:
                results["reverse_dns"][ip] = entry

        return results

    def _fetch_ct_logs(self, domain: str) -> List[str]:
        """
        Queries crt.sh to find subdomains from Certificate Transparency logs.
        """
        subs = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            # Set a rigorous timeout as crt.sh can be slow
            resp = requests.get(url, timeout=60, headers={'User-Agent': 'Mozilla/5.0 (compatible; YADS/1.0)'})
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # split by newlines as one cert can have multiple SANs
                    for name in name_value.split('\n'):
                        name = name.strip()
                        # Only include if it ends with our target domain and isn't a wildcard
                        if name.endswith(domain) and '*' not in name:
                             subs.add(name)
        except Exception as e:
            # crt.sh often times out or fails, just log and continue
            import logging
            logging.getLogger("yads.modules.dns").warning(f"CT Log query failed: {e}")
            
        return list(subs)

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
