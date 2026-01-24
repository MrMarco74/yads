import dns.resolver
import itertools
import logging
from typing import List, Dict, Any, Optional
from yads.core.base import BaseScannerModule

class TyposquatScanner(BaseScannerModule):
    """
    Generates potential typosquatting domains and checks if they are resolvable.
    """
    @property
    def module_name(self) -> str:
        return "typosquat_scanner"

    def _generate_variations(self, domain: str) -> List[str]:
        """
        Generates a list of potential typosquatting domains.
        """
        variations = set()
        name, tld = domain.split('.', 1)
        
        # 1. Omission (remove one character)
        for i in range(len(name)):
            variations.add(f"{name[:i]}{name[i+1:]}.{tld}")

        # 2. Repetition (duplicate one character)
        for i in range(len(name)):
            variations.add(f"{name[:i+1]}{name[i]}{name[i+1:]}.{tld}")

        # 3. Transposition (swap adjacent characters)
        for i in range(len(name) - 1):
            variations.add(f"{name[:i]}{name[i+1]}{name[i]}{name[i+2:]}.{tld}")

        # 4. Replacement (common keyboard mispresses - simplified)
        # This is a basic set, could be expanded significantly
        chars = 'abcdefghijklmnopqrstuvwxyz'
        for i in range(len(name)):
            for c in chars:
                if c != name[i]:
                    variations.add(f"{name[:i]}{c}{name[i+1:]}.{tld}")

        # 5. TLD Swap (common TLDs)
        common_tlds = ['com', 'net', 'org', 'info', 'io', 'co', 'de']
        for ext in common_tlds:
            if ext != tld:
                variations.add(f"{name}.{ext}")

        # Remove original domain if somehow generated
        if domain in variations:
            variations.remove(domain)
            
        return list(variations)

    def run_scan(self, domain: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Main execution method.
        """
        logger = logging.getLogger("yads.modules.typosquat")
        logger.info(f"[{self.module_name}] Generating variations for {domain}...")
        variations = self._generate_variations(domain)
        logger.info(f"[{self.module_name}] Checking {len(variations)} variations...")

        found_squats = []
        
        # Shared resolver for efficiency/caching
        shared_resolver = dns.resolver.Resolver()
        shared_resolver.timeout = 1.0
        shared_resolver.lifetime = 1.0

        import concurrent.futures

        def check_variant(variant):
            try:
                # Use shared resolver
                answers = shared_resolver.resolve(variant, 'A')
                ips = [r.to_text() for r in answers]
                return {
                    "domain": variant,
                    "ips": ips,
                    "type": "A_RECORD"
                }
            except:
                return None

        # Increase limit to 2000 or all. With 50 threads, 2000 checks takes ~40s max (assuming 1s timeout worst case, but mostly minimal)
        # Using the local dns-cache makes this blazing fast.
        
        scan_list = list(variations)
        total_to_scan = len(scan_list)
        
        # Determine max variants to scan to keep it reasonable (e.g. 5000)
        # 5000 * 50ms (average with cache/NXDOMAIN) / 50 threads = 5 seconds.
        # But timeouts take 1s. If 90% exist? No, 99% won't exist. So they are fast NXDOMAINs.
        # So we can easily scan ALL generated variations.
        
        logger.info(f"Starting parallel scan of {total_to_scan} targets...")
        
        checked_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(check_variant, var): var for var in scan_list}
            for future in concurrent.futures.as_completed(future_to_url):
                checked_count += 1
                res = future.result()
                if res:
                    found_squats.append(res)
        
        logger.info(f"Typosquat scan complete. Found {len(found_squats)} active domains.")
        
        return {
            "scanned_count": checked_count,
            "total_variations": len(variations),
            "found": found_squats
        }
