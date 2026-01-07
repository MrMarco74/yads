import dns.resolver
import itertools
from typing import List, Dict, Any
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

    def run_scan(self, domain: str) -> Dict[str, Any]:
        """
        Main execution method.
        """
        print(f"[{self.module_name}] Generating variations for {domain}...")
        variations = self._generate_variations(domain)
        print(f"[{self.module_name}] Checking {len(variations)} variations...")

        found_squats = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1

        # Limit to first 100 to avoid long scans in this demo/MVP
        # In production, this should be async/parallelized
        checked_count = 0
        for variant in variations[:200]: 
            try:
                answers = resolver.resolve(variant, 'A')
                ips = [r.to_text() for r in answers]
                found_squats.append({
                    "domain": variant,
                    "ips": ips,
                    "type": "A_RECORD"
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                # print(f"Error checking {variant}: {e}")
                pass
            checked_count += 1
        
        return {
            "scanned_count": checked_count,
            "total_variations": len(variations),
            "found": found_squats
        }
