import requests
import logging
from typing import List, Set

def search_domain(domain_name: str) -> List[str]:
    """
    Searches crt.sh via public JSON API for subdomains.
    
    Args:
        domain_name: The domain/subdomain to search for (e.g. 'example.com')
        
    Returns:
        List[str]: A list of unique subdomains found.
    """
    logger = logging.getLogger("yads.modules.crtsh")
    subs: Set[str] = set()
    
    # JSON API URL
    # %.domain matches subdomains
    url = f"https://crt.sh/?q=%.{domain_name}&output=json"
    
    try:
        # Timeout is important for external APIs
        resp = requests.get(url, timeout=25)
        
        if resp.status_code != 200:
            logger.warning(f"crt.sh returned status {resp.status_code}")
            return []
            
        data = resp.json()
        # data is a list of dicts:
        # [{'issuer_ca_id': 123, 'issuer_name': '...', 'common_name': '...', 'name_value': '...', ...}, ...]
        
        if not data:
            return []
            
        for entry in data:
            name_value = entry.get('name_value')
            if name_value:
                # name_value can be a multi-line string (SANs)
                if '\n' in name_value:
                    names = name_value.split('\n')
                else:
                    names = [name_value]
                    
                for name in names:
                    name = name.strip().lower()
                    # Filter to ensure it actually matches domain
                    if name.endswith(domain_name):
                        # Avoid wildcards if possible, or include them?
                        # Usually we want concrete subdomains for scanning.
                        if '*' not in name:
                            subs.add(name)
                            
        logger.info(f"crt.sh (API) returned {len(subs)} subdomains for {domain_name}")
        
    except requests.exceptions.Timeout:
        logger.warning("crt.sh Request Timed Out")
        return []
    except requests.exceptions.RequestException as e:
        logger.warning(f"crt.sh Request Failed: {e}")
        return []
    except Exception as e:
        logger.error(f"crt.sh Processing Error: {e}")
        return []
        
    return list(subs)
