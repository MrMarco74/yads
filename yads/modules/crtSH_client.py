import requests
import logging
import tldextract
from typing import List, Set

from yads.core.api_block_detection import ApiBlockedError
from yads.core.throttled_http import throttled_get

def search_by_org(org_name: str = None, email: str = None, exclude_domain: str = None) -> List[str]:
    """
    Queries crt.sh for certificates matching an organisation name or e-mail address.
    Returns a deduplicated list of apex domains found in those certificates,
    excluding subdomains of exclude_domain (the target itself).
    """
    logger = logging.getLogger("yads.modules.crtsh")
    domains: Set[str] = set()

    queries = []
    if org_name:
        queries.append(org_name)
    if email:
        queries.append(email)

    for q in queries:
        url = f"https://crt.sh/?q={requests.utils.quote(q)}&output=json"
        try:
            resp = throttled_get(url, service="crt_sh", timeout=20)
            if resp.status_code != 200:
                continue
            data = resp.json()
            for entry in data:
                for field in ("common_name", "name_value"):
                    value = entry.get(field, "") or ""
                    for name in value.split("\n"):
                        name = name.strip().lower()
                        if not name or "*" in name:
                            continue
                        ext = tldextract.extract(name)
                        if not ext.domain or not ext.suffix:
                            continue
                        apex = f"{ext.domain}.{ext.suffix}"
                        if exclude_domain and apex == exclude_domain.lower():
                            continue
                        domains.add(apex)
        except requests.exceptions.Timeout:
            logger.warning(f"crt.sh org query timed out for: {q}")
        except ApiBlockedError:
            raise
        except Exception as e:
            logger.warning(f"crt.sh org query failed for '{q}': {e}")

    logger.info(f"crt.sh org search found {len(domains)} related domains")
    return sorted(domains)


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
        resp = throttled_get(url, service="crt_sh", timeout=25)
        
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
    except ApiBlockedError:
        raise
    except Exception as e:
        logger.error(f"crt.sh Processing Error: {e}")
        return []
        
    return list(subs)
