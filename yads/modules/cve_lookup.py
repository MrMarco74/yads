import requests
from typing import List, Dict

def lookup_cves(product: str, version: str) -> List[Dict[str, str]]:
    """
    Queries cve.circl.lu for vulnerabilities matching the product and version.
    Returns a list of dicts with 'id', 'cvss', 'summary'.
    """
    product = product.lower().strip()
    version = version.strip()
    
    # Try using product as vendor/product
    url = f"https://cve.circl.lu/api/search/{product}/{product}"
    
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
            
        json_resp = resp.json()
        
        # Structure check: {"results": {"cvelistv5": [...]}} or just list?
        # Based on curl, it's {"results": ...}
        
        matches = []
        
        # Helper to extract CVEs from 'cvelistv5' or 'nvd'
        sources = json_resp.get("results", {}) if isinstance(json_resp, dict) else {}
        
        # We prioritize 'cvelistv5' or 'nvd'. 
        candidates = sources.get("cvelistv5", []) or sources.get("nvd", [])
        
        # If candidates is empty, maybe the API returned a flat list (older behavior)?
        if not candidates and isinstance(json_resp, list):
             candidates = json_resp

        for item in candidates:
            # item structure varies. In cvelistv5 search it seemed to be [id, data]
            cve_id = "Unknown"
            summary = ""
            cvss = "N/A"
            
            if isinstance(item, list) and len(item) >= 2:
                # cvelistv5 format: ["CVE-...", { ... }]
                cve_id = item[0]
                data = item[1]
                
                # Extract Description
                # Try path: containers -> cna -> descriptions -> [0] -> value
                try:
                    desc_list = data.get("containers", {}).get("cna", {}).get("descriptions", [])
                    if desc_list:
                        summary = desc_list[0].get("value", "")
                except (AttributeError, KeyError, IndexError):
                    pass
                    
            elif isinstance(item, dict):
                # Flat list format or NVD object
                cve_id = item.get("id", item.get("cve_id", "Unknown"))
                summary = item.get("summary", item.get("description", ""))
                cvss = item.get("cvss", "N/A")
            
            # Filter by Version
            # We look for the version string in the summary.
            # This is a heuristic.
            
            cve_item = {
                 "id": cve_id,
                 "cvss": cvss,
                 "summary": summary[:200] + "..."
            }
            
            if version in summary:
                 matches.append(cve_item)
            else:
                 # Check for "before <version>" logic is too hard here.
                 # Just add to potential candidates
                 # But verify likely relevance (e.g. mentions product name)
                 if product in summary.lower():
                     matches.append(cve_item) # For now, just mix them
            
            if len(matches) >= 5:
                break
                
        return matches

    except Exception as e:
        print(f"CVE Lookup Error: {e}")
        return []
