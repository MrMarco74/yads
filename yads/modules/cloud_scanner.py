import requests
import logging
from typing import Any, Dict, List
from yads.core.base import BaseScannerModule

class CloudScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "cloud_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.cloud_scanner")

    def run_scan(self, target: str) -> Dict[str, Any]:
        """
        Scans for Shadow IT cloud assets (buckets/blobs) related to the target.
        """
        self.logger.info(f"Starting Cloud Asset scan for: {target}")
        
        # 1. Generate Permutations
        # Extract base name (e.g., "example.com" -> "example")
        parts = target.split('.')
        base_name = parts[0]
        if base_name == "www" and len(parts) > 1:
            base_name = parts[1]
            
        keywords = ["", "backup", "assets", "dev", "staging", "prod", "public", "internal", "data", "files", "images", "media", "static", "corp"]
        separators = ["", "-", "."]
        
        candidates = set()
        
        # Add exact target permutations
        # example.com -> example-com-backup
        safe_target = target.replace('.', '-')
        candidates.add(safe_target)
        
        for kw in keywords:
            for sep in separators:
                if kw:
                    candidates.add(f"{base_name}{sep}{kw}")
                    candidates.add(f"{kw}{sep}{base_name}")
                    # Also try with full safe target
                    candidates.add(f"{safe_target}{sep}{kw}")
                else:
                    candidates.add(base_name)
        
        # Limit to avoid timeouts
        candidate_list = list(candidates)
        # Prioritize shorter/simpler ones
        candidate_list.sort(key=len)
        candidate_list = candidate_list[:100]
        
        findings = []
        
        # 2. Check Providers
        # We look for existence (DNS/Response) and accessibility (200 vs 403)
        providers = [
            {"name": "AWS S3", "template": "https://{name}.s3.amazonaws.com"},
            {"name": "Google Cloud", "template": "https://storage.googleapis.com/{name}"},
            # Azure is tricky without container, but account existence check via DNS/HTTP is possible
            {"name": "Azure Blob", "template": "https://{name}.blob.core.windows.net"},
        ]

        self.logger.info(f"Checking {len(candidate_list)} permutations across {len(providers)} providers...")

        for name in candidate_list:
            if not name or len(name) < 3: continue
            if not name.islower() and not name.replace('-','').isalnum(): continue # simple sanitize
            
            for prov in providers:
                url = prov["template"].format(name=name)
                try:
                    # Timeout must be short
                    resp = requests.head(url, timeout=2, allow_redirects=True)
                    
                    status = "Unknown"
                    found = False
                    
                    # AWS S3 Logic
                    if prov["name"] == "AWS S3":
                        if resp.status_code == 200:
                            status = "Public (Open)"
                            found = True
                        elif resp.status_code == 403:
                            status = "Protected (Exists)"
                            found = True
                        elif resp.status_code == 404:
                            found = False # NoSuchBucket
                            
                    # GCS Logic
                    elif prov["name"] == "Google Cloud":
                        if resp.status_code == 200:
                            status = "Public (Open)"
                            found = True
                        elif resp.status_code == 403:
                            status = "Protected (Exists)"
                            found = True
                        elif resp.status_code == 404:
                            found = False
                            
                    # Azure Logic
                    elif prov["name"] == "Azure Blob":
                        # Azure returns 400 (InvalidQueryParameterValue) if account exists but no container
                        # ConnectionError (NXDOMAIN) if account doesn't exist
                        # 404 resource not found means account exists but root not found? usually 400 for root
                        if resp.status_code in [200, 403, 400]: 
                            # 400 on root often means "Value for one of the query parameters..." -> Account exists!
                            status = "Protected (Exists)"
                            if resp.status_code == 200: status = "Public (Open)"
                            found = True
                        else:
                            # 404 from Azure usually means AccountNotFound OR ContainerNotFound. 
                            # But for root domain check, 404 usually means Account doesn't exist (DNS) or 
                            # actually Azure Blob specifically returns 404 The specified account does not exist.
                            found = False

                    if found:
                        findings.append({
                            "provider": prov["name"],
                            "bucket_name": name,
                            "url": url,
                            "status": status,
                            "status_code": resp.status_code
                        })
                        self.logger.info(f"Found {prov['name']} asset: {name} ({status})")
                        
                except requests.exceptions.ConnectionError:
                    # DNS failure -> Does not exist
                    pass
                except Exception as e:
                    # Timeouts etc
                    pass

        self.logger.info(f"Cloud Asset scan finished. Found {len(findings)} assets.")
        return {"assets": findings}
