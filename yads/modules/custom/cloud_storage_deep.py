import requests
import re
from typing import Any, Dict, Optional
from yads.core.base import BaseScannerModule

class CloudStorageDeepScanner(BaseScannerModule):
    """
    Analyzes web content for leaked bucket names and cloud credentials.
    """
    
    @property
    def module_name(self) -> str:
        return "cloud_storage_deep"

    @property
    def label(self) -> str:
        return "Cloud Asset Leak Scan"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        results = {
            "buckets": [],
            "secrets": [],
            "findings_count": 0
        }
        
        try:
            url = f"https://{target}"
            resp = requests.get(url, timeout=10, verify=False)
            html = resp.text
            
            # 1. AWS S3 Buckets
            # s3.amazonaws.com/bucket-name or bucket-name.s3.amazonaws.com
            bucket_regex = r"[a-z0-9.-]+\.s3[.-]?[a-z0-9-]*\.amazonaws\.com"
            matches = re.findall(bucket_regex, html, re.I)
            results["buckets"].extend(list(set(matches)))
            
            # 2. Azure Blobs
            blob_regex = r"[a-z0-9.-]+\.blob\.core\.windows\.net"
            matches = re.findall(blob_regex, html, re.I)
            results["buckets"].extend(list(set(matches)))
            
            # 3. AWS Access Keys (Heuristic)
            key_regex = r"AKIA[0-9A-Z]{16}"
            matches = re.findall(key_regex, html)
            results["secrets"].extend(list(set(matches)))

            results["findings_count"] = len(results["buckets"]) + len(results["secrets"])
            
        except Exception as e:
            results["error"] = str(e)
            
        return results
