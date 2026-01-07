import requests
from typing import Any, Dict, List
from yads.core.base import BaseScannerModule

class VisualOSINT(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "visual_osint"

    def run_scan(self, target: str) -> Dict[str, Any]:
        """
        Queries external sources for public logos associated with the domain.
        """
        results = {
            "logos": []
        }
        
        # Sources
        sources = [
            {
                "name": "Google",
                "url": f"https://www.google.com/s2/favicons?domain={target}&sz=128",
                "type": "favicon"
            },
            {
                "name": "Clearbit",
                "url": f"https://logo.clearbit.com/{target}",
                "type": "logo"
            },
            {
                "name": "DuckDuckGo",
                "url": f"https://icons.duckduckgo.com/ip3/{target}.ico",
                "type": "favicon"
            }
        ]
        
        for source in sources:
            try:
                # fast check if image exists
                resp = requests.head(source["url"], timeout=5)
                # Some APIs return 200 even for default/missing, but usually 404 if not found.
                # Clearbit returns 404 if not found.
                # Google always returns something (default globe if unknown), but 200 OK. 
                # Diffing against default google favicon is expensive here, so we just accept it for now or check size.
                
                if resp.status_code == 200:
                    results["logos"].append({
                        "source": source["name"],
                        "url": source["url"],
                        "type": source["type"]
                    })
            except Exception:
                continue
                
        return results
