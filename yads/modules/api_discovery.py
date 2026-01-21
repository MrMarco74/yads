import requests
import logging
import json
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from yads.core.base import BaseScannerModule
from yads.core.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

class ApiDiscoveryScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "api_discovery"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.limiter = RateLimiter()
        
        # known locations for API definitions
        self.definition_paths = [
            "swagger.json",
            "openapi.json",
            "api/docs",
            "api/v1/docs",
            "v1/docs",
            "docs/swagger.json",
            "docs/openapi.json",
            "api/swagger.json",
            "api/openapi.json",
            "swagger-ui.html",
            "swagger/index.html"
        ]
        
        # common prefixes to probe if no definition found
        self.prefixes = [
            "api",
            "api/v1",
            "api/v2",
            "v1",
            "v2",
            "graphql",
            "rest",
            "service"
        ]

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Scans for API definitions and endpoints.
        """
        results = {
            "definitions_found": [],
            "endpoints": [],
            "prefixes_found": [],
            "error": None
        }

        # 1. Connectivity Check & Base URL determination
        base_urls = [f"https://{target}", f"http://{target}"]
        primary_url = None
        
        for url in base_urls:
            try:
                r = requests.get(url, timeout=5)
                # We accept even error codes if we can reach the server, but ideally we want something running
                if r.status_code < 600: 
                    primary_url = url.rstrip('/')
                    break
            except:
                continue
        
        if not primary_url:
            results["error"] = "Could not connect to target via HTTP or HTTPS"
            return results

        logger.info(f"[{self.module_name}] Starting scan on {primary_url}")

        # 2. Probe for Definitions
        found_definitions = self._probe_paths(primary_url, self.definition_paths, target)
        results["definitions_found"] = found_definitions
        
        # 3. If definitions found, try to parse them
        for def_item in found_definitions:
            if def_item['url'].endswith('.json'):
                try:
                    endpoints = self._parse_swagger(def_item['url'])
                    if endpoints:
                        results["endpoints"].extend(endpoints)
                        logger.info(f"[{self.module_name}] Extracted {len(endpoints)} endpoints from {def_item['url']}")
                except Exception as e:
                    logger.warning(f"[{self.module_name}] Failed to parse {def_item['url']}: {e}")

        # 4. Probe for Common Prefixes (blind discovery)
        # We only do this if we haven't found a vast number of endpoints already, 
        # or maybe we do it anyway to find undocumented APIs? Let's do it anyway.
        found_prefixes = self._probe_paths(primary_url, self.prefixes, target)
        results["prefixes_found"] = found_prefixes

        # Deduplicate endpoints
        results["endpoints"] = list(set(results["endpoints"]))
        
        return results

    def _probe_paths(self, base_url: str, paths: List[str], target: str) -> List[Dict]:
        found = []
        
        def check_path(path):
            full_url = f"{base_url}/{path}"
            self.limiter.wait(target)
            try:
                resp = requests.get(full_url, timeout=5, allow_redirects=True, stream=True)
                # We are looking for 200 OK mostly. 
                # For APIs, 401/403 might also indicate existence but locked down.
                if resp.status_code in [200, 401, 403]:
                    # Ignore standard clean 404s
                    # If it's a 200, check if it's a soft 404? 
                    # For json files, we expect JSON content type.
                    
                    is_json_path = path.endswith('.json')
                    ct = resp.headers.get("Content-Type", "")
                    
                    if is_json_path and "json" not in ct and resp.status_code == 200:
                         # Likely a soft 404 returning HTML
                         return None
                         
                    return {
                        "path": path,
                        "url": full_url,
                        "status": resp.status_code,
                        "content_type": ct
                    }
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            task_map = {executor.submit(check_path, p): p for p in paths}
            for future in as_completed(task_map):
                res = future.result()
                if res:
                    found.append(res)
        
        return found

    def _parse_swagger(self, url: str) -> List[str]:
        """
        Fetches and parses a Swagger/OpenAPI JSON file to extract paths.
        """
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return []
            
            data = resp.json()
            paths = []
            
            # OpenAI / Swagger 2.0 structure
            if "paths" in data:
                for path, methods in data["paths"].items():
                    # We store the path and maybe methods? 
                    # For now just the path string is useful enough
                    paths.append(path)
            
            return paths
        except Exception as e:
            logger.debug(f"Error parsing swagger at {url}: {e}")
            return []
