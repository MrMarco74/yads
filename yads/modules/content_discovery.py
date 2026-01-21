import requests
import logging
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from yads.core.base import BaseScannerModule
from yads.core.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

class ContentDiscoveryScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "content_discovery"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.limiter = RateLimiter()
        # Curated list of high-value "Hidden Assets"
        self.wordlist = [
            # Configs & Secrets
            ".env",
            ".git/HEAD",
            ".git/config",
            ".DS_Store",
            ".vscode/sftp.json",
            "docker-compose.yml",
            "bg.zip",
            "backup.zip",
            "backup.sql",
            "db_backup.sql",
            "dump.sql",
            # Admin Panels
            "admin",
            "admin/",
            "administrator",
            "dashboard",
            "cpanel",
            "login",
            "wp-admin",
            # Server Info
            "server-status",
            "phpinfo.php",
            "info.php",
            # App Specific
            "wp-config.php.bak",
            "config.php.bak",
            "config.php.old",
            "web.config",
            # API
            "api/docs",
            "swagger.json",
            "graphql",
            # Misc
            "robots.txt",
            "sitemap.xml",
            "README.md"
        ]

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Fuzzes the target for common sensitive files and directories.
        """
        results = {
            "found_assets": [],
            "error": None
        }

        # Ensure schema (default to http, let requests handle redirects or try both if needed)
        # Usually target comes as "example.com". We should try https first.
        base_urls = [f"https://{target}", f"http://{target}"]
        
        # We'll determine the primary working URL first using a quick check
        primary_url = None
        for url in base_urls:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code < 500: # Accept 200, 403, 301, 404... just need connectivity
                    primary_url = url.rstrip('/')
                    break
            except:
                continue
        
        if not primary_url:
            results["error"] = "Could not connect to target via HTTP or HTTPS"
            return results

        logger.info(f"Starting content discovery on {primary_url} with {len(self.wordlist)} paths")

        def check_path(path):
            full_url = f"{primary_url}/{path}"
            self.limiter.wait(target) # Respect rate limits
            try:
                # Use stream=True to avoid downloading large files, allow_redirects=False to spot redirects
                resp = requests.get(full_url, timeout=5, allow_redirects=False, stream=True)
                
                # Interesting codes: 200 (Found), 403 (Forbidden - maybe exists), 401 (Auth), 301/302 (Redirect)
                # Ignore 404
                if resp.status_code != 404:
                    # Filter out generic error pages or soft 404s if possible (simple method: content length > 0)
                    # For now, just report status code.
                    
                    return {
                        "path": path,
                        "url": full_url,
                        "status": resp.status_code,
                        "length": resp.headers.get("Content-Length"),
                        "type": resp.headers.get("Content-Type")
                    }
            except Exception as e:
                # logger.debug(f"Error checking {path}: {e}")
                pass
            return None

        # Run in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            task_map = {executor.submit(check_path, path): path for path in self.wordlist}
            for future in as_completed(task_map):
                res = future.result()
                if res:
                    results["found_assets"].append(res)

        # Sort by status code for better readability
        results["found_assets"].sort(key=lambda x: x["status"])
        
        return results
