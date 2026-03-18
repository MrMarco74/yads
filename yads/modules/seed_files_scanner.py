"""
Seed Files Scanner Module

Analyzes robots.txt and sitemap.xml files to discover:
- Disallowed/allowed paths (potential sensitive endpoints)
- Sitemap URLs and nested sitemaps
- URL patterns and structures
- Crawl delay rules
- Security-relevant paths
"""

import re
import requests
import defusedxml.ElementTree as ET
import xml.etree.ElementTree as core_ET
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from datetime import datetime
import logging

from yads.core.base import BaseScannerModule

logger = logging.getLogger("yads.seed_files_scanner")

# Patterns that might indicate sensitive endpoints
SENSITIVE_PATH_PATTERNS = [
    r'/admin',
    r'/administrator',
    r'/wp-admin',
    r'/login',
    r'/signin',
    r'/auth',
    r'/api',
    r'/graphql',
    r'/debug',
    r'/test',
    r'/staging',
    r'/dev',
    r'/backup',
    r'/config',
    r'/setup',
    r'/install',
    r'/phpmyadmin',
    r'/phpinfo',
    r'/server-status',
    r'/\.git',
    r'/\.env',
    r'/\.htaccess',
    r'/wp-config',
    r'/database',
    r'/db',
    r'/sql',
    r'/dump',
    r'/export',
    r'/private',
    r'/internal',
    r'/secret',
    r'/hidden',
    r'/temp',
    r'/tmp',
    r'/upload',
    r'/uploads',
    r'/files',
    r'/cgi-bin',
    r'/scripts',
]


class SeedFilesScanner(BaseScannerModule):
    """Scanner for robots.txt and sitemap.xml analysis."""

    @property
    def module_name(self) -> str:
        return "seed_files_scanner"

    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.timeout = 15
        self.max_sitemaps = 10  # Limit nested sitemap fetching
        self.max_urls_per_sitemap = 500  # Limit URLs extracted per sitemap

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """Execute seed files analysis."""
        logger.info(f"Starting seed files scan for {target}")
        from datetime import timezone
        results = {
            "domain": target, "scanned_at": datetime.now(timezone.utc).isoformat(),
            "robots_txt": None, "sitemaps": [], "discovered_paths": [], "sensitive_paths": [],
            "statistics": {"total_paths": 0, "total_sitemap_urls": 0, "sensitive_paths_count": 0}
        }

        # 1. Robots.txt
        base_url = f"https://{target}"
        results["robots_txt"] = self._analyze_robots_txt(base_url, target)

        # 2. Sitemaps
        sitemap_urls = self._collect_sitemap_urls(base_url, results["robots_txt"])
        all_sitemap_urls = set()
        analyzed = set()

        for s_url in list(sitemap_urls)[:self.max_sitemaps]:
            if s_url in analyzed: continue
            data = self._analyze_sitemap(s_url, target, analyzed)
            if data:
                results["sitemaps"].append(data)
                if data.get("urls"): all_sitemap_urls.update(data["urls"])

        # 3. Paths & Sensitive Discovery
        all_paths = self._process_discovered_paths(results["robots_txt"], all_sitemap_urls)
        results["discovered_paths"] = sorted(all_paths)
        results["sensitive_paths"] = self._find_sensitive_paths(all_paths, results["robots_txt"])

        # 4. Statistics
        results["statistics"] = {
            "total_paths": len(all_paths), "total_sitemap_urls": len(all_sitemap_urls),
            "sensitive_paths_count": len(results["sensitive_paths"]),
            "sitemaps_analyzed": len(results["sitemaps"]),
            "robots_txt_found": results["robots_txt"].get("found", False)
        }
        return results

    def _collect_sitemap_urls(self, base_url: str, robots_data: Optional[Dict]) -> Set[str]:
        """Aggregates known sitemap locations."""
        urls = {f"{base_url}/sitemap.xml", f"{base_url}/sitemap_index.xml", f"{base_url}/sitemap/sitemap.xml"}
        if robots_data and robots_data.get("sitemaps"):
            urls.update(robots_data["sitemaps"])
        return urls

    def _process_discovered_paths(self, robots_data: Optional[Dict], sitemap_urls: Set[str]) -> Set[str]:
        """Extracts paths from robots rules and sitemap URLs."""
        paths = set()
        if robots_data:
            for rule in robots_data.get("disallow_rules", []) + robots_data.get("allow_rules", []):
                if rule.get("path"): paths.add(rule["path"])
        
        for url in sitemap_urls:
            try:
                p_obj = urlparse(url)
                if p_obj.path: paths.add(p_obj.path)
            except Exception: pass
        return paths

    def _analyze_robots_txt(self, base_url: str, domain: str) -> Optional[Dict]:
        """Fetch and parse robots.txt with fallback."""
        urls = [f"{base_url}/robots.txt", f"http://{domain}/robots.txt"]
        
        for url in urls:
            try:
                verify = url.startswith("https")
                resp = requests.get(url, timeout=self.timeout, headers={"User-Agent": "YADS-Security-Scanner/1.19 (+https://yads-security.com)"}, verify=verify, allow_redirects=True)  # nosec B113 B501 — scanner probes target over http/https with intentional cert handling
                if resp.status_code == 200:
                    return self._parse_robots_txt(resp.text, url)
            except Exception as e:
                logger.debug(f"Failed to fetch robots.txt from {url}: {e}")
        
        return {"found": False, "url": urls[0], "error": "Not Found or Connection Error"}

    def _parse_robots_txt(self, content: str, url: str) -> Dict:
        """Parse robots.txt content."""
        result = {
            "found": True, "url": url, "raw_content": content[:5000], "user_agents": [],
            "disallow_rules": [], "allow_rules": [], "sitemaps": [], "crawl_delay": None, "host": None
        }

        current_agent = "*"
        seen_agents = set()

        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'): continue

            if ':' in line:
                directive, value = [p.strip() for p in line.split(':', 1)]
                directive = directive.lower()
                
                if directive == 'user-agent':
                    current_agent = value
                    if value not in seen_agents:
                        seen_agents.add(value)
                        result["user_agents"].append(value)
                else:
                    self._handle_robots_directive(directive, value, current_agent, result)

        return result

    def _handle_robots_directive(self, directive: str, value: str, agent: str, result: Dict):
        """Processes a single robots.txt directive."""
        if not value and directive != 'crawl-delay': return

        if directive == 'disallow':
            result["disallow_rules"].append({"user_agent": agent, "path": value})
        elif directive == 'allow':
            result["allow_rules"].append({"user_agent": agent, "path": value})
        elif directive == 'sitemap' and value.startswith('http'):
            result["sitemaps"].append(value)
        elif directive == 'crawl-delay':
            try: result["crawl_delay"] = float(value)
            except (TypeError, ValueError): pass
        elif directive == 'host':
            result["host"] = value

    def _analyze_sitemap(self, sitemap_url: str, domain: str, analyzed: Set[str]) -> Optional[Dict]:
        """Fetch and parse a sitemap."""
        if sitemap_url in analyzed:
            return None

        analyzed.add(sitemap_url)

        try:
            response = requests.get(
                sitemap_url,
                timeout=self.timeout,
                headers={"User-Agent": "YADS-Security-Scanner/1.19 (+https://yads-security.com)"},
                verify=True,
                allow_redirects=True
            )

            if response.status_code != 200:
                return None

            content_type = response.headers.get('Content-Type', '')
            content = response.text

            # Check if it's XML
            if 'xml' in content_type or content.strip().startswith('<?xml') or content.strip().startswith('<'):
                return self._parse_sitemap_xml(content, sitemap_url, domain, analyzed)

            return None

        except Exception as e:
            logger.debug(f"Error fetching sitemap {sitemap_url}: {e}")
            return None

    def _parse_sitemap_xml(self, content: str, url: str, domain: str, analyzed: Set[str]) -> Dict:
        """Parse sitemap XML content."""
        result = {"url": url, "type": "unknown", "urls": [], "nested_sitemaps": [], "url_count": 0, "last_modified_dates": []}
        try:
            content = re.sub(r'xmlns="[^"]+"', '', content)
            root = ET.fromstring(content)
            
            if 'sitemapindex' in root.tag.lower() or root.find('.//sitemap') is not None:
                self._parse_sitemap_index(root, result, domain, analyzed)
            else:
                self._parse_urlset(root, result)
            
            result["url_count"] = len(result["urls"])
        except Exception as e:
            logger.debug(f"Sitemap parse error for {url}: {e}")
            result["error"] = str(e)
        return result

    def _parse_sitemap_index(self, root: core_ET.Element, result: Dict, domain: str, analyzed: Set[str]):
        """Parses sitemap index and follows nested links."""
        result["type"] = "sitemap_index"
        for s_elem in root.findall('.//sitemap'):
            loc = s_elem.find('loc')
            if loc is not None and loc.text:
                n_url = loc.text.strip()
                result["nested_sitemaps"].append(n_url)
                if len(analyzed) < self.max_sitemaps:
                    n_data = self._analyze_sitemap(n_url, domain, analyzed)
                    if n_data and n_data.get("urls"):
                        result["urls"].extend(n_data["urls"][:100])

    def _parse_urlset(self, root: core_ET.Element, result: Dict):
        """Parses a standard urlset sitemap."""
        result["type"] = "urlset"
        for u_elem in root.findall('.//url'):
            if len(result["urls"]) >= self.max_urls_per_sitemap: break
            loc, lastmod = u_elem.find('loc'), u_elem.find('lastmod')
            if loc is not None and loc.text:
                result["urls"].append(loc.text.strip())
            if lastmod is not None and lastmod.text:
                result["last_modified_dates"].append(lastmod.text.strip())

    def _find_sensitive_paths(self, paths: Set[str], robots_data: Optional[Dict]) -> List[Dict]:
        """Identify potentially sensitive paths."""
        sensitive = []

        for path in paths:
            path_lower = path.lower()

            for pattern in SENSITIVE_PATH_PATTERNS:
                if re.search(pattern, path_lower):
                    # Check if it's in disallow rules (extra interesting)
                    in_disallow = False
                    if robots_data:
                        for rule in robots_data.get("disallow_rules", []):
                            if rule.get("path") == path:
                                in_disallow = True
                                break

                    sensitive.append({
                        "path": path,
                        "pattern_matched": pattern,
                        "in_robots_disallow": in_disallow,
                        "risk_indicator": "high" if in_disallow else "medium"
                    })
                    break

        # Sort by risk indicator
        sensitive.sort(key=lambda x: (0 if x["risk_indicator"] == "high" else 1, x["path"]))

        return sensitive
