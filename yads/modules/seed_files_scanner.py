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
import xml.etree.ElementTree as ET
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

        results = {
            "domain": target,
            "scanned_at": datetime.utcnow().isoformat(),
            "robots_txt": None,
            "sitemaps": [],
            "discovered_paths": [],
            "sensitive_paths": [],
            "statistics": {
                "total_paths": 0,
                "total_sitemap_urls": 0,
                "sensitive_paths_count": 0
            }
        }

        base_url = f"https://{target}"

        # 1. Analyze robots.txt
        robots_data = self._analyze_robots_txt(base_url, target)
        results["robots_txt"] = robots_data

        # 2. Collect sitemap URLs from robots.txt
        sitemap_urls = set()
        if robots_data and robots_data.get("sitemaps"):
            sitemap_urls.update(robots_data["sitemaps"])

        # Add common sitemap locations
        sitemap_urls.add(f"{base_url}/sitemap.xml")
        sitemap_urls.add(f"{base_url}/sitemap_index.xml")
        sitemap_urls.add(f"{base_url}/sitemap/sitemap.xml")

        # 3. Analyze sitemaps
        all_sitemap_urls = set()
        analyzed_sitemaps = set()

        for sitemap_url in list(sitemap_urls)[:self.max_sitemaps]:
            if sitemap_url in analyzed_sitemaps:
                continue

            sitemap_data = self._analyze_sitemap(sitemap_url, target, analyzed_sitemaps)
            if sitemap_data:
                results["sitemaps"].append(sitemap_data)
                if sitemap_data.get("urls"):
                    all_sitemap_urls.update(sitemap_data["urls"])

        # 4. Collect all discovered paths
        all_paths = set()

        # From robots.txt
        if robots_data:
            for rule in robots_data.get("disallow_rules", []):
                if rule.get("path"):
                    all_paths.add(rule["path"])
            for rule in robots_data.get("allow_rules", []):
                if rule.get("path"):
                    all_paths.add(rule["path"])

        # From sitemaps (extract paths)
        for url in all_sitemap_urls:
            try:
                parsed = urlparse(url)
                if parsed.path:
                    all_paths.add(parsed.path)
            except:
                pass

        results["discovered_paths"] = sorted(list(all_paths))

        # 5. Identify sensitive paths
        sensitive = self._find_sensitive_paths(all_paths, robots_data)
        results["sensitive_paths"] = sensitive

        # 6. Update statistics
        results["statistics"] = {
            "total_paths": len(all_paths),
            "total_sitemap_urls": len(all_sitemap_urls),
            "sensitive_paths_count": len(sensitive),
            "sitemaps_analyzed": len(results["sitemaps"]),
            "robots_txt_found": robots_data is not None and robots_data.get("found", False)
        }

        logger.info(f"Seed files scan complete for {target}: {results['statistics']}")
        return results

    def _analyze_robots_txt(self, base_url: str, domain: str) -> Optional[Dict]:
        """Fetch and parse robots.txt."""
        robots_url = f"{base_url}/robots.txt"

        try:
            response = requests.get(
                robots_url,
                timeout=self.timeout,
                headers={"User-Agent": "YADS Security Scanner"},
                verify=True,
                allow_redirects=True
            )

            if response.status_code != 200:
                # Try HTTP fallback
                robots_url_http = f"http://{domain}/robots.txt"
                response = requests.get(
                    robots_url_http,
                    timeout=self.timeout,
                    headers={"User-Agent": "YADS Security Scanner"},
                    verify=False,
                    allow_redirects=True
                )

            if response.status_code != 200:
                return {"found": False, "url": robots_url, "error": f"HTTP {response.status_code}"}

            content = response.text
            return self._parse_robots_txt(content, robots_url)

        except requests.exceptions.SSLError:
            # Try HTTP fallback
            try:
                robots_url_http = f"http://{domain}/robots.txt"
                response = requests.get(
                    robots_url_http,
                    timeout=self.timeout,
                    headers={"User-Agent": "YADS Security Scanner"},
                    verify=False,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    return self._parse_robots_txt(response.text, robots_url_http)
            except:
                pass
            return {"found": False, "url": robots_url, "error": "SSL Error"}
        except requests.exceptions.Timeout:
            return {"found": False, "url": robots_url, "error": "Timeout"}
        except Exception as e:
            return {"found": False, "url": robots_url, "error": str(e)}

    def _parse_robots_txt(self, content: str, url: str) -> Dict:
        """Parse robots.txt content."""
        result = {
            "found": True,
            "url": url,
            "raw_content": content[:5000],  # Limit stored content
            "user_agents": [],
            "disallow_rules": [],
            "allow_rules": [],
            "sitemaps": [],
            "crawl_delay": None,
            "host": None
        }

        current_user_agent = "*"
        user_agents_seen = set()

        for line in content.split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Parse directive
            if ':' in line:
                directive, value = line.split(':', 1)
                directive = directive.strip().lower()
                value = value.strip()

                if directive == 'user-agent':
                    current_user_agent = value
                    if value not in user_agents_seen:
                        user_agents_seen.add(value)
                        result["user_agents"].append(value)

                elif directive == 'disallow':
                    if value:
                        result["disallow_rules"].append({
                            "user_agent": current_user_agent,
                            "path": value
                        })

                elif directive == 'allow':
                    if value:
                        result["allow_rules"].append({
                            "user_agent": current_user_agent,
                            "path": value
                        })

                elif directive == 'sitemap':
                    if value and value.startswith('http'):
                        result["sitemaps"].append(value)

                elif directive == 'crawl-delay':
                    try:
                        result["crawl_delay"] = float(value)
                    except:
                        pass

                elif directive == 'host':
                    result["host"] = value

        return result

    def _analyze_sitemap(self, sitemap_url: str, domain: str, analyzed: Set[str]) -> Optional[Dict]:
        """Fetch and parse a sitemap."""
        if sitemap_url in analyzed:
            return None

        analyzed.add(sitemap_url)

        try:
            response = requests.get(
                sitemap_url,
                timeout=self.timeout,
                headers={"User-Agent": "YADS Security Scanner"},
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
        result = {
            "url": url,
            "type": "unknown",
            "urls": [],
            "nested_sitemaps": [],
            "url_count": 0,
            "last_modified_dates": []
        }

        try:
            # Handle XML namespaces
            content = re.sub(r'xmlns="[^"]+"', '', content)
            root = ET.fromstring(content)

            # Check if it's a sitemap index
            if 'sitemapindex' in root.tag.lower() or root.find('.//sitemap') is not None:
                result["type"] = "sitemap_index"

                for sitemap_elem in root.findall('.//sitemap'):
                    loc = sitemap_elem.find('loc')
                    if loc is not None and loc.text:
                        nested_url = loc.text.strip()
                        result["nested_sitemaps"].append(nested_url)

                        # Recursively analyze nested sitemaps (with limit)
                        if len(analyzed) < self.max_sitemaps:
                            nested_data = self._analyze_sitemap(nested_url, domain, analyzed)
                            if nested_data and nested_data.get("urls"):
                                result["urls"].extend(nested_data["urls"][:100])

            # Regular sitemap with URLs
            else:
                result["type"] = "urlset"

                for url_elem in root.findall('.//url'):
                    if len(result["urls"]) >= self.max_urls_per_sitemap:
                        break

                    loc = url_elem.find('loc')
                    if loc is not None and loc.text:
                        page_url = loc.text.strip()
                        result["urls"].append(page_url)

                        # Extract lastmod if available
                        lastmod = url_elem.find('lastmod')
                        if lastmod is not None and lastmod.text:
                            result["last_modified_dates"].append(lastmod.text.strip())

            result["url_count"] = len(result["urls"])

        except ET.ParseError as e:
            logger.debug(f"XML parse error for {url}: {e}")
            result["error"] = "XML parse error"
        except Exception as e:
            logger.debug(f"Error parsing sitemap {url}: {e}")
            result["error"] = str(e)

        return result

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
