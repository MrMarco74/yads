import time
import re
import requests
import logging
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Any, Dict, List, Set, Deque
from collections import deque, Counter

from yads.core.base import BaseScannerModule
from yads.config import settings
from yads.models import SystemConfig
from sqlmodel import select

class Crawler(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "crawler"

    def run_scan(self, target: str) -> Dict[str, Any]:
        """
        Slow crawler to map site structure and find anomalies.
        """
        logger = logging.getLogger("yads.modules.crawler")
        
        # Configuration (Defaults)
        MAX_PAGES = 100
        DEPTH_LIMIT = 3
        DELAY = 0.5 
        TIMEOUT = 5

        # Override from Settings
        if self.db:
            try:
                # Delay
                delay_conf = self.db.get(SystemConfig, "WEB_RATE_LIMIT_DELAY")
                if delay_conf:
                    DELAY = float(delay_conf.value)
                
                # Timeout
                timeout_conf = self.db.get(SystemConfig, "WEB_REQUEST_TIMEOUT")
                if timeout_conf:
                    TIMEOUT = int(timeout_conf.value)
            except Exception as e:
                logger.warning(f"Failed to load settings: {e}")

        HEADERS = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        # State
        start_url = target
        if not start_url.startswith("http"):
             start_url = f"https://{target}"
             
        # Initial Check (Fallback to HTTP if HTTPS fails, to avoid 0s scan)
        try:
            requests.get(start_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        except:
            if start_url.startswith("https"):
                fallback = start_url.replace("https://", "http://")
                try:
                    requests.get(fallback, headers=HEADERS, timeout=TIMEOUT, verify=False)
                    start_url = fallback
                    logger.info(f"HTTPS failed, falling back to {start_url}")
                except:
                    pass # Let the main loop handle it (and fail/log error node)
        
        # Normalize start_url to ensure we stay on domain
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        # Queue: (url, depth)
        queue: Deque[tuple[str, int]] = deque([(start_url, 0)])
        visited: Set[str] = set()
        
        # Graph Data
        nodes: List[Dict[str, Any]] = [] # {id: url, title: str, status: int, type: internal/internal_error}
        edges: List[Dict[str, str]] = [] # {source: url, target: url}
        external_counts = Counter()
        
        # Helper to normalize URL
        def normalize(url, base):
            try:
                joined = urljoin(base, url)
                parsed = urlparse(joined)
                # Remove fragment
                clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
                return clean
            except:
                return None

        # Helper to extract links (Regex to avoid external dependencies like bs4 for now)
        # <a href="...">
        href_re = re.compile(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']*)["\']', re.IGNORECASE)
        title_re = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)

        logger.info(f"Starting crawl of {start_url} (Max Pages: {MAX_PAGES})")

        pages_processed = 0
        
        while queue and len(visited) < MAX_PAGES:
            current_url, depth = queue.popleft()
            
            if current_url in visited:
                continue
            
            visited.add(current_url)
            pages_processed += 1
            
            # Fetch
            try:
                # Polite Delay
                if pages_processed > 1:
                    time.sleep(DELAY)
                    
                if pages_processed > 1:
                    time.sleep(DELAY)
                    
                resp = requests.get(current_url, headers=HEADERS, timeout=TIMEOUT, verify=False) # Skip SSL verify for broader coverage
                status = resp.status_code
                content_type = resp.headers.get('Content-Type', '')
                
                # Extract Title
                title = "Unknown"
                if "text/html" in content_type:
                    m = title_re.search(resp.text)
                    if m:
                        title = m.group(1).strip()
                
                # Add Node
                nodes.append({
                    "id": current_url,
                    "title": title[:50] + "..." if len(title) > 50 else title,
                    "status": status,
                    "type": "internal"
                })
                
                # If OK and HTML and within depth, parse links
                if status == 200 and "text/html" in content_type and depth < DEPTH_LIMIT:
                    links = href_re.findall(resp.text)
                    for link in links:
                        full_link = normalize(link, current_url)
                        if not full_link: continue
                        
                        # Classify
                        link_parsed = urlparse(full_link)
                        # Internal if netloc matches base or is empty (relative)
                        is_internal = link_parsed.netloc == base_domain or link_parsed.netloc == ""
                        
                        # Add Edge
                        edges.append({"source": current_url, "target": full_link, "type": "internal" if is_internal else "external"})
                        
                        if is_internal:
                            if full_link not in visited:
                                # Prioritize by depth (BFS is natural with queue)
                                queue.append((full_link, depth + 1))
                        else:
                            # External
                            if link_parsed.netloc:
                                external_counts[link_parsed.netloc] += 1
                            
            except Exception as e:
                logger.debug(f"Failed to fetch {current_url}: {e}")
                nodes.append({
                    "id": current_url,
                    "title": "Error",
                    "status": 0,
                    "error": str(e),
                    "type": "internal_error"
                })

        # Analysis
        # 1. Dead Ends: Internal nodes with NO outgoing INTERNAL links (that are not errors)
        # We need to map outgoing internal (source -> count)
        outgoing_internal_map = Counter([e['source'] for e in edges if e.get('type') == 'internal'])
            
        dead_ends = [
            {"url": node['id'], "title": node['title']} 
            for node in nodes 
            if outgoing_internal_map[node['id']] == 0 and node['status'] == 200 and node.get('type') != 'internal_error'
        ]
        
        # 2. Collector Domains (Top 10)
        collectors = [{"domain": k, "count": v} for k, v in external_counts.most_common(10)]

        return {
            "stats": {
                "pages_crawled": len(visited),
                "depth_reached": DEPTH_LIMIT,
                "total_links": len(edges)
            },
            "dead_ends": dead_ends,
            "collectors": collectors,
            "edges": edges, # Persist edges for graph viz
            "nodes": nodes, # Persist nodes (optional, but good for context)
            "sample_nodes": nodes[:5] 
        }
