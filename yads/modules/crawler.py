import time
import re
import requests
import logging
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Any, Dict, List, Set, Deque, Optional
from collections import deque, Counter

import hashlib
import redis
import os
import uuid
from playwright.sync_api import sync_playwright

from yads.database import redis_client
from yads.config import settings
from yads.models import SystemConfig, HTTPTraffic
from yads.core.base import BaseScannerModule, sanitize_null_bytes
from yads.utils.sanitize import redact_headers
from sqlmodel import select

TEXT_HTML = "text/html"

class Crawler(BaseScannerModule):
    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.redis_client = redis_client

    @property
    def module_name(self) -> str:
        return "crawler"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """Slow crawler to map site structure and find anomalies."""
        config = self._load_config()
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 YADS/1.19"}
        
        start_url = target
        if not start_url.startswith("http"):
             start_url = f"https://{target}"
             
        # Initial Check / Fallback
        start_url = self._check_initial_url(start_url, headers, config["TIMEOUT"])
        
        queue: Deque[tuple[str, int]] = deque([(start_url, 0)])
        visited: Set[str] = set()
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []
        external_counts = Counter()
        traffic_log: List[Dict[str, Any]] = []
        
        playwright_data = self._init_browser(headers["User-Agent"])
        p_page = playwright_data.get("page")
        
        try:
            while queue and len(visited) < config["MAX_PAGES"]:
                current_url, depth = queue.popleft()
                if current_url in visited or self._is_globally_visited(current_url):
                    continue

                visited.add(current_url)
                if len(visited) > 1:
                    time.sleep(config["DELAY"])

                self._crawl_url(current_url, depth, headers, config, target_id, p_page, visited, nodes, edges, external_counts, traffic_log, queue)

            return self._analyze_crawl_results(nodes, edges, external_counts, visited, config["DEPTH_LIMIT"], traffic_log)

        finally:
            if playwright_data.get("browser"): playwright_data["browser"].close()
            if playwright_data.get("playwright"): playwright_data["playwright"].stop()

    def _load_config(self) -> Dict[str, Any]:
        """Loads crawler configuration."""
        config = {
            "MAX_PAGES": 100, "MAX_SCREENSHOTS": 10, "DEPTH_LIMIT": 3,
            "DELAY": 0.5, "TIMEOUT": 5, "screenshots_taken": 0
        }
        if self.db:
            try:
                delay_conf = self.db.get(SystemConfig, "WEB_RATE_LIMIT_DELAY")
                if delay_conf: config["DELAY"] = float(delay_conf.value)
                timeout_conf = self.db.get(SystemConfig, "WEB_REQUEST_TIMEOUT")
                if timeout_conf: config["TIMEOUT"] = int(timeout_conf.value)
            except Exception as e:
                logger.warning(f"Failed to load settings: {e}")
        return config

    def _check_initial_url(self, url: str, headers: Dict[str, str], timeout: int) -> str:
        """Checks if URL works, falls back to HTTP if HTTPS fails."""
        try:
            requests.get(url, headers=headers, timeout=timeout, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            return url
        except Exception:
            if url.startswith("https"):
                fallback = url.replace("https://", "http://")
                try:
                    requests.get(fallback, headers=headers, timeout=timeout, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
                    return fallback
                except Exception:
                    pass
        return url

    def _init_browser(self, user_agent: str) -> Dict[str, Any]:
        """Initializes Playwright browser."""
        try:
            playwright = sync_playwright().start()
            browser = playwright.chromium.launch(headless=True, args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 800})
            page = context.new_page()
            page.set_extra_http_headers({"User-Agent": user_agent})
            return {"playwright": playwright, "browser": browser, "page": page}
        except Exception as e:
            logger.error(f"Failed to initialize Playwright: {e}")
            return {}

    def _is_globally_visited(self, url: str) -> bool:
        """Checks Redis for global deduplication."""
        if not self.redis_client: return False
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        redis_key = f"crawler:visited:{url_hash}"
        if self.redis_client.exists(redis_key): return True
        self.redis_client.setex(redis_key, 86400, "1")
        return False

    def _fetch_page(self, url: str, headers: Dict[str, str], timeout: int, target_id: Optional[int]) -> Dict[str, Any]:
        """Fetches page via requests and logs traffic."""
        start_time = time.time()
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            duration = time.time() - start_time
            body = resp.text or ""
            traffic = {
                "url": url, "method": "GET", "status": resp.status_code, "duration": round(duration, 3),
                "request_headers": redact_headers(dict(resp.request.headers)), 
                "response_headers": redact_headers(dict(resp.headers)),
                "response_body_snippet": sanitize_null_bytes(body[:1024])
            }
            if self.db and target_id:
                self._log_traffic(traffic, target_id)
            return {"status": resp.status_code, "content_type": resp.headers.get('Content-Type', ''), "html": body, "traffic": traffic}
        except Exception as e:
            traffic = {
                "url": url, "method": "GET", "status": 0, "error": sanitize_null_bytes(str(e)), 
                "duration": round(duration, 3), "request_headers": redact_headers(headers)
            }
            raise e

    def _log_traffic(self, traffic: Dict[str, Any], target_id: int):
        """Saves traffic record to DB."""
        try:
            record = HTTPTraffic(
                target_id=target_id, method=traffic["method"], url=traffic["url"],
                status_code=traffic.get("status", 0), request_headers=traffic.get("request_headers"),
                response_headers=traffic.get("response_headers"),
                response_body_snippet=traffic.get("response_body_snippet"),
                duration=traffic["duration"]
            )
            self.db.add(record)
        except Exception as e:
            logger.warning(f"Failed to save traffic record: {e}")

    def _extract_title(self, html: str) -> str:
        """Extracts title using regex."""
        m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if m: return sanitize_null_bytes(m.group(1).strip())[:100]
        return "Unknown"

    def _take_screenshot(self, page: Any, url: str, timeout: int) -> Optional[str]:
        """Captures page screenshot."""
        try:
            filename = f"crawler_{self.compute_hash({'u':url})}_{uuid.uuid4()}.png"
            path = os.path.join("yads/api/static/screenshots", filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            page.screenshot(path=path, full_page=False)
            return filename
        except Exception as e:
            logger.warning(f"Screenshot failed for {url}: {e}")
        return None

    def _normalize_url(self, url: str, base: str) -> Optional[str]:
        """Normalizes relative URL to absolute."""
        try:
            joined = urljoin(base, url)
            p = urlparse(joined)
            return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
        except Exception:
            return None

    def _process_links(self, html: str, current_url: str, base_domain: str, depth: int, visited: Set[str], edges: List[Dict[str, str]], external_counts: Counter) -> List[tuple[str, int]]:
        """Extracts and classifies links."""
        links = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']*)["\']', html, re.IGNORECASE)
        new_links = []
        for link in links:
            full = self._normalize_url(link, current_url)
            if not full: continue
            
            p = urlparse(full)
            is_internal = p.netloc == base_domain or p.netloc == ""
            edges.append({"source": current_url, "target": full, "type": "internal" if is_internal else "external"})
            
            if is_internal:
                if full not in visited:
                    new_links.append((full, depth + 1))
            elif p.netloc:
                external_counts[p.netloc] += 1
        return new_links

    def _analyze_crawl_results(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, str]], external_counts: Counter, visited: Set[str], depth_limit: int, traffic_log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarizes crawl data."""
        outgoing_internal = Counter([e['source'] for e in edges if e.get('type') == 'internal'])
        dead_ends = [{"url": n['id'], "title": n['title']} for n in nodes if outgoing_internal[n['id']] == 0 and n['status'] == 200 and n.get('type') != 'internal_error']
        collectors = [{"domain": k, "count": v} for k, v in external_counts.most_common(10)]

        return {
            "stats": {"pages_crawled": len(visited), "depth_reached": depth_limit, "total_links": len(edges)},
            "dead_ends": dead_ends, "collectors": collectors, "edges": edges, "nodes": nodes,
            "http_traffic": traffic_log, "sample_nodes": nodes[:5]
        }

    def _crawl_url(self, url: str, depth: int, headers: Dict[str, str], config: Dict[str, Any], target_id: Optional[int], p_page: Any, visited: Set[str], nodes: List[Dict[str, Any]], edges: List[Dict[str, str]], external_counts: Counter, traffic_log: List[Dict[str, Any]], queue: Deque):
        """Processes a single URL in the crawl queue."""
        try:
            page_data = self._fetch_page(url, headers, config["TIMEOUT"], target_id)
            traffic_log.append(page_data["traffic"])
            
            status, content_type, html = page_data["status"], page_data["content_type"], page_data["html"]
            is_html = TEXT_HTML in content_type
            
            node_entry = {
                "id": url, "status": status, "type": "internal", "screenshot": None,
                "title": self._extract_title(html) if is_html else "Unknown"
            }

            if p_page and status == 200 and is_html and config["screenshots_taken"] < config["MAX_SCREENSHOTS"]:
                screenshot = self._take_screenshot(p_page, url, config["TIMEOUT"])
                if screenshot:
                    node_entry["screenshot"] = screenshot
                    config["screenshots_taken"] += 1

            nodes.append(node_entry)

            if status == 200 and is_html and depth < config["DEPTH_LIMIT"]:
                base_domain = urlparse(url).netloc
                new_links = self._process_links(html, url, base_domain, depth, visited, edges, external_counts)
                queue.extend(new_links)

        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            nodes.append({
                "id": url, "title": "Error", "status": 0,
                "error": sanitize_null_bytes(str(e)), "type": "internal_error"
            })
    
    def __del__(self):
        # Base class might not have cleanup, but we should try to close playwright if it leaked
        # Actually it's better to use try/finally in run_scan
        pass
