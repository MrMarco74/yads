import requests
from typing import Any, Dict
from playwright.sync_api import sync_playwright

from yads.core.base import BaseScannerModule
from yads.config import settings
from yads.core.rate_limiter import RateLimiter
from yads.modules.cve_lookup import lookup_cves

import re

import logging

class WebAnalyzer(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "web_analyzer"
        
    def __init__(self, db_session=None):
        super().__init__(db_session)
        self.logger = logging.getLogger("yads.modules.web")
        self.limiter = RateLimiter()

    def run_scan(self, target: str) -> Dict[str, Any]:
        """
        Two-stage web analysis:
        1. Fast Header Check (Requests)
        2. Deep Scan (Playwright) - if needed or configured
        """
        results = {
            "http_headers": {},
            "status_code": None,
            "redirect_chain": [],
            "tech_stack": [],
            "risk_hints": [],
            "keywords_found": [],
            "visuals": {"favicon": None, "og_image": None},
            "screenshot_path": None,
            "meta_tags": {},
            "visuals": {"favicon": None, "og_image": None},
            "screenshot_path": None,
            "meta_tags": {},
            "title": None,
            "http_status": 0,
            "https_status": 0,
            "https_redirect": False,
            "cves": []
        }
        
        url = f"http://{target}" # Start with http, let it redirect to https
        
        # Determine Timeout (DB Override -> Config Default)
        timeout = settings.WEB_REQUEST_TIMEOUT
        if self.db:
            try:
                from yads.models import SystemConfig
                timeout_conf = self.db.get(SystemConfig, "WEB_REQUEST_TIMEOUT")
                if timeout_conf:
                    timeout = int(timeout_conf.value)
            except Exception:
                pass # Fallback to default
        
        # --- Stage 1: Connectivity Check & Basic Headers ---
        self.logger.info(f"Stage 1: Connectivity Check for {target} (Timeout: {timeout}s)")
        self.limiter.wait(target)
        
        # Check HTTP
        try:
            r_http = requests.get(f"http://{target}", timeout=timeout, allow_redirects=False)
            results["http_status"] = r_http.status_code
            
            # Check for redirect to HTTPS
            if r_http.is_redirect and r_http.headers.get("Location", "").startswith("https"):
                results["https_redirect"] = True
                
        except Exception:
            results["http_status"] = 0 # Failed

        # Check HTTPS
        try:
            r_https = requests.get(f"https://{target}", timeout=timeout, allow_redirects=True)
            results["https_status"] = r_https.status_code
            results["http_headers"] = dict(r_https.headers)
            results["redirect_chain"] = [r.url for r in r_https.history] + [r_https.url]
            results["status_code"] = r_https.status_code # Primary status for legacy logic
            
            # Simple Tech Stack fingerprinting via headers
            server = r_https.headers.get("Server")
            if server:
                results["tech_stack"].append(f"Server: {server}")
            
            x_powered = r_https.headers.get("X-Powered-By")
            if x_powered:
                results["tech_stack"].append(f"PoweredBy: {x_powered}")
                if any(char.isdigit() for char in x_powered):
                     results["risk_hints"].append(f"Version Disclosure: {x_powered}")
                     # Try CVE Lookup
                     parts = x_powered.split(' ')
                     if len(parts) >= 2: 
                         product = parts[0]
                         version = parts[1] 
                         if '/' in product and not version:
                             p2 = product.split('/')
                             product = p2[0]
                             version = p2[1]
                         product = product.split('/')[0]
                         cves = lookup_cves(product, version)
                         if cves:
                             results["cves"].extend(cves)

        except requests.RequestException as e:
             if results["http_status"] == 0:
                 results["error"] = f"Both HTTP/HTTPS failed: {e}"
                 return results
             # If HTTP worked but HTTPS failed, we still have some info
             results["https_status"] = 0

        # Decide which URL to use for Deep Scan (prefer HTTPS if available, else HTTP)
        url = f"https://{target}" if results["https_status"] > 0 else f"http://{target}"


        # --- Stage 2: Headless (Playwright) ---
        # Only run if Stage 1 succeeded (or logic dictates)
        if results["status_code"] is not None:
             self.logger.info("Stage 2: Starting Headless Scan (Playwright)...")
             self._run_headless(url, results, timeout)

        return results

    def _run_headless(self, url: str, results: Dict[str, Any], timeout: int = 30):
        """
        Uses Playwright to render the page, take screenshot, and extract dynamic content.
        """
        try:
            with sync_playwright() as p:
                # Performance optimizations: disable-gpu, no-sandbox
                browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]) 
                
                # Context with blocked resources
                context = browser.new_context()
                
                # Block unnecessary resources to speed up loading
                # (Images, Fonts, CSS for screenshot might be needed? 
                # Actually, CSS is needed for screenshot accuracy, but fonts/images often aren't critical for initial DOM analysis.
                # However, for a "Visual" scanner, we WANT screenshots to look right.
                # Let's start with just blocking Media/Fonts if possible, but keep CSS.
                # Or just keep it as is?
                # A huge speedup comes from just blocking trackers/ads, but we don't have a list.
                # Let's stick to Launch Args first.)
                
                page = context.new_page()
                
                # Set simple anti-bot evasions
                page.set_extra_http_headers({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})
                
                # Optimize page loading
                # page.route("**/*.{png,jpg,jpeg,gif,webp}", lambda route: route.abort()) # Valid for pure data, but hurts screenshot
                
                
                try:
                    # Rate Limit for Stage 2 as well
                    target_domain = url.split("//")[-1].split("/")[0]
                    self.limiter.wait(target_domain)
                    
                    response = page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                except Exception as e:
                    results["headless_error_goto"] = str(e)
                    # continue to screenshot even if networkidle timed out or 403
                
                content = page.content()
                results["title"] = page.title()
                
                # 1. Visual Identity (Favicon & OG)
                try:
                    # Favicon
                    icon_href = page.locator("link[rel*='icon']").first.get_attribute("href")
                    if icon_href:
                        results["visuals"]["favicon"] = icon_href
                        
                    # OG Image
                    og_img = page.locator("meta[property='og:image']").first.get_attribute("content")
                    if og_img:
                        results["visuals"]["og_image"] = og_img
                except:
                    pass

                # 2. Sensitive Keyword Search
                keywords = ["Confidential", "Internal Use Only", "Index of /", "admin portal", "login", "dashboard"]
                page_text = page.inner_text("body").lower()
                for kw in keywords:
                    if kw.lower() in page_text:
                        results["keywords_found"].append(kw)

                # 3. Enhanced Fingerprinting (Regex on HTML)
                signatures = {
                    "WordPress": r"wp-content|wp-includes",
                    "Drupal": r"Drupal",
                    "Joomla": r"Joomla",
                    "React": r"data-reactroot",
                    "Vue.js": r"data-v-"
                }
                
                for tech, regex in signatures.items():
                    if re.search(regex, content, re.IGNORECASE):
                        if f"{tech}" not in results["tech_stack"]: # Avoid duplicates if header found it
                            results["tech_stack"].append(tech)

                # Meta tags
                metas = page.locator("meta").all()
                for m in metas:
                    name = m.get_attribute("name")
                    content_attr = m.get_attribute("content")
                    if name and content_attr:
                        results["meta_tags"][name] = content_attr

                # Screenshot
                import os
                import uuid
                screenshot_filename = f"screenshot_{self.compute_hash({'u':url})}_{uuid.uuid4()}.png"
                screenshot_dir = "yads/api/static/screenshots"
                os.makedirs(screenshot_dir, exist_ok=True)
                
                page.screenshot(path=f"{screenshot_dir}/{screenshot_filename}")
                results["screenshot_path"] = screenshot_filename
                self.logger.info(f"Screenshot taken: {screenshot_filename}")
                
                # Check for JS redirects or meta refreshes that requests didn't catch
                if page.url != url and page.url not in results["redirect_chain"]:
                    results["redirect_chain"].append(page.url)

                browser.close()
        except Exception as e:
            results["headless_error"] = str(e)
