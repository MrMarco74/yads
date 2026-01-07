import requests
from typing import Any, Dict
from playwright.sync_api import sync_playwright

from yads.core.base import BaseScannerModule
from yads.config import settings
from yads.modules.cve_lookup import lookup_cves

import re

class WebAnalyzer(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "web_analyzer"

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
            "cves": []
        }
        
        url = f"http://{target}" # Start with http, let it redirect to https
        
        # --- Stage 1: Fast Check ---
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            results["status_code"] = resp.status_code
            results["http_headers"] = dict(resp.headers)
            results["redirect_chain"] = [r.url for r in resp.history]
            
            # Simple Tech Stack fingerprinting via headers
            server = resp.headers.get("Server")
            if server:
                results["tech_stack"].append(f"Server: {server}")
            
            x_powered = resp.headers.get("X-Powered-By")
            if x_powered:
                results["tech_stack"].append(f"PoweredBy: {x_powered}")
                # Risk Hint for revealing version
                if any(char.isdigit() for char in x_powered):
                     results["risk_hints"].append(f"Version Disclosure: {x_powered}")
                     # Try CVE Lookup
                     # Assuming format "Product/Version" or "Product Version"
                     parts = x_powered.split(' ')
                     if len(parts) >= 2: # Very basic split
                         product = parts[0]
                         version = parts[1] # e.g. PHP/7.4.3 -> PHP, 7.4.3
                         if '/' in product and not version: # handling Product/Version without space
                             p2 = product.split('/')
                             product = p2[0]
                             version = p2[1]
                         
                         # Cleanup
                         product = product.split('/')[0]
                         
                         cves = lookup_cves(product, version)
                         if cves:
                             results["cves"].extend(cves)

        except requests.RequestException as e:
            results["error"] = str(e)
            return results

        # --- Stage 2: Headless (Playwright) ---
        # Only run if Stage 1 succeeded (or logic dictates)
        if results["status_code"] is not None:
             self._run_headless(url, results)

        return results

    def _run_headless(self, url: str, results: Dict[str, Any]):
        """
        Uses Playwright to render the page, take screenshot, and extract dynamic content.
        """
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True) # executable_path=settings.CHROME_BIN if needed
                page = browser.new_page()
                
                # Set simple anti-bot evasions
                page.set_extra_http_headers({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})
                
                try:
                    response = page.goto(url, wait_until="networkidle", timeout=30000)
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
                
                # Check for JS redirects or meta refreshes that requests didn't catch
                if page.url != url and page.url not in results["redirect_chain"]:
                    results["redirect_chain"].append(page.url)

                browser.close()
        except Exception as e:
            results["headless_error"] = str(e)
