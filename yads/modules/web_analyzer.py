import re
import dns.resolver
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
        
    def __init__(self, db_session=None, enable_cves: bool = False):
        super().__init__(db_session)
        self.enable_cves = enable_cves
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
            "emails": [],
            "socials": [],
            "documents": [],
            "phones": [],
            "broken_links": [],
            "http_status": 0,
            "https_status": 0,
            "https_redirect": False,
            "cves": [],
            "secrets": []
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
                self._check_cve(server, results)
            
            x_powered = r_https.headers.get("X-Powered-By")
            if x_powered:
                results["tech_stack"].append(f"PoweredBy: {x_powered}")
                if any(char.isdigit() for char in x_powered):
                     results["risk_hints"].append(f"Version Disclosure: {x_powered}")
                     self._check_cve(x_powered, results)

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

    def _scan_secrets(self, content: str, results: Dict[str, Any]):
        """
        Scans HTML/JS content for known secret patterns.
        """
        patterns = {
            "AWS Access Key": r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)(?![A-Z]{16}\b)[A-Z0-9]{16}\b",
            "Stripe Secret Key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
            "Google API Key": r"\bAIza[0-9A-Za-z\\-_]{35}\b",
            "Slack Token": r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
            "Private Key": r"-----BEGIN PRIVATE KEY-----",
            "Mailchimp API Key": r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
            "Heroku API Key": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "Facebook Access Token": r"\bEAACEdEose0cBA[0-9A-Za-z]+\b"
        }
        
        for name, regex in patterns.items():
            matches = re.finditer(regex, content)
            for match in matches:
                full_match = match.group(0)
                # Redact
                if len(full_match) > 8:
                    redacted = full_match[:4] + "*" * (len(full_match) - 8) + full_match[-4:]
                else:
                    redacted = "*" * len(full_match)
                
                # Check for uniqueness
                if not any(s['value'] == redacted for s in results["secrets"]):
                    results["secrets"].append({
                        "type": name,
                        "value": redacted,
                        "snippet": "..." # Snippets hard in minified JS, keeping concise
                    })
                    self.logger.warning(f"Potential Secret Found: {name}")

    def _check_cve(self, product_string: str, results: Dict[str, Any]):
        """
        Parses product string (e.g. 'nginx/1.18.0 (Ubuntu)') and looks up CVEs.
        """
        if not self.enable_cves:
            return

        if not product_string or ('/' not in product_string and ' ' not in product_string):
            return
        
        try:
            # Handle multiple products in one header (e.g. "nginx/1.18.0 (Ubuntu)")
            # or "PHP/7.4.3"
            
            # Simple splitter: treat spaces as separate products if they look like Prod/Ver
            parts = product_string.split(' ')
            for part in parts:
                if '/' in part:
                    p_split = part.split('/')
                    if len(p_split) == 2:
                        product = p_split[0]
                        version = p_split[1]
                        
                        # Cleanup version (remove trailing parens etc)
                        version = version.rstrip(';,()')
                        
                        # Skip generic
                        if product.lower() in ['cern-httpd', 'apache', 'nginx'] and not any(c.isdigit() for c in version):
                             continue

                        cves = lookup_cves(product, version)
                        if cves:
                            self.logger.warning(f"CVEs found for {product} {version}: {len(cves)}")
                            # Avoid dups
                            existing_ids = {c['id'] for c in results["cves"]}
                            for cve in cves:
                                if cve['id'] not in existing_ids:
                                    cve['product'] = f"{product} {version}" # Add context
                                    results["cves"].append(cve)
                                    existing_ids.add(cve['id'])
        except Exception as e:
            self.logger.error(f"CVE Check Error: {e}")

    def _run_headless(self, url: str, results: Dict[str, Any], timeout: int = 30):
        """
        Uses Playwright to render the page, take screenshot, and extract dynamic content.
        """
        try:
            with sync_playwright() as p:
                # Performance optimizations: disable-gpu, no-sandbox
                browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]) 
                
                context = browser.new_context()
                page = context.new_page()
                page.set_extra_http_headers({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"})
                
                try:
                    target_domain = url.split("//")[-1].split("/")[0]
                    self.limiter.wait(target_domain)
                    response = page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                except Exception as e:
                    results["headless_error_goto"] = str(e)
                
                content = page.content()
                results["title"] = page.title()
                
                # 0. Secret Scanning
                self._scan_secrets(content, results)
                
                # 1. Visual Identity (Favicon & OG)
                try:
                    icon_href = page.locator("link[rel*='icon']").first.get_attribute("href")
                    if icon_href: results["visuals"]["favicon"] = icon_href
                        
                    og_img = page.locator("meta[property='og:image']").first.get_attribute("content")
                    if og_img: results["visuals"]["og_image"] = og_img
                except: pass

                # 2. Sensitive Keyword Search
                keywords = ["Confidential", "Internal Use Only", "Index of /", "admin portal", "login", "dashboard"]
                page_text = page.inner_text("body").lower()
                for kw in keywords:
                    if kw.lower() in page_text:
                        results["keywords_found"].append(kw)

                # 3. Enhanced Fingerprinting & CVE (Regex on HTML + Meta Generators)
                
                # A. Meta Generator (High confidence version)
                try:
                    generators = page.locator("meta[name='generator']").all()
                    for gen in generators:
                        content_attr = gen.get_attribute("content")
                        if content_attr:
                            results["tech_stack"].append(f"Generator: {content_attr}")
                            # Try CVE check
                            # Generator often is "WordPress 5.8" (space sep) not "/"
                            if " " in content_attr:
                                p_parts = content_attr.split(" ")
                                if len(p_parts) >= 2:
                                    # Assume last part is version if digit?
                                    ver = p_parts[-1]
                                    prod = " ".join(p_parts[:-1])
                                    if any(c.isdigit() for c in ver):
                                        cves = lookup_cves(prod, ver)
                                        if cves:
                                             existing_ids = {c['id'] for c in results["cves"]}
                                             for cve in cves:
                                                 if cve['id'] not in existing_ids:
                                                     cve['product'] = content_attr
                                                     results["cves"].append(cve)
                except:
                    pass

                # B. Regex Signatures
                signatures = {
                    "WordPress": r"wp-content|wp-includes",
                    "Drupal": r"Drupal",
                    "Joomla": r"Joomla",
                    "React": r"data-reactroot",
                    "Vue.js": r"data-v-"
                }
                
                for tech, regex in signatures.items():
                    if re.search(regex, content, re.IGNORECASE):
                        if f"{tech}" not in results["tech_stack"]: 
                            results["tech_stack"].append(tech)

                # --- 4. OSINT Extraction ---
                # A. Emails
                email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                raw_emails = re.findall(email_regex, page_text)
                unique_emails = set()
                ignore_ext = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.css', '.js']
                for email in raw_emails:
                    email = email.lower()
                    if not any(email.endswith(ext) for ext in ignore_ext):
                         unique_emails.add(email)
                results["emails"] = list(unique_emails)

                # B. Social Media
                social_platforms = {
                    "linkedin": r"linkedin\.com/in/|linkedin\.com/company/",
                    "twitter": r"twitter\.com/|x\.com/",
                    "facebook": r"facebook\.com/",
                    "instagram": r"instagram\.com/",
                    "youtube": r"youtube\.com/|youtu\.be/",
                    "github": r"github\.com/",
                    "gitlab": r"gitlab\.com/"
                }
                found_socials = []
                try:
                    links = page.locator("a").evaluate_all("list => list.map(el => el.href)")
                    for link in links:
                        for platform, regex in social_platforms.items():
                            if re.search(regex, link, re.IGNORECASE):
                                if link not in found_socials: found_socials.append(link)
                except: pass
                results["socials"] = found_socials

                # C. Documents
                doc_exts = ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.csv']
                found_docs = []
                try:
                    for link in links:
                        lower_link = link.lower()
                        if any(lower_link.endswith(ext) for ext in doc_exts):
                            if link not in found_docs: found_docs.append(link)
                except: pass
                results["documents"] = found_docs
                
                # D. Phones
                phone_regex = r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
                found_phones = set()
                for match in re.finditer(phone_regex, page_text):
                    found_phones.add(match.group(0).strip())
                results["phones"] = list(found_phones)

                # --- 5. Broken Link Hijacking ---
                broken_links = []
                checked_domains = set()
                try:
                    from urllib.parse import urlparse
                    target_domain = urlparse(target).netloc if '://' in target else target
                    if not target_domain: target_domain = target
                    
                    for link in links:
                        try:
                            parsed = urlparse(link)
                            if not parsed.netloc: continue
                            if parsed.netloc == target_domain or parsed.netloc.endswith("." + target_domain): continue
                                
                            ext_domain = parsed.netloc
                            if ext_domain in checked_domains: continue
                            checked_domains.add(ext_domain)
                            
                            try:
                                dns.resolver.resolve(ext_domain, 'A')
                            except dns.resolver.NXDOMAIN:
                                broken_links.append(link)
                            except: pass
                        except: pass
                except: pass
                results["broken_links"] = broken_links

                # Meta tags general
                metas = page.locator("meta").all()
                for m in metas:
                    name = m.get_attribute("name")
                    content_attr = m.get_attribute("content")
                    if name and content_attr:
                        results["meta_tags"][name] = content_attr

                # Screenshot
                import os, uuid
                screenshot_filename = f"screenshot_{self.compute_hash({'u':url})}_{uuid.uuid4()}.png"
                screenshot_dir = "yads/api/static/screenshots"
                os.makedirs(screenshot_dir, exist_ok=True)
                page.screenshot(path=f"{screenshot_dir}/{screenshot_filename}")
                results["screenshot_path"] = screenshot_filename
                
                if page.url != url and page.url not in results["redirect_chain"]:
                    results["redirect_chain"].append(page.url)

                browser.close()
        except Exception as e:
            results["headless_error"] = str(e)
