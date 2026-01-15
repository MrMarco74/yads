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

TECH_SIGNATURES = {
    # CMS / Frameworks
    "WordPress": {
        "meta": {"generator": r"WordPress"},
        "script": [r"wp-content", r"wp-includes"],
        "html": [r"wp-json"],
        "headers": {"X-Powered-By": r"WordPress"}
    },
    "Joomla": {
        "meta": {"generator": r"Joomla"},
        "html": [r"Joomla!"],
        "headers": {"X-Content-Encoded-By": r"Joomla"}
    },
    "Drupal": {
        "meta": {"generator": r"Drupal"},
        "headers": {"X-Generator": r"Drupal"},
        "script": [r"drupal.js"]
    },
    "Magento": {
        "script": [r"mage/cookies", r"varien/js"],
        "html": [r"Mage\.Cookies"],
        "headers": {"X-Magento-Vary": r".*"}
    },
    "Shopify": {
        "html": [r"shopify\.com"],
        "script": [r"cdn\.shopify\.com"],
        "headers": {"X-Shopify-Stage": r".*"}
    },
    "Wix": {
        "meta": {"generator": r"Wix"},
        "headers": {"X-Wix-Request-Id": r".*"}
    },
    "Squarespace": {
        "headers": {"X-Served-By": r"Squarespace"}
    },
    
    # JavaScript Frameworks
    "React": {
        "html": [r"data-reactroot", r"react-dom"],
        "script": [r"react\.production\.min\.js", r"react\.development\.js"]
    },
    "Vue.js": {
        "html": [r"data-v-", r"vue-root"],
        "script": [r"vue\.js", r"vue\.min\.js"]
    },
    "Angular": {
        "html": [r"ng-app", r"ng-controller", r"ng-version"],
        "script": [r"angular\.js"]
    },
    "Svelte": {
        "html": [r"svelte-"],
        "script": [r"svelte-internal"]
    },
    
    # Web Servers (Headers mostly)
    "Nginx": {
        "headers": {"Server": r"nginx"}
    },
    "Apache": {
        "headers": {"Server": r"Apache"}
    },
    "IIS": {
        "headers": {"Server": r"IIS"}
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"}
    },
    "Cloudflare": {
        "headers": {"Server": r"cloudflare", "CF-RAY": r".*"}
    },
    
    # Backend Tech
    "PHP": {
        "headers": {"X-Powered-By": r"PHP", "Set-Cookie": r"PHPSESSID"}
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "Set-Cookie": r"ASPSESSIONID"}
    },
    "Laravel": {
        "headers": {"Set-Cookie": r"laravel_session", "X-Powered-By": r"Laravel"}
    },
    "Django": {
        "headers": {"Set-Cookie": r"csrftoken"},
        "html": [r"csrfmiddlewaretoken"]
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger", "X-Runtime": r".*"},
        "meta": {"csrf-param": r"authenticity_token"}
    },
    "Express": {
        "headers": {"X-Powered-By": r"Express"}
    },
    
    # UI / Libraries
    "Bootstrap": {
        "script": [r"bootstrap(\.min)?\.js"],
        "html": [r"bootstrap(\.min)?\.css"]
    },
    "jQuery": {
        "script": [r"jquery.*\.js"]
    },
    "Tailwind CSS": {
        "html": [r"tailwindcss"]
    },
    "FontAwesome": {
        "html": [r"fa-", r"font-awesome"],
        "script": [r"fontawesome"]
    },
    
    # Analytics / Marketing
    "Google Analytics": {
        "script": [r"google-analytics\.com/analytics\.js", r"googletagmanager\.com/gtag/js"],
        "cookies": [r"_ga", r"_gid"]
    },
    "Google Tag Manager": {
        "script": [r"googletagmanager\.com/gtm\.js"],
        "html": [r"googletagmanager\.com/ns\.html"]
    },
    "Hotjar": {
        "script": [r"static\.hotjar\.com"]
    },
    "Facebook Pixel": {
        "script": [r"connect\.facebook\.net/en_US/fbevents\.js"]
    }
}

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
            "secrets": [],
            "api_endpoints": [],
            "js_analysis": {
                "files_analyzed": [],
                "findings": []
            },
            "api_specs": [],
            "is_login_page": False
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
            r_http = requests.get(f"http://{target}", timeout=timeout, allow_redirects=False, verify=False)
            results["http_status"] = r_http.status_code
            
            # Check for redirect to HTTPS
            if r_http.is_redirect and r_http.headers.get("Location", "").startswith("https"):
                results["https_redirect"] = True
            
            # 401 means Basic Auth -> Login Page
            if r_http.status_code == 401:
                results["is_login_page"] = True
                self.logger.info(f"Login Page Detected (HTTP 401) for {target}")
                
        except Exception:
            results["http_status"] = 0 # Failed

        # Check HTTPS
        try:
            r_https = requests.get(f"https://{target}", timeout=timeout, allow_redirects=True, verify=False)
            results["https_status"] = r_https.status_code
            results["http_headers"] = dict(r_https.headers)
            results["redirect_chain"] = [r.url for r in r_https.history] + [r_https.url]
            results["status_code"] = r_https.status_code # Primary status for legacy logic
            
            # Tech Stack fingerprinting via headers (Stage 1)
            for tech, signatures in TECH_SIGNATURES.items():
                if "headers" in signatures:
                    for header_name, regex in signatures["headers"].items():
                        header_val = results["http_headers"].get(header_name) or results["http_headers"].get(header_name.lower())
                        if header_val:
                            if re.search(regex, header_val, re.IGNORECASE):
                                if tech not in results["tech_stack"]:
                                    results["tech_stack"].append(tech)
                                    
                                    # Version extraction hints
                                    # Start with simple one: if header has digits, maybe version?
                                    # Refined: checks if the matched value actually contains the version
                                    # This is a broad heuristic.
                                    if any(c.isdigit() for c in header_val) and len(header_val) < 50:
                                         # Try to isolate version? 
                                         # For now, just logging the hint or sending to CVE check
                                         self._check_cve(f"{tech} {header_val}", results)

        except requests.RequestException as e:
             if results["http_status"] == 0:
                 results["error"] = f"Both HTTP/HTTPS failed: {e}"
                 return results
             # If HTTP worked but HTTPS failed, we still have some info
             results["https_status"] = 0
             if results["http_status"] > 0:
                 results["status_code"] = results["http_status"]

        # Decide which URL to use for Deep Scan (prefer HTTPS if available, else HTTP)
        url = f"https://{target}" if results["https_status"] > 0 else f"http://{target}"


        # --- Stage 2: Headless (Playwright) ---
        # Only run if Stage 1 succeeded (or logic dictates)
        if results["status_code"] is not None:
             self.logger.info("Stage 2: Starting Headless Scan (Playwright)...")
             self._run_headless(url, results, timeout)

        # --- Stage 3: Smart Merge (Data Preservation) ---
        # If we failed to find technologies/title (likely timeout/error), 
        # try to restore from previous scan to avoid "blinking" dashboard.
        if not results["tech_stack"] and self.db:
            try:
                from yads.models import Target, ScanResult
                from sqlmodel import select
                
                # We need target_id. `target` arg is string domain.
                t_obj = self.db.exec(select(Target).where(Target.domain == target)).first()
                if t_obj:
                    # Fetch LAST successful WebAnalyzer result
                    prev = self.db.exec(select(ScanResult).where(
                        ScanResult.target_id == t_obj.id,
                        ScanResult.module_name == "web_analyzer"
                    ).order_by(ScanResult.scanned_at.desc())).first()
                    
                    if prev and prev.data:
                         prev_stack = prev.data.get("tech_stack", [])
                         if prev_stack:
                             results["tech_stack"] = prev_stack
                             results["risk_hints"].append("Cached technologies used (Scan failed)")
                             self.logger.info(f"Restored {len(prev_stack)} technologies from history.")
                         
                         if not results.get("title") and prev.data.get("title"):
                             results["title"] = prev.data.get("title")

            except Exception as e:
                self.logger.error(f"Smart Merge failed: {e}")

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
                # No Redaction per user request
                redacted = full_match
                
                # Check for uniqueness
                if not any(s['value'] == redacted for s in results["secrets"]):
                    results["secrets"].append({
                        "type": name,
                        "value": redacted,
                        "snippet": "..." # Snippets hard in minified JS, keeping concise
                    })
                    self.logger.warning(f"Potential Secret Found: {name}")

    def _scan_api_endpoints(self, content: str, results: Dict[str, Any], page=None):
        """
        Scans for API endpoints and documentation.
        """
        api_patterns = {
            "Swagger/OpenAPI": r"swagger\.json|openapi\.yaml|/api-docs|swagger-ui",
            "GraphQL": r"/graphql\b|query\s*\{|mutation\s*\{",
            "REST API (Versioned)": r"/api/v\d+/",
            "WSDL/SOAP": r"\.wsdl\b|\.asmx\b",
            "Health Check": r"/health\b|/actuator/health",
        }
        
        found = []
        
        # 1. Regex on Content
        for type_name, regex in api_patterns.items():
            if re.search(regex, content, re.IGNORECASE):
                found.append({"type": type_name, "source": "content_regex"})
                
        # 2. Check Intercepted Requests (if page available)
        # We can't easily access request history from here unless we tracked it during goto
        # But we can check links in the page
        if page:
             try:
                 links = page.locator("a").evaluate_all("list => list.map(el => el.href)")
                 for link in links:
                     for type_name, regex in api_patterns.items():
                         if re.search(regex, link, re.IGNORECASE):
                             # Avoid dups
                             if not any(f.get('url') == link for f in found):
                                 found.append({"type": type_name, "source": "link", "url": link})
                                 
                                 # If it's Swagger, try to parse it immediately
                                 if type_name == "Swagger/OpenAPI":
                                     self._fetch_and_parse_swagger(link, results)
             except: pass

        results["api_endpoints"] = found

    def _fetch_and_parse_swagger(self, url: str, results: Dict[str, Any]):
        """
        Attempts to download and parse a Swagger/OpenAPI Definition.
        """
        try:
            # Check if already parsed
            if any(s['url'] == url for s in results.get("api_specs", [])):
                return

            r = requests.get(url, timeout=5, verify=False)
            if r.status_code != 200: return
            
            spec = None
            try:
                spec = r.json()
            except:
                pass # Could try YAML later if needed
            
            if not spec or not isinstance(spec, dict):
                return
                
            # Basic Validation (Swagger 2.0 or OpenAPI 3.0)
            if not ("swagger" in spec or "openapi" in spec):
                return
                
            endpoints = []
            paths = spec.get("paths", {})
            for path, methods in paths.items():
                # Extract methods (get, post, etc.)
                active_methods = [m.upper() for m in methods.keys() if m.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']]
                endpoints.append({
                    "path": path,
                    "methods": active_methods
                })
                
            if endpoints:
                results["api_specs"].append({
                    "url": url,
                    "version": spec.get("info", {}).get("version", "unknown"),
                    "title": spec.get("info", {}).get("title", "Unknown API"),
                    "endpoints": endpoints
                })
                self.logger.info(f"Parsed Swagger Spec at {url}: {len(endpoints)} endpoints found.")

        except Exception as e:
            self.logger.error(f"Swagger Parse Error: {e}")

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
                
                context = browser.new_context(ignore_https_errors=True)
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
                self._scan_secrets(content, results)
                self._scan_api_endpoints(content, results, page)
                
                # 0.1 JS SAST Analysis
                self._scan_js_files(page, url, results)
                
                # 0.5 Login Page Detection
                try:
                    # Check 1: Password Input
                    pw_count = page.locator("input[type='password']").count()
                    if pw_count > 0:
                        results["is_login_page"] = True
                        self.logger.info(f"Login Page Detected (Password Input) for {url}")
                    
                    # Check 2: Title Keywords (if not already found)
                    if not results["is_login_page"] and results["title"]:
                        t_lower = results["title"].lower()
                        if "login" in t_lower or "sign in" in t_lower or "anmeldung" in t_lower:
                            results["is_login_page"] = True
                            self.logger.info(f"Login Page Detected (Title Keyword) for {url}")
                            
                except Exception as e:
                    self.logger.error(f"Login detection failed: {e}")
                
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
                title_text = (results.get("title") or "").lower()
                
                found_dir_listing = False
                
                # Check for Directory Listing (Title or Body)
                if "index of /" in title_text or "index of /" in page_text:
                     found_dir_listing = True
                     if "Index of /" not in results["keywords_found"]:
                         results["keywords_found"].append("Index of /")

                for kw in keywords:
                    if kw.lower() in page_text:
                        # Avoid duplicating Index of / if already added
                        if kw == "Index of /": continue
                        results["keywords_found"].append(kw)
                
                if found_dir_listing:
                    hint = "Directory Listing Enabled"
                    if hint not in results["risk_hints"]:
                        results["risk_hints"].append(hint)
                    
                    # Explicit Vulnerability
                    vuln_id = "MISC-DIR-LISTING"
                    if not any(v.get('id') == vuln_id for v in results["cves"]):
                        results["cves"].append({
                            "id": vuln_id,
                            "severity": "MEDIUM",
                            "cvss": 5.3,
                            "description": "Directory Browsing is enabled (Index of / found). This exposes the web server's file structure and may allow attackers to download sensitive files not intended for public access.",
                            "references": ["https://cwe.mitre.org/data/definitions/548.html"],
                            "product": "Web Server Configuration"
                        })

                # 3. Enhanced Fingerprinting & CVE (Comprehensive)
                
                # Gather data points
                cookies_list = context.cookies()
                cookie_names = [c["name"] for c in cookies_list]
                
                # Re-check headers from response if accessible (Playwright response object)
                # But we mostly rely on Requests for headers.
                
                # Check Signatures
                for tech, signatures in TECH_SIGNATURES.items():
                    if tech in results["tech_stack"]:
                        continue # Already found
                        
                    # Meta Tags
                    if "meta" in signatures:
                        for m_name, m_regex in signatures["meta"].items():
                            val = results["meta_tags"].get(m_name)
                            if val and re.search(m_regex, val, re.IGNORECASE):
                                results["tech_stack"].append(tech)
                                if any(c.isdigit() for c in val):
                                    self._check_cve(f"{tech} {val}", results)
                                break
                    
                    if tech in results["tech_stack"]: continue

                    # HTML Content
                    if "html" in signatures:
                        for html_regex in signatures["html"]:
                            if re.search(html_regex, content, re.IGNORECASE):
                                results["tech_stack"].append(tech)
                                break
                                
                    if tech in results["tech_stack"]: continue

                    # Scripts (src)
                    if "script" in signatures:
                        try:
                            # We can re-evaluate script tags or check network requests if we tracked them
                            # Simple approach: check script src in DOM
                            script_srcs = page.locator("script[src]").evaluate_all("list => list.map(el => el.src)")
                            found_script = False
                            for src in script_srcs:
                                for s_regex in signatures["script"]:
                                    if re.search(s_regex, src, re.IGNORECASE):
                                        results["tech_stack"].append(tech)
                                        found_script = True
                                        break
                                if found_script: break
                        except: pass
                        
                    if tech in results["tech_stack"]: continue

                    # Cookies
                    if "cookies" in signatures:
                        for c_regex in signatures["cookies"]:
                            if any(re.search(c_regex, c_name, re.IGNORECASE) for c_name in cookie_names):
                                results["tech_stack"].append(tech)
                                break

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

    def _scan_js_files(self, page, base_url: str, results: Dict[str, Any]):
        """
        Fetches and statically analyzes referenced JS files for sinks and routes.
        """
        try:
            # Get all script srcs
            scripts = page.locator("script[src]").evaluate_all("list => list.map(el => el.src)")
            
            # Patterns
            sinks = {
                "Dangerous Sink (innerHTML)": r"\.innerHTML\s*=",
                "Dangerous Sink (outerHTML)": r"\.outerHTML\s*=",
                "Dangerous Sink (document.write)": r"document\.write\(",
                "Dangerous Func (eval)": r"\beval\(",
                "Dangerous Sink (location assignment)": r"location\.(href|search)\s*=",
                "Open Redirect Potential": r"window\.location\s*="
            }
            
            # Simple heuristic for routes: strings starting with /api, /v1, etc.
            # Avoid overly generic paths.
            route_pattern = r"['\"](\/api\/[\w\-\/]+|\/v\d\/[\w\-\/]+|\/graphql|\/admin\/[\w\-\/]+)['\"]"
            
            analyzed_count = 0
            # Limit analysis
            max_files = 10
            
            from urllib.parse import urlparse
            base_domain = urlparse(base_url).netloc
            
            for src in scripts:
                if analyzed_count >= max_files: break
                
                # Filter: Only scan same-origin or relevant subdomains logic?
                # For now, simplistic: if it contains the domain name OR is relative (which playwright resolves to absolute, so check domain)
                src_domain = urlparse(src).netloc
                if base_domain not in src_domain and "cdn" in src_domain:
                    # Skip generic CDNs
                    continue
                
                if src in results["js_analysis"]["files_analyzed"]:
                    continue
                
                try:
                    # Fetch
                    r = requests.get(src, timeout=5, verify=False)
                    if r.status_code == 200:
                        content = r.text
                        results["js_analysis"]["files_analyzed"].append(src)
                        analyzed_count += 1
                        
                        # Check Sinks
                        for name, regex in sinks.items():
                            if re.search(regex, content):
                                results["js_analysis"]["findings"].append({
                                    "file": src,
                                    "type": "sink",
                                    "name": name,
                                    "severity": "medium", # SAST is prone to FP, so medium default
                                    "details": f"Found pattern: {regex}"
                                })
                        
                        # Check Routes
                        matches = re.finditer(route_pattern, content)
                        for m in matches:
                            route = m.group(1)
                            # Avoid duplicates globally or per file?
                            # Let's add if unique
                            if not any(f.get('route') == route for f in results["js_analysis"]["findings"]):
                                results["js_analysis"]["findings"].append({
                                    "file": src,
                                    "type": "route",
                                    "name": "Hidden API Route",
                                    "severity": "info",
                                    "route": route,
                                    "details": f"Discovered potential endpoint: {route}"
                                })

                except Exception as e:
                    pass
                    
        except Exception as e:
            self.logger.error(f"JS Analysis failed: {e}")
