import re
import dns.resolver
import requests
from typing import Any, Dict, Optional, List, Set
from playwright.sync_api import sync_playwright
import time

from yads.core.base import BaseScannerModule
from yads.config import settings
from yads.core.rate_limiter import RateLimiter
from yads.modules.cve_lookup import lookup_cves
from yads.models import HTTPTraffic
from yads.utils.sanitize import redact_headers

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
    INDEX_OF_SLASH = "Index of /"
    @property
    def module_name(self) -> str:
        return "web_analyzer"
        
    def __init__(self, db_session=None, enable_cves: bool = False):
        super().__init__(db_session)
        self.enable_cves = enable_cves
        self.logger = logging.getLogger("yads.modules.web")
        self.limiter = RateLimiter()

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Two-stage web analysis:
        1. Fast Header Check (Requests)
        2. Deep Scan (Playwright) - if needed or configured
        """
        results = {
            "http_headers": {}, "status_code": None, "redirect_chain": [], "tech_stack": [],
            "risk_hints": [], "keywords_found": [], "visuals": {"favicon": None, "og_image": None},
            "screenshot_path": None, "meta_tags": {}, "title": None, "emails": [], "socials": [],
            "documents": [], "phones": [], "broken_links": [], "http_status": 0, "https_status": 0,
            "https_redirect": False, "cves": [], "secrets": [], "api_endpoints": [],
            "js_analysis": {"files_analyzed": [], "findings": []}, "api_specs": [], "is_login_page": False
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
        
        # Stage 1: Connectivity & Basic Headers
        url = self._check_connectivity_and_headers(target, timeout, target_id, results)


        # --- Stage 2: Headless (Playwright) ---
        # Only run if Stage 1 succeeded (or logic dictates)
        if results["status_code"] is not None:
             self.logger.info("Stage 2: Starting Headless Scan (Playwright)...")
             self._run_headless(url, results, timeout)

        # Stage 3: Smart Merge (Data Preservation)
        self._restore_from_history(target, results)

        return results

    def _scan_secrets(self, content: str, results: Dict[str, Any], source: str = "Main Page"):
        """Scans HTML/JS content for known secret patterns."""
        ignored_sources = ["googletagmanager.com", "google-analytics.com", "connect.facebook.net", "static.hotjar.com", "cdn.shopify.com"]
        if any(ignored in source for ignored in ignored_sources): return

        patterns = {
            "AWS Access Key": r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)(?![A-Z]{16}\b)[A-Z0-9]{16}\b",
            "Stripe Secret Key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
            "Google API Key": r"\bAIza[0-9A-Za-z\\-_]{35}\b",
            "Slack Token": r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
            "Private Key": r"-----BEGIN PRIVATE KEY-----",
        }
        
        for name, regex in patterns.items():
            for match in re.finditer(regex, content):
                val = match.group(0)
                if any(s['value'] == val and s.get('source') == source for s in results["secrets"]): continue
                
                line_no = content.count('\n', 0, match.start()) + 1
                context = self._calculate_secret_context(content, match.start(), match.end())
                results["secrets"].append({"type": name, "value": val, "source": source, "line": line_no, "context": context.strip()})
                self.logger.warning(f"Potential Secret Found: {name} in {source} at line {line_no}")

    def _calculate_secret_context(self, content: str, start: int, end: int) -> str:
        """Calculates a few lines of context around a match."""
        s_offset = max(0, start - 100)
        e_offset = min(len(content), end + 100)
        
        l_start = content.rfind('\n', 0, start)
        if l_start != -1:
            l2 = content.rfind('\n', 0, l_start)
            s_offset = (content.rfind('\n', 0, l2) + 1) if l2 != -1 else 0
        
        l_end = content.find('\n', end)
        if l_end != -1:
            l2 = content.find('\n', l_end + 1)
            e_offset = content.find('\n', l2 + 1) if l2 != -1 else len(content)
            if e_offset == -1: e_offset = len(content)
            
        return content[s_offset:e_offset]

    def _scan_api_endpoints(self, content: str, results: Dict[str, Any], page=None):
        """Scans for API endpoints and documentation."""
        api_patterns = {
            "Swagger/OpenAPI": r"swagger\.json|openapi\.yaml|/api-docs|swagger-ui",
            "GraphQL": r"/graphql\b|query\s*\{|mutation\s*\{",
            "REST API (Versioned)": r"/api/v\d+/",
            "WSDL/SOAP": r"\.wsdl\b|\.asmx\b",
            "Health Check": r"/health\b|/actuator/health",
        }
        
        found = []
        for type_name, regex in api_patterns.items():
            if re.search(regex, content, re.IGNORECASE):
                found.append({"type": type_name, "source": "content_regex"})
                
        if page:
            self._check_links_for_api(page, api_patterns, found, results)

        results["api_endpoints"] = found

    def _check_links_for_api(self, page, api_patterns, found, results):
        """Extracts and checks page links for API indicators."""
        try:
            links = self._get_page_links(page)
            for link in links:
                self._match_link_to_api(link, api_patterns, found, results)
        except Exception as e:
            self.logger.debug(f"Failed to scan API endpoints via page links: {e}")

    def _match_link_to_api(self, link, api_patterns, found, results):
        """Checks if a single link matches any API patterns."""
        for type_name, regex in api_patterns.items():
            if re.search(regex, link, re.IGNORECASE):
                if not any(f.get('url') == link for f in found):
                    found.append({"type": type_name, "source": "link", "url": link})
                    if type_name == "Swagger/OpenAPI":
                        self._fetch_and_parse_swagger(link, results)
                return

    def _fetch_and_parse_swagger(self, url: str, results: Dict[str, Any]):
        """Attempts to download and parse a Swagger/OpenAPI Definition."""
        try:
            if any(s['url'] == url for s in results.get("api_specs", [])): return
            r = requests.get(url, timeout=5, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            if r.status_code != 200: return
            
            spec = r.json()
            if not spec or not isinstance(spec, dict): return
            if not ("swagger" in spec or "openapi" in spec): return
                
            endpoints = []
            for path, methods in spec.get("paths", {}).items():
                m_list = [m.upper() for m in methods.keys() if m.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']]
                endpoints.append({"path": path, "methods": m_list})
                
            if endpoints:
                results["api_specs"].append({
                    "url": url, "version": spec.get("info", {}).get("version", "unknown"),
                    "title": spec.get("info", {}).get("title", "Unknown API"), "endpoints": endpoints
                })
                self.logger.info(f"Parsed Swagger Spec at {url}: {len(endpoints)} endpoints found.")
        except Exception as e:
            self.logger.error(f"Swagger Parse Error: {e}")

    def _check_cve(self, product_string: str, results: Dict[str, Any]):
        """Parses product string and looks up CVEs."""
        if not self.enable_cves or not product_string or ('/' not in product_string and ' ' not in product_string): return
        
        try:
            for part in product_string.split(' '):
                self._parse_and_lookup_cve(part, results)
        except Exception as e:
            self.logger.error(f"CVE Check Error: {e}")

    def _parse_and_lookup_cve(self, part: str, results: Dict[str, Any]):
        """Parses a single product/version part."""
        if '/' not in part: return
        p_split = part.split('/')
        if len(p_split) != 2: return
        
        prod, ver = p_split[0], p_split[1].rstrip(';,()')
        if prod.lower() in ['cern-httpd', 'apache', 'nginx'] and not any(c.isdigit() for c in ver): return

        cves = lookup_cves(prod, ver)
        if cves:
            self.logger.warning(f"CVEs found for {prod} {ver}: {len(cves)}")
            existing_ids = {c['id'] for c in results["cves"]}
            for cve in cves:
                if cve['id'] not in existing_ids:
                    cve['product'] = f"{prod} {ver}"
                    results["cves"].append(cve)
                    existing_ids.add(cve['id'])

    def _detect_login_page(self, page, results, url):
        """Checks for password inputs or login-related keywords in title."""
        try:
            if page.locator("input[type='password']").count() > 0:
                results["is_login_page"] = True
                self.logger.info(f"Login Page Detected (Password Input) for {url}")
                return

            if results.get("title"):
                t_lower = results["title"].lower()
                if any(kw in t_lower for kw in ["login", "sign in", "anmeldung"]):
                    results["is_login_page"] = True
                    self.logger.info(f"Login Page Detected (Title Keyword) for {url}")
        except Exception as e:
            self.logger.error(f"Login detection failed: {e}")

    def _extract_visual_identity(self, page, results):
        """Extracts favicon and OG image URLs."""
        try:
            icon = page.locator("link[rel*='icon']").first
            if icon.count() > 0:
                results["visuals"]["favicon"] = icon.get_attribute("href")
                
            og = page.locator("meta[property='og:image']").first
            if og.count() > 0:
                results["visuals"]["og_image"] = og.get_attribute("content")
        except Exception as e:
            self.logger.debug(f"Failed to read favicon/og_image: {e}")

    def _search_sensitive_keywords(self, page, results, title_text):
        """Scans page text for sensitive keywords and directory listing indicators."""
        keywords = ["Confidential", "Internal Use Only", self.INDEX_OF_SLASH, "admin portal", "login", "dashboard"]
        try:
            page_text = page.inner_text("body").lower()
            title_lower = (title_text or "").lower()
            
            # Directory Listing Check
            if self.INDEX_OF_SLASH.lower() in title_lower or self.INDEX_OF_SLASH.lower() in page_text:
                if self.INDEX_OF_SLASH not in results["keywords_found"]:
                    results["keywords_found"].append(self.INDEX_OF_SLASH)
                if "Directory Listing Enabled" not in results["risk_hints"]:
                    results["risk_hints"].append("Directory Listing Enabled")
                
                # Add Vulnerability if not present
                if not any(v.get('id') == "MISC-DIR-LISTING" for v in results["cves"]):
                    results["cves"].append({
                        "id": "MISC-DIR-LISTING",
                        "severity": "MEDIUM", "cvss": 5.3,
                        "description": f"Directory Browsing is enabled ({self.INDEX_OF_SLASH} found).",
                        "references": ["https://cwe.mitre.org/data/definitions/548.html"],
                        "product": "Web Server Configuration"
                    })

            for kw in keywords:
                if kw.lower() in page_text and kw != self.INDEX_OF_SLASH:
                    results["keywords_found"].append(kw)
            return page_text
        except Exception as e:
            self.logger.debug(f"Keyword search failed: {e}")
            return ""

    def _fingerprint_tech_stack_complex(self, page, content, results, cookie_names):
        """Performs comprehensive fingerprinting using multiple sources."""
        try:
            script_srcs = page.locator("script[src]").evaluate_all("list => list.map(el => el.src)")
        except Exception as e:
            self.logger.debug(f"Script src evaluation failed: {e}")
            script_srcs = []

        for tech, sigs in TECH_SIGNATURES.items():
            if tech in results["tech_stack"]: continue
            if self._matches_tech_signature(tech, sigs, content, results["meta_tags"], script_srcs, cookie_names, results, results.get("http_headers")):
                results["tech_stack"].append(tech)

    def _matches_tech_signature(self, tech, sigs, content, meta_tags, script_srcs, cookie_names, results, headers=None) -> bool:
        """Checks if a technology matches any of its signatures."""
        if self._check_meta_sigs(tech, sigs.get("meta"), meta_tags, results): return True
        if self._check_content_sigs(sigs.get("html"), content): return True
        if self._check_script_sigs(sigs.get("script"), script_srcs): return True
        if self._check_cookie_sigs(sigs.get("cookies"), cookie_names): return True
        if headers and self._check_header_sigs(sigs.get("headers"), headers): return True
        return False

    def _check_meta_sigs(self, tech, meta_sigs, meta_tags, results) -> bool:
        if not meta_sigs: return False
        for m_name, m_regex in meta_sigs.items():
            val = meta_tags.get(m_name)
            if val and re.search(m_regex, val, re.IGNORECASE):
                if any(c.isdigit() for c in val):
                    self._check_cve(f"{tech} {val}", results)
                return True
        return False

    def _check_content_sigs(self, html_sigs, content) -> bool:
        return bool(html_sigs and any(re.search(r, content, re.IGNORECASE) for r in html_sigs))

    def _check_script_sigs(self, script_sigs, script_srcs) -> bool:
        return bool(script_sigs and script_srcs and any(re.search(r, src, re.IGNORECASE) for src in script_srcs for r in script_sigs))

    def _check_cookie_sigs(self, cookie_sigs, cookie_names) -> bool:
        return bool(cookie_sigs and cookie_names and any(re.search(r, c, re.IGNORECASE) for c in cookie_names for r in cookie_sigs))

    def _check_header_sigs(self, header_sigs, headers) -> bool:
        if not header_sigs or not headers: return False
        h_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        for h_name, h_regex in header_sigs.items():
            val = h_lower.get(h_name.lower())
            if val and re.search(h_regex.lower(), val): return True
        return False

    def _extract_osint_data_complex(self, page_text, links, results):
        """Extracts emails, social media profiles, documents, and phones."""
        self._extract_emails(page_text, results)
        self._extract_socials_and_docs(links, results)
        self._extract_phones(page_text, results)

    def _extract_emails(self, text: str, results: Dict[str, Any]):
        """Regex-based email extraction with exclusion logic."""
        email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ignore_ext = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.css', '.js'}
        emails = {e.lower() for e in re.findall(email_regex, text) 
                  if not any(e.lower().endswith(ext) for ext in ignore_ext)}
        results["emails"] = list(emails)

    def _extract_socials_and_docs(self, links: List[str], results: Dict[str, Any]):
        """Categorizes links into social media profiles and documents."""
        social_map = {
            "linkedin": r"linkedin\.com/(in|company)/", "twitter": r"(twitter|x)\.com/",
            "facebook": r"facebook\.com/", "instagram": r"instagram\.com/",
            "youtube": r"(youtube\.com/|youtu\.be/)", "github": r"github\.com/", "gitlab": r"gitlab\.com/"
        }
        doc_exts = {'.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.csv'}
        found_socials, found_docs = set(), set()
        
        for link in links:
            l_lower = link.lower()
            if any(re.search(regex, link, re.IGNORECASE) for regex in social_map.values()):
                found_socials.add(link)
            if any(l_lower.endswith(ext) for ext in doc_exts):
                found_docs.add(link)
        
        results["socials"], results["documents"] = list(found_socials), list(found_docs)

    def _extract_phones(self, text: str, results: Dict[str, Any]):
        """Regex-based phone number extraction."""
        phone_regex = r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
        results["phones"] = list({m.group(0).strip() for m in re.finditer(phone_regex, text)})

    def _check_broken_links_complex(self, links, target_url, results):
        """Identifies potentially hijackable broken external links."""
        from urllib.parse import urlparse
        try:
            domain = urlparse(target_url).netloc or target_url
            broken = []
            checked = set()
            for link in links:
                try:
                    parsed = urlparse(link)
                    if not parsed.netloc or parsed.netloc == domain or parsed.netloc.endswith("." + domain):
                        continue
                    if parsed.netloc in checked: continue
                    checked.add(parsed.netloc)
                    
                    try:
                        dns.resolver.resolve(parsed.netloc, 'A')
                    except dns.resolver.NXDOMAIN:
                        broken.append(link)
                    except Exception:
                        pass
                except Exception:
                    pass
            results["broken_links"] = broken
        except Exception as e:
            self.logger.debug(f"Broken link check failed: {e}")

    def _run_headless(self, url: str, results: Dict[str, Any], timeout: int = 30):
        """Simplified entry point for headless analysis."""
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"])
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_extra_http_headers({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 YADS/1.19"})
                
                try:
                    self.limiter.wait(url.split("//")[-1].split("/")[0])
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
                except Exception as e:
                    results["headless_error_goto"] = str(e)
                
                self._run_page_analysis_pipeline(page, context, url, results)
                browser.close()
        except Exception as e:
            self.logger.error(f"Headless analysis failed for {url}: {e}")
            results["headless_error"] = str(e)

    def _run_page_analysis_pipeline(self, page, context, url, results):
        """Orchestrates different analysis modules on the loaded page."""
        content = page.content()
        results["title"] = page.title()
        
        self._deep_page_analysis(page, url, results, content)
        self._risk_and_osint_analysis(page, context, url, results, content)
        self._capture_screenshot(page, url, results)
        
        if page.url != url and page.url not in results["redirect_chain"]:
            results["redirect_chain"].append(page.url)

    def _deep_page_analysis(self, page, url, results, content):
        """Runs deep content-based analysis like secrets, APIs and JS scanning."""
        self._scan_secrets(content, results, source="Main HTML")
        self._scan_api_endpoints(content, results, page)
        self._scan_js_files(page, url, results)
        self._detect_login_page(page, results, url)
        self._extract_page_metadata(page, results)

    def _risk_and_osint_analysis(self, page, context, url, results, content):
        """Analyzes tech stack, OSINT data and potential risks."""
        p_text = self._search_sensitive_keywords(page, results, results["title"])
        cookies = [c["name"] for c in context.cookies()]
        self._fingerprint_tech_stack_complex(page, content, results, cookies)
        
        links = self._get_page_links(page)
        self._extract_osint_data_complex(p_text, links, results)
        self._check_broken_links_complex(links, url, results)

    def _get_page_links(self, page) -> List[str]:
        try: return page.locator("a").evaluate_all("list => list.map(el => el.href)")
        except Exception: return []

    def _capture_screenshot(self, page, url, results):
        import os, uuid
        f_name = f"screenshot_{self.compute_hash({'u':url})}_{uuid.uuid4()}.png"
        s_dir = "yads/api/static/screenshots"
        os.makedirs(s_dir, exist_ok=True)
        try:
            page.screenshot(path=f"{s_dir}/{f_name}")
            results["screenshot_path"] = f_name
        except Exception: pass

    def _check_connectivity_and_headers(self, target: str, timeout: int, target_id: Optional[int], results: Dict[str, Any]) -> str:
        """Stage 1: Checks HTTP/HTTPS connectivity and extracts header signatures."""
        self.logger.info(f"Stage 1: Connectivity Check for {target}")
        self.limiter.wait(target)
        self._check_http_vitals(target, timeout, target_id, results)
        self._check_https_vitals_and_headers(target, timeout, target_id, results)
        return f"https://{target}" if results["https_status"] > 0 else f"http://{target}"

    def _check_http_vitals(self, target: str, timeout: int, target_id: Optional[int], results: Dict[str, Any]):
        """Checks basic HTTP connectivity."""
        try:
            req_start = time.time()
            r = requests.get(f"http://{target}", timeout=timeout, allow_redirects=False, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            results["http_status"] = r.status_code
            if self.db and target_id: self._log_traffic(target_id, r, req_start)
            if r.is_redirect and r.headers.get("Location", "").startswith("https"): results["https_redirect"] = True
            if r.status_code == 401: results["is_login_page"] = True
        except Exception:
            results["http_status"] = 0

    def _check_https_vitals_and_headers(self, target: str, timeout: int, target_id: Optional[int], results: Dict[str, Any]):
        """Checks HTTPS and analyzes response headers."""
        try:
            req_start = time.time()
            r = requests.get(f"https://{target}", timeout=timeout, allow_redirects=True, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            results["https_status"] = r.status_code
            if self.db and target_id: self._log_traffic(target_id, r, req_start)
            results.update({"http_headers": dict(r.headers), "redirect_chain": [res.url for res in r.history] + [r.url], "status_code": r.status_code})
            self._fingerprint_headers(r.headers, results)
        except requests.RequestException as e:
            results["https_status"] = 0
            if results["http_status"] == 0: results["error"] = f"Both HTTP/HTTPS failed: {e}"
            else: results["status_code"] = results["http_status"]

    def _fingerprint_headers(self, headers, results):
        """Extracts technology information from headers."""
        for tech, sigs in TECH_SIGNATURES.items():
            if "headers" not in sigs: continue
            for h_name, regex in sigs["headers"].items():
                val = headers.get(h_name) or headers.get(h_name.lower())
                if val and re.search(regex, val, re.IGNORECASE):
                    self._add_detected_tech(tech, val, results)
                    return

    def _add_detected_tech(self, tech, val, results):
        if tech in results["tech_stack"]: return
        results["tech_stack"].append(tech)
        if any(c.isdigit() for c in val) and len(val) < 50:
            self._check_cve(f"{tech} {val}", results)

    def _log_traffic(self, target_id: int, resp: requests.Response, start_time: float):
        """Utility to log HTTP traffic."""
        try:
            self.db.add(HTTPTraffic(
                target_id=target_id, method="GET", url=resp.url, status_code=resp.status_code,
                request_headers=redact_headers(dict(resp.request.headers)), 
                response_headers=redact_headers(dict(resp.headers)),
                response_body_snippet=resp.text[:1024] if resp.text else "",
                duration=round(time.time() - start_time, 3)
            ))
            self.db.commit()
        except Exception as e:
            self.logger.debug(f"Traffic logging failed: {e}")

    def _restore_from_history(self, target: str, results: Dict[str, Any]):
        """Stage 3: Restore technology details from history if scan fails."""
        if results["tech_stack"] or not self.db: return
        try:
            prev_result = self._fetch_history_objects(target)
            if prev_result and prev_result.data:
                if "tech_stack" in prev_result.data and prev_result.data["tech_stack"]:
                    results["tech_stack"] = prev_result.data["tech_stack"]
                    results["risk_hints"].append("Cached technologies used (Scan failed)")
                if not results.get("title") and prev_result.data.get("title"):
                    results["title"] = prev_result.data.get("title")
        except Exception as e:
            self.logger.error(f"History restore failed: {e}")

    def _fetch_history_objects(self, target: str):
        """Helper to fetch the latest past results from DB."""
        from yads.models import Target, ScanResult
        from sqlmodel import select
        t_obj = self.db.exec(select(Target).where(Target.domain == target)).first()
        if not t_obj: return None
        return self.db.exec(select(ScanResult).where(
            ScanResult.target_id == t_obj.id, ScanResult.module_name == self.module_name
        ).order_by(ScanResult.scanned_at.desc())).first()

    def _extract_page_metadata(self, page, results: Dict[str, Any]):
        """Extracts meta tags and visual identity from the page."""
        self._extract_visual_identity(page, results)
        try:
            for m in page.locator("meta").all():
                name, c = m.get_attribute("name"), m.get_attribute("content")
                if name and c: results["meta_tags"][name] = c
        except Exception: pass

    def _scan_js_files(self, page, base_url: str, results: Dict[str, Any]):
        """Fetches and statically analyzes referenced JS files for sinks and routes."""
        try:
            scripts = self._get_script_sources(page)
            sinks = {
                "Dangerous Sink (innerHTML)": r"\.innerHTML\s*=", "Dangerous Sink (outerHTML)": r"\.outerHTML\s*=",
                "Dangerous Sink (document.write)": r"document\.write\(", "Dangerous Func (eval)": r"\beval\(",
                "Dangerous Sink (location assignment)": r"location\.(href|search)\s*=", "Open Redirect Potential": r"window\.location\s*="
            }
            route_pattern = r"['\"](\/api\/[\w\-\/]+|\/v\d\/[\w\-\/]+|\/graphql|\/admin\/[\w\-\/]+)['\"]"
            
            from urllib.parse import urlparse
            base_domain = urlparse(base_url).netloc
            analyzed_count = 0
            for src in scripts:
                if analyzed_count >= 10: break
                src_domain = urlparse(src).netloc
                if (base_domain not in src_domain and "cdn" in src_domain) or src in results["js_analysis"]["files_analyzed"]: continue
                
                if self._process_single_js_file(src, results, sinks, route_pattern):
                    analyzed_count += 1
        except Exception as e:
            self.logger.debug(f"JS file scanning failed: {e}")

    def _get_script_sources(self, page) -> List[str]:
        try: return page.locator("script[src]").evaluate_all("list => list.map(el => el.src)")
        except Exception: return []

    def _process_single_js_file(self, src: str, results: Dict[str, Any], sinks: Dict[str, str], route_pattern: str) -> bool:
        """Analyzes a single JS file for vulnerabilities and routes."""
        try:
            r = requests.get(src, timeout=5, verify=False)  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
            if r.status_code != 200: return False
            content = r.text
            results["js_analysis"]["files_analyzed"].append(src)
            self._scan_secrets(content, results, source=src)
            self._check_js_vulnerabilities(src, content, results, sinks)
            self._detect_js_routes(src, content, results, route_pattern)
            return True
        except Exception: return False

    def _check_js_vulnerabilities(self, file_url, content, results, sinks):
        for name, regex in sinks.items():
            if re.search(regex, content):
                results["js_analysis"]["findings"].append({"file": file_url, "type": "sink", "name": name, "severity": "medium", "details": f"Found pattern: {regex}"})

    def _detect_js_routes(self, file_url, content, results, route_pattern):
        for m in re.finditer(route_pattern, content):
            route = m.group(1)
            if not any(f.get('route') == route for f in results["js_analysis"]["findings"]):
                results["js_analysis"]["findings"].append({"file": file_url, "type": "route", "name": "Hidden API Route", "severity": "info", "route": route, "details": f"Discovered endpoint: {route}"})
