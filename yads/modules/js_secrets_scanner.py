"""
JavaScript Secrets & Endpoints Scanner (Task #3)

Discovers JS files from target pages and scans for:
- Hardcoded API keys and tokens (AWS, Google, Stripe, Slack, etc.)
- Internal API endpoints (/api/v1/..., /internal/...)
- S3 bucket URLs, cloud storage references
- Private IP addresses (internal endpoints)
- Suspicious comments (TODO, FIXME with credentials)

Approach: crawl HTML for <script src> tags, fetch JS files, regex scan.
No external APIs required — pure HTTP + regex.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10

# (pattern_name, regex, severity, description)
SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    # AWS
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "critical", "AWS Access Key ID"),
    ("aws_secret_key", r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})", "critical", "AWS Secret Access Key"),
    # Google
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", "high", "Google API Key"),
    ("google_oauth_id", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "medium", "Google OAuth Client ID"),
    # Stripe
    ("stripe_live_key", r"sk_live_[0-9a-zA-Z]{24,}", "critical", "Stripe Live Secret Key"),
    ("stripe_pub_key", r"pk_live_[0-9a-zA-Z]{24,}", "medium", "Stripe Live Publishable Key"),
    ("stripe_test_key", r"sk_test_[0-9a-zA-Z]{24,}", "low", "Stripe Test Secret Key"),
    # Slack
    ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", "high", "Slack Token"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "high", "Slack Webhook URL"),
    # GitHub
    ("github_token", r"ghp_[A-Za-z0-9]{36}", "critical", "GitHub Personal Access Token"),
    ("github_app_token", r"ghs_[A-Za-z0-9]{36}", "critical", "GitHub App Token"),
    # General patterns
    ("jwt_token", r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "high", "JWT Token (hardcoded)"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "critical", "Private Key"),
    ("password_in_js", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "high", "Hardcoded password"),
    ("api_key_generic", r"(?i)(?:api[_\-]?key|apikey|api_token|access[_\-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "high", "Generic API Key"),
    ("bearer_token", r"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})", "medium", "Bearer token (possible hardcode)"),
    # Database / connection strings
    ("db_connection", r"(?i)(?:mongodb|postgres|postgresql|mysql|mssql|redis)://[^\s'\"<>]+", "critical", "Database connection string"),
    # Cloud
    ("aws_s3_url", r"https://[a-z0-9\-\.]+\.s3\.amazonaws\.com", "low", "AWS S3 bucket URL"),
    ("azure_blob", r"https://[a-z0-9]+\.blob\.core\.windows\.net", "low", "Azure Blob Storage URL"),
    # Internal IPs
    ("private_ip", r"(?:^|[^0-9])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)", "medium", "Private IP address (internal endpoint?)"),
    # Sendgrid
    ("sendgrid_key", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "critical", "SendGrid API Key"),
    # Twilio
    ("twilio_sid", r"AC[a-zA-Z0-9]{32}", "high", "Twilio Account SID"),
    ("twilio_token", r"SK[a-zA-Z0-9]{32}", "high", "Twilio Auth Token"),
    # Firebase
    ("firebase_key", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}", "high", "Firebase Server Key"),
    # Mapbox
    ("mapbox_token", r"pk\.eyJ1IjoiW[A-Za-z0-9_\-\.]+", "medium", "Mapbox Token"),
    # Braintree
    ("braintree_key", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "critical", "Braintree Access Token"),
]

# API endpoint patterns to extract
ENDPOINT_PATTERNS = [
    r"""(?:fetch|axios|ajax|get|post|put|delete|request)\s*\(?['\"](/api/[^\s'\"<>]+)['\"]""",
    r"""(?:url|endpoint|baseURL|BASE_URL)\s*[:=]\s*['\"]([^'\"]+/api/[^\s'\"]+)['\"]""",
    r"""['\"](/[a-z0-9_\-/]+/v[0-9]+/[a-z0-9_\-/]+)['\"]""",
    r"""['\"](/api/[a-z0-9_\-/]+)['\"]""",
    r"""['\"](/internal/[a-z0-9_\-/]+)['\"]""",
    r"""['\"](/admin/[a-z0-9_\-/]+)['\"]""",
    r"""['\"](/graphql)['\"]""",
]

_COMPILED_SECRETS = [(name, re.compile(pat), sev, desc) for name, pat, sev, desc in SECRET_PATTERNS]
_COMPILED_ENDPOINTS = [re.compile(pat, re.IGNORECASE) for pat in ENDPOINT_PATTERNS]

# Scoped npm package references in require()/import statements — feeds
# dependency_confusion.py's continuous monitoring (#31).
PACKAGE_IMPORT_PATTERNS = [
    r"""require\(\s*['\"](@[a-z0-9][a-z0-9\-_.]*\/[a-z0-9][a-z0-9\-_.]*)['\"]\s*\)""",
    r"""from\s+['\"](@[a-z0-9][a-z0-9\-_.]*\/[a-z0-9][a-z0-9\-_.]*)['\"]""",
    r"""import\s*\(\s*['\"](@[a-z0-9][a-z0-9\-_.]*\/[a-z0-9][a-z0-9\-_.]*)['\"]\s*\)""",
]
_COMPILED_PACKAGE_IMPORTS = [re.compile(pat, re.IGNORECASE) for pat in PACKAGE_IMPORT_PATTERNS]


class JsSecretsScanner(BaseScannerModule):
    """Fetch and analyze JavaScript files for hardcoded secrets and internal endpoints."""

    MAX_JS_FILES = 30
    MAX_JS_SIZE = 500_000  # 500 KB per file

    @property
    def module_name(self) -> str:
        return "js_secrets"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        result: Dict[str, Any] = {
            "domain": domain,
            "js_files_found": [],
            "js_files_scanned": 0,
            "secrets": [],
            "endpoints": [],
            "findings": [],
            "summary": {
                "score": 100,
                "secret_count": 0,
                "endpoint_count": 0,
            },
        }

        base_url = self._get_base_url(domain)
        if not base_url:
            result["error"] = "Domain not reachable"
            return result

        # 1. Collect JS file URLs from the main page
        js_urls = self._collect_js_urls(base_url, domain)
        result["js_files_found"] = js_urls[:self.MAX_JS_FILES]

        if not js_urls:
            return result

        # 2. Scan each JS file
        all_secrets: List[Dict] = []
        all_endpoints: Set[str] = set()
        all_packages: Set[str] = set()
        scanned = 0

        for js_url in js_urls[:self.MAX_JS_FILES]:
            content = self._fetch_js(js_url)
            if not content:
                continue
            scanned += 1

            secrets = self._scan_secrets(content, js_url)
            all_secrets.extend(secrets)

            endpoints = self._extract_endpoints(content)
            all_endpoints.update(endpoints)

            all_packages.update(self._extract_package_names(content))

        result["js_files_scanned"] = scanned
        result["secrets"] = all_secrets
        result["endpoints"] = sorted(all_endpoints)[:100]
        # Feeds dependency_confusion.py's continuous package monitoring (#31):
        # scoped/internal-looking import identifiers found in bundled JS.
        result["discovered_packages"] = sorted(all_packages)

        # 3. Build findings
        for secret in all_secrets:
            result["findings"].append({
                "severity": secret["severity"],
                "title": f"{secret['description']} in {secret['filename']}",
                "detail": f"Pattern: {secret['pattern_name']} — Match: {secret['match'][:60]}...",
                "url": secret["url"],
                "category": "secret",
            })

        # Score
        score = 100
        for f in result["findings"]:
            if f["severity"] == "critical":
                score -= 20
            elif f["severity"] == "high":
                score -= 12
            elif f["severity"] == "medium":
                score -= 6
            else:
                score -= 2

        result["summary"]["score"] = max(0, score)
        result["summary"]["secret_count"] = len(all_secrets)
        result["summary"]["endpoint_count"] = len(all_endpoints)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_base_url(self, domain: str) -> Optional[str]:
        for scheme in ("https", "http"):
            try:
                resp = requests.head(
                    f"{scheme}://{domain}",
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
                )
                if resp.status_code < 500:
                    return f"{scheme}://{domain}"
            except Exception:
                continue
        return None

    def _collect_js_urls(self, base_url: str, domain: str) -> List[str]:
        """Parse HTML and collect <script src> URLs."""
        try:
            resp = requests.get(
                base_url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
            )
            html = resp.text

            # Find all script src attributes
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            js_urls = []
            for src in script_srcs:
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    src = base_url.rstrip("/") + src
                elif not src.startswith("http"):
                    src = base_url.rstrip("/") + "/" + src

                # Only include JS from same domain or CDNs likely to host app code
                parsed = urlparse(src)
                if domain in parsed.netloc or any(cdn in parsed.netloc for cdn in [
                    "cdn.", "static.", "assets.", "js."
                ]):
                    js_urls.append(src)

            return js_urls
        except Exception as e:
            logger.debug(f"[JsSecrets] HTML fetch failed: {e}")
            return []

    def _fetch_js(self, url: str) -> Optional[str]:
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                stream=True,
                headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
            )
            if resp.status_code != 200:
                return None
            content = resp.content[:self.MAX_JS_SIZE]
            return content.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _scan_secrets(self, content: str, url: str) -> List[Dict]:
        findings = []
        filename = urlparse(url).path.split("/")[-1] or "inline"
        seen_matches: Set[str] = set()

        for pattern_name, regex, severity, description in _COMPILED_SECRETS:
            for match in regex.finditer(content):
                match_str = match.group(0)[:80]
                dedup_key = f"{pattern_name}:{match_str[:30]}"
                if dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                # Get context (surrounding line)
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace("\n", " ").strip()

                findings.append({
                    "pattern_name": pattern_name,
                    "description": description,
                    "severity": severity,
                    "match": match_str,
                    "context": context[:150],
                    "url": url,
                    "filename": filename,
                })

        return findings

    def _extract_endpoints(self, content: str) -> Set[str]:
        endpoints = set()
        for regex in _COMPILED_ENDPOINTS:
            for match in regex.finditer(content):
                ep = match.group(1) if match.lastindex else match.group(0)
                if len(ep) > 3 and len(ep) < 200:
                    endpoints.add(ep)
        return endpoints

    def _extract_package_names(self, content: str) -> Set[str]:
        """
        Extract scoped npm-style package identifiers referenced via
        require()/import from bundled JS — e.g. `require("@acme/auth-utils")`
        or `from "@acme/logger"`. Only scoped packages (@org/name) are kept:
        they're the ones registrable under someone else's org on the public
        npm registry if the "acme" org name isn't claimed there, which is
        exactly what dependency_confusion.py checks for.
        """
        packages: Set[str] = set()
        for regex in _COMPILED_PACKAGE_IMPORTS:
            for match in regex.finditer(content):
                pkg = match.group(1)
                if pkg and len(pkg) < 100:
                    packages.add(pkg)
        return packages
