"""
External Resources Scanner (Task #14 extension + new)

Analyzes what external resources a page loads and from where:
- Third-party JavaScript from external domains (supply chain risk)
- External CSS stylesheets
- External fonts (Google Fonts, Typekit, etc.)
- External iframes
- Mixed content (HTTP resources on HTTPS pages)
- Resources from flagged/CDN domains with known risks
- Open redirect checks in outbound links

For each external origin, assesses:
- Is this a known CDN/legitimate service? (low risk)
- Is this an unusual/unknown domain? (medium risk)
- Is this loading from a resource-heavy/tracking domain? (info)
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10

# Known legitimate CDN and service domains (low risk)
TRUSTED_ORIGINS = {
    # CDNs
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "code.jquery.com", "ajax.googleapis.com", "ajax.aspnetcdn.com",
    "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "cdn.bootcss.com", "cdn.staticfile.org",
    # Fonts
    "fonts.googleapis.com", "fonts.gstatic.com",
    "use.typekit.net", "kit.fontawesome.com",
    "use.fontawesome.com", "pro.fontawesome.com",
    # Analytics / Monitoring (medium risk — loads 3rd party JS)
    "www.google-analytics.com", "www.googletagmanager.com",
    "connect.facebook.net", "platform.twitter.com",
    "www.youtube.com", "player.vimeo.com",
    "snap.licdn.com", "assets.pinterest.com",
    # Chat / Support
    "widget.intercom.io", "js.hs-scripts.com", "js.hsadspixel.net",
    "js.usemessages.com", "js.hsleadflows.net",
    # Payments
    "js.stripe.com", "checkout.stripe.com", "www.paypal.com",
    # Maps
    "maps.googleapis.com", "maps.gstatic.com", "api.mapbox.com",
    # Monitoring
    "browser.sentry-cdn.com", "js.newrelic.com",
    # Microsoft
    "ajax.aspnetcdn.com", "az416426.vo.msecnd.net",
}

# High-risk or suspicious origin patterns
SUSPICIOUS_PATTERNS = [
    (r"\.ru$", "high", "Russian TLD (.ru) — verify legitimacy"),
    (r"\.cn$", "medium", "Chinese TLD (.cn) — verify legitimacy"),
    (r"\.tk$", "high", "Free TLD (.tk) — commonly used in malware"),
    (r"\.xyz$", "medium", "Common spam TLD (.xyz)"),
    (r"\.top$", "medium", "Common spam TLD (.top)"),
    (r"bit\.ly|t\.co|tinyurl\.com|goo\.gl", "medium", "URL shortener used for resource loading"),
    (r"pastebin\.com|hastebin\.com", "critical", "Pastebin as script source — common malware pattern"),
    (r"raw\.github(?:usercontent)?\.com", "high", "Raw GitHub as script source — version pinning risk"),
    (r"cdn\d+\.", "low", "Numbered CDN subdomain — verify"),
]

_SUSPICIOUS = [(re.compile(p, re.IGNORECASE), sev, msg) for p, sev, msg in SUSPICIOUS_PATTERNS]

# Open redirect parameter patterns
REDIRECT_PARAMS = re.compile(
    r'[?&](?:redirect|redirect_to|next|url|return|returnUrl|goto|forward|target|link|dest|destination|redirect_uri)=',
    re.IGNORECASE
)


class ExternalResourcesScanner(BaseScannerModule):
    """Analyze external resources loaded by target pages."""

    @property
    def module_name(self) -> str:
        return "external_resources"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = target.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

        result: Dict[str, Any] = {
            "domain": domain,
            "external_scripts": [],
            "external_styles": [],
            "external_iframes": [],
            "external_images": [],
            "mixed_content": [],
            "open_redirect_candidates": [],
            "origins_summary": {},
            "findings": [],
            "summary": {
                "score": 100,
                "external_script_count": 0,
                "unique_origins": 0,
                "risky_origins": 0,
            },
        }

        base_url = self._get_base_url(domain)
        if not base_url:
            result["error"] = "Domain not reachable"
            return result

        is_https = base_url.startswith("https://")
        html = self._fetch_html(base_url)
        if not html:
            result["error"] = "Could not fetch page HTML"
            return result

        # Collect external resources
        scripts = self._extract_resources(html, base_url, domain, "script", "src")
        styles = self._extract_resources(html, base_url, domain, "link", "href", filter_rel="stylesheet")
        iframes = self._extract_resources(html, base_url, domain, "iframe", "src")
        images = self._extract_resources(html, base_url, domain, "img", "src")

        result["external_scripts"] = scripts
        result["external_styles"] = styles
        result["external_iframes"] = iframes

        # Mixed content check
        if is_https:
            all_resources = scripts + styles + iframes + images
            mixed = [r for r in all_resources if r.get("url", "").startswith("http://")]
            result["mixed_content"] = mixed
            if mixed:
                result["findings"].append({
                    "severity": "high",
                    "title": f"Mixed content: {len(mixed)} HTTP resource(s) on HTTPS page",
                    "detail": f"HTTP resources on HTTPS pages can be intercepted. Examples: {', '.join(m['url'][:60] for m in mixed[:3])}",
                    "category": "mixed_content",
                })

        # Open redirect candidates in outbound links
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for link in links:
            if REDIRECT_PARAMS.search(link):
                result["open_redirect_candidates"].append(link[:200])

        if result["open_redirect_candidates"]:
            result["findings"].append({
                "severity": "medium",
                "title": f"Open redirect parameter(s) detected in {len(result['open_redirect_candidates'])} URL(s)",
                "detail": f"URLs with redirect parameters may enable phishing. Check: {result['open_redirect_candidates'][0][:100]}",
                "category": "open_redirect",
            })

        # Analyze origins
        all_origins: Dict[str, Dict] = {}
        for resource_type, resources in [("script", scripts), ("style", styles), ("iframe", iframes)]:
            for r in resources:
                origin = r.get("origin", "")
                if not origin:
                    continue
                if origin not in all_origins:
                    all_origins[origin] = {
                        "domain": origin,
                        "resource_types": [],
                        "trusted": origin in TRUSTED_ORIGINS or any(t in origin for t in TRUSTED_ORIGINS),
                        "urls": [],
                    }
                all_origins[origin]["resource_types"].append(resource_type)
                all_origins[origin]["urls"].append(r["url"][:100])

        result["origins_summary"] = all_origins
        result["summary"]["unique_origins"] = len(all_origins)

        # Script from untrusted/unknown origins
        risky = 0
        for origin, info in all_origins.items():
            if "script" not in info["resource_types"]:
                continue
            if info["trusted"]:
                continue

            # Check suspicious patterns
            sev = "medium"
            detail = f"Unknown origin loading JS: {origin}"
            for regex, pat_sev, pat_msg in _SUSPICIOUS:
                if regex.search(origin):
                    sev = pat_sev
                    detail = f"{origin} — {pat_msg}"
                    break

            risky += 1
            result["findings"].append({
                "severity": sev,
                "title": f"External JS from unrecognized origin: {origin}",
                "detail": detail,
                "category": "external_script",
                "origin": origin,
            })

        # Iframe from external origin (clickjacking risk, data exfil)
        for r in iframes:
            origin = r.get("origin", "")
            if origin and not any(t in origin for t in TRUSTED_ORIGINS):
                result["findings"].append({
                    "severity": "medium",
                    "title": f"External iframe loaded from: {origin}",
                    "detail": f"Iframes from external domains may pose security risks. URL: {r['url'][:100]}",
                    "category": "external_iframe",
                    "origin": origin,
                })

        result["summary"]["risky_origins"] = risky
        result["summary"]["external_script_count"] = len(scripts)

        # Score
        score = 100
        for f in result["findings"]:
            if f["severity"] == "critical":
                score -= 20
            elif f["severity"] == "high":
                score -= 12
            elif f["severity"] == "medium":
                score -= 6
            elif f["severity"] == "low":
                score -= 2
        result["summary"]["score"] = max(0, score)

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

    def _fetch_html(self, url: str) -> Optional[str]:
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
            )
            return resp.text[:500_000]
        except Exception:
            return None

    def _extract_resources(
        self, html: str, base_url: str, own_domain: str, tag: str, attr: str, filter_rel: Optional[str] = None
    ) -> List[Dict]:
        """Extract external resource URLs from HTML tags."""
        results = []
        seen: Set[str] = set()

        if filter_rel:
            # Match <link rel="stylesheet" href="..."> specifically
            pattern = rf'<{tag}[^>]+rel=["\'][^"\']*{filter_rel}[^"\']*["\'][^>]+{attr}=["\']([^"\']+)["\']|<{tag}[^>]+{attr}=["\']([^"\']+)["\'][^>]+rel=["\'][^"\']*{filter_rel}[^"\']*["\']'
        else:
            pattern = rf'<{tag}[^>]+{attr}=["\']([^"\']+)["\']'

        for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            url = match.group(1) or (match.group(2) if match.lastindex and match.lastindex >= 2 else "")
            if not url or url.startswith("data:") or url.startswith("#"):
                continue

            # Resolve URL
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/") or not url.startswith("http"):
                continue  # Internal resource

            parsed = urlparse(url)
            origin = parsed.netloc.lower()

            # Skip own domain
            if own_domain in origin:
                continue
            if url in seen:
                continue
            seen.add(url)

            results.append({
                "url": url,
                "origin": origin,
                "tag": tag,
            })

        return results
