"""
Privacy / DSGVO (GDPR) Compliance Scanner

Scans a target's main page for signs of GDPR/DSGVO compliance:
- Cookie Consent Management Platform (CMP) detection
- Tracking pixels & analytics scripts loaded without consent gate
- Privacy policy page link
- Third-party data processors (Google, Meta, LinkedIn, etc.)
- Cross-border data transfers via external CDN/font loading
- Google Fonts (CJEU-relevant: IP address transmitted to US)

Severity mapping:
- No CMP but tracking present → high
- No privacy policy link → medium
- Google Fonts without local hosting → medium
- External processors found → info
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15

# ------------------------------------------------------------------
# CMP Signatures (script src patterns, cookie names, HTML markers)
# ------------------------------------------------------------------
CMP_SIGNATURES = {
    "OneTrust": [
        "onetrust", "OptanonConsent", "otBannerSdk", "cookielaw.org/consent",
    ],
    "Cookiebot": [
        "cookiebot", "CookieConsent", "consent.cookiebot.com",
    ],
    "Usercentrics": [
        "usercentrics", "uc-corner", "app.usercentrics.eu",
    ],
    "TrustArc": [
        "truste.com", "trustarc", "consent.trustarc",
    ],
    "CookieYes": [
        "cookieyes", "cky-consent", "app.cookieyes.com",
    ],
    "Borlabs Cookie": [
        "borlabs-cookie", "BorlabsCookie",
    ],
    "Consentmanager": [
        "consentmanager.net", "cmp-block", "__cmpapi",
    ],
    "Klaro": [
        "klaro.js", "klaro-cookie-notice",
    ],
    "Didomi": [
        "didomi.io", "didomiOnReady",
    ],
    "GDPR Cookie Consent (WP)": [
        "gdpr-cookie-consent", "wt3_eprivacy",
    ],
    "Osano": [
        "osano.com", "osano-cm-",
    ],
}

# ------------------------------------------------------------------
# Tracking Scripts (loaded before or without CMP)
# ------------------------------------------------------------------
TRACKING_SCRIPTS = {
    "Google Analytics (UA/GA4)": [
        "google-analytics.com/analytics.js",
        "google-analytics.com/ga.js",
        "googletagmanager.com/gtm.js",
        "googletagmanager.com/gtag/js",
    ],
    "Facebook Pixel": [
        "connect.facebook.net/en_US/fbevents.js",
        "facebook.com/tr",
        "fbq(",
    ],
    "LinkedIn Insight Tag": [
        "snap.licdn.com/li.lms-analytics",
        "_linkedin_partner_id",
    ],
    "Hotjar": [
        "static.hotjar.com",
        "hotjar-",
    ],
    "Microsoft Clarity": [
        "clarity.ms/tag",
        "microsoft.com/clarity",
    ],
    "Matomo/Piwik": [
        "matomo.js",
        "piwik.js",
        "_paq.push",
    ],
    "Mixpanel": [
        "cdn.mxpnl.com",
        "mixpanel.com/libs",
    ],
    "Segment": [
        "cdn.segment.com",
        "analytics.js",
    ],
    "Twitter Pixel": [
        "static.ads-twitter.com",
        "t.co/i/adsct",
    ],
    "TikTok Pixel": [
        "analytics.tiktok.com",
        "ttq.load(",
    ],
}

# Third-party domains that constitute data processor relationships
KNOWN_PROCESSORS = {
    "Google": ["google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
               "google-analytics.com", "doubleclick.net"],
    "Meta/Facebook": ["facebook.com", "facebook.net", "fbcdn.net", "instagram.com"],
    "Microsoft": ["microsoft.com", "msecnd.net", "clarity.ms", "bing.com"],
    "Amazon/AWS": ["amazonaws.com", "cloudfront.net", "amazon.com"],
    "LinkedIn": ["linkedin.com", "licdn.com"],
    "Twitter/X": ["twitter.com", "twimg.com", "t.co"],
    "Hotjar": ["hotjar.com"],
    "Stripe": ["stripe.com", "stripe.network"],
    "Intercom": ["intercom.io", "intercomcdn.com"],
    "HubSpot": ["hubspot.com", "hs-scripts.com", "hsforms.com"],
    "Salesforce": ["salesforce.com", "force.com"],
    "Zendesk": ["zendesk.com", "zdassets.com"],
    "Cloudflare": ["cloudflare.com", "cloudflare.net", "cloudflareinsights.com"],
}

GOOGLE_FONTS_PATTERNS = [
    "fonts.googleapis.com",
    "fonts.gstatic.com",
]

PRIVACY_POLICY_PATTERNS = re.compile(
    r"(privacy|datenschutz|privatsph[äa]re|cookie.policy)",
    re.IGNORECASE,
)
# Impressum/legal-notice is a separate legal requirement from the GDPR privacy
# notice above (German TMG/DDG §5 vs. GDPR Art. 13/14) -- tracked as its own
# signal rather than folded into "privacy policy found".
IMPRESSUM_PATTERNS = re.compile(
    r"(impressum|legal.notice|rechtliches)",
    re.IGNORECASE,
)


class DsgvoScanner(BaseScannerModule):
    """GDPR/DSGVO compliance indicator scanner."""

    @property
    def module_name(self) -> str:
        return "dsgvo_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
        )

        result: Dict[str, Any] = {
            "domain": domain,
            "cmp_detected": None,
            "tracking_without_cmp": [],
            "processors": [],
            "google_fonts": False,
            "privacy_policy_found": False,
            "privacy_policy_url": None,
            "impressum_found": False,
            "impressum_url": None,
            "findings": [],
            "summary": {
                "score": 100,
                "cmp": None,
                "tracking_count": 0,
                "processor_count": 0,
                "findings_count": 0,
            },
        }

        html = self._fetch_page(domain)
        if not html:
            result["error"] = "Could not fetch page"
            return result

        html_lower = html.lower()

        # 1. CMP Detection
        cmp_name = self._detect_cmp(html, html_lower)
        result["cmp_detected"] = cmp_name
        result["summary"]["cmp"] = cmp_name

        # 2. Tracking scripts
        tracking_found = self._detect_tracking(html, html_lower)
        result["tracking_without_cmp"] = tracking_found

        # 3. Privacy policy link
        pp_url = self._find_privacy_policy(html, domain)
        result["privacy_policy_found"] = pp_url is not None
        result["privacy_policy_url"] = pp_url

        # 3b. Impressum / legal notice link (separate legal basis from GDPR privacy policy)
        imp_url = self._find_impressum(html, domain)
        result["impressum_found"] = imp_url is not None
        result["impressum_url"] = imp_url

        # 4. Third-party processors
        processors = self._detect_processors(html, html_lower)
        result["processors"] = processors

        # 5. Google Fonts
        google_fonts = any(p in html_lower for p in GOOGLE_FONTS_PATTERNS)
        result["google_fonts"] = google_fonts

        # ------------------------------------------------------------------
        # Generate findings
        # ------------------------------------------------------------------

        # Tracking without CMP = biggest issue
        if tracking_found and not cmp_name:
            for tracker in tracking_found:
                result["findings"].append({
                    "severity": "high",
                    "title": f"Tracking without consent: {tracker}",
                    "detail": (
                        f"{tracker} is loaded on the page but no Cookie Consent "
                        f"Management Platform (CMP) was detected. Personal data "
                        f"(IP addresses) is transmitted without prior user consent, "
                        f"violating GDPR Art. 6."
                    ),
                    "category": "tracking_no_cmp",
                })
        elif tracking_found and cmp_name:
            # CMP present but may not block pre-consent load
            for tracker in tracking_found:
                result["findings"].append({
                    "severity": "medium",
                    "title": f"Verify pre-consent blocking: {tracker}",
                    "detail": (
                        f"{tracker} detected. CMP ({cmp_name}) present — "
                        f"verify that script is blocked until consent is given."
                    ),
                    "category": "tracking_verify_cmp",
                })

        if not result["privacy_policy_found"]:
            result["findings"].append({
                "severity": "medium",
                "title": "No privacy policy link found",
                "detail": (
                    "No link to a privacy policy, Datenschutzerklärung, or imprint "
                    "was found on the main page. GDPR Art. 13/14 requires a "
                    "publicly accessible privacy notice."
                ),
                "category": "no_privacy_policy",
            })

        if not result["impressum_found"]:
            result["findings"].append({
                "severity": "medium",
                "title": "No Impressum / legal notice found",
                "detail": (
                    "No link to an Impressum or legal notice was found on the main "
                    "page. German TMG/DDG §5 requires a separate legal notice on "
                    "commercial websites, independent of the GDPR privacy policy "
                    "requirement above."
                ),
                "category": "no_impressum",
            })

        if google_fonts:
            result["findings"].append({
                "severity": "medium",
                "title": "Google Fonts loaded from Google CDN",
                "detail": (
                    "fonts.googleapis.com is referenced, which transmits the visitor's "
                    "IP address to Google LLC (US). German courts have found this "
                    "non-compliant with GDPR without explicit consent. "
                    "Consider self-hosting fonts."
                ),
                "category": "google_fonts_external",
            })

        if processors:
            result["summary"]["processor_count"] = len(processors)
            for proc in processors:
                result["findings"].append({
                    "severity": "info",
                    "title": f"Third-party data processor: {proc}",
                    "detail": (
                        f"Resources from {proc} are loaded. This constitutes a "
                        f"data processing relationship requiring disclosure in the "
                        f"privacy policy (GDPR Art. 13/28)."
                    ),
                    "category": "third_party_processor",
                })

        result["summary"]["tracking_count"] = len(tracking_found)
        result["summary"]["findings_count"] = len(result["findings"])

        # Score
        score = 100
        for f in result["findings"]:
            if f["severity"] == "high":
                score -= 20
            elif f["severity"] == "medium":
                score -= 10
            elif f["severity"] == "info":
                score -= 2
        result["summary"]["score"] = max(0, score)

        return result

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _fetch_page(self, domain: str) -> Optional[str]:
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 YADS Security Scanner"},
                    allow_redirects=True,
                )
                if resp.status_code < 500:
                    return resp.text[:400_000]
            except Exception:
                continue
        return None

    def _detect_cmp(self, html: str, html_lower: str) -> Optional[str]:
        for cmp_name, patterns in CMP_SIGNATURES.items():
            for p in patterns:
                if p.lower() in html_lower:
                    return cmp_name
        return None

    def _detect_tracking(self, html: str, html_lower: str) -> List[str]:
        found = []
        for tracker_name, patterns in TRACKING_SCRIPTS.items():
            for p in patterns:
                if p.lower() in html_lower:
                    found.append(tracker_name)
                    break
        return found

    def _find_link(self, html: str, domain: str, pattern: "re.Pattern") -> Optional[str]:
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            if pattern.search(href) or pattern.search(
                html[max(0, m.start() - 50): m.end() + 100]
            ):
                if href.startswith("http"):
                    return href
                elif href.startswith("/"):
                    return f"https://{domain}{href}"
        return None

    def _find_privacy_policy(self, html: str, domain: str) -> Optional[str]:
        return self._find_link(html, domain, PRIVACY_POLICY_PATTERNS)

    def _find_impressum(self, html: str, domain: str) -> Optional[str]:
        return self._find_link(html, domain, IMPRESSUM_PATTERNS)

    def _detect_processors(self, html: str, html_lower: str) -> List[str]:
        found: List[str] = []
        for proc_name, domains in KNOWN_PROCESSORS.items():
            for d in domains:
                if d in html_lower:
                    found.append(proc_name)
                    break
        return found
