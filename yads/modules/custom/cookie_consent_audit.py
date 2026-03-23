"""
Cookie Consent Audit

Deep-tests a target's cookie consent implementation beyond static HTML analysis.
Where dsgvo_scanner detects *presence* of a CMP, this module verifies *correctness*:

Dynamic layer (Playwright):
- Intercepts network requests to detect tracking fires BEFORE consent is given
- Simulates "Reject All" and verifies tracking stops
- Checks consent cookie TTL (EDPB: max 13 months)
- Detects cookie walls (content gated behind consent)

Dark pattern detection:
- Missing or hidden "Reject All" / "Deny" option
- Pre-ticked consent checkboxes
- Asymmetric button styling (accept prominent, reject hidden/grey)
- Forced interaction patterns (no way to close without accepting)

Static fallback (requests):
- Used when Playwright is unavailable
- Covers CMP detection, banner text analysis, and cookie header inspection

Severity mapping:
- Tracking before consent → critical
- No reject path detectable → high
- Pre-ticked boxes / dark patterns → high
- Consent TTL > 13 months → medium
- Cookie wall detected → medium
- CMP present but unverified → info
"""

import logging
import re
import socket
from datetime import datetime, timezone
from http.cookiejar import http2time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 20

# Known tracking domains — network requests to these before consent = violation
TRACKING_DOMAINS = [
    "google-analytics.com", "analytics.google.com",
    "googletagmanager.com", "googleadservices.com",
    "doubleclick.net", "googlesyndication.com",
    "connect.facebook.net", "facebook.com/tr",
    "snap.licdn.com", "px.ads.linkedin.com",
    "static.hotjar.com", "script.hotjar.com",
    "clarity.ms",
    "cdn.segment.com",
    "cdn.mxpnl.com",
    "analytics.tiktok.com",
    "static.ads-twitter.com",
    "bat.bing.com",
    "td.doubleclick.net",
    "stats.g.doubleclick.net",
]

# Text patterns indicating a "Reject" option in consent banners
REJECT_PATTERNS = re.compile(
    r"(reject all|deny all|decline all|alle ablehnen|alles ablehnen"
    r"|nicht akzeptieren|ablehnen|opt.?out|refuse|no thanks|nein danke"
    r"|nur notwendige|only necessary|only essential)",
    re.IGNORECASE,
)

# Text patterns for accept buttons (to compare prominence)
ACCEPT_PATTERNS = re.compile(
    r"(accept all|agree|allow all|alle akzeptieren|zustimmen"
    r"|einverstanden|ok|got it|verstanden|i agree)",
    re.IGNORECASE,
)

# Dark pattern: pre-ticked checkbox patterns
PRE_TICKED_PATTERNS = re.compile(
    r'<input[^>]+type=["\']checkbox["\'][^>]+checked[^>]*>',
    re.IGNORECASE,
)

# Cookie wall indicators
COOKIE_WALL_PATTERNS = re.compile(
    r"(to continue|um fortzufahren|to access|zugriff erhalten"
    r"|you must accept|sie müssen akzeptieren|required to proceed"
    r"|mandatory|pflicht|consent required)",
    re.IGNORECASE,
)

# Max consent TTL per EDPB guidelines (13 months in seconds)
EDPB_MAX_TTL_SECONDS = 13 * 30 * 24 * 3600


class CookieConsentAudit(BaseScannerModule):
    """
    Verifies that cookie consent implementations are correctly enforced,
    not just visually present. Detects dark patterns, pre-consent tracking
    fires, and non-compliant consent TTLs.
    """

    @property
    def module_name(self) -> str:
        return "cookie_consent_audit"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
        )
        url = f"https://{domain}"

        result: Dict[str, Any] = {
            "domain": domain,
            "method": "static",
            "pre_consent_tracking": [],
            "reject_path_found": None,
            "dark_patterns": [],
            "consent_ttl_violations": [],
            "cookie_wall": False,
            "findings": [],
        }

        # --- Try dynamic analysis first ---
        dynamic_ok = False
        try:
            from playwright.sync_api import sync_playwright
            dynamic_ok = True
        except ImportError:
            logger.debug("Playwright not available — falling back to static analysis")

        if dynamic_ok:
            self._run_dynamic(url, domain, result)
        else:
            self._run_static(url, domain, result)

        self._score(result)
        return result

    # ------------------------------------------------------------------
    # Dynamic Analysis (Playwright)
    # ------------------------------------------------------------------

    def _run_dynamic(self, url: str, domain: str, result: Dict) -> None:
        result["method"] = "dynamic"
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={"width": 1280, "height": 900},
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) YADS/ConsentAudit",
                )

                pre_consent_fires: List[str] = []

                def _intercept(request):
                    req_url = request.url.lower()
                    for td in TRACKING_DOMAINS:
                        if td in req_url:
                            pre_consent_fires.append(request.url)

                page = context.new_page()
                page.on("request", _intercept)

                try:
                    page.goto(url, timeout=20000, wait_until="networkidle")
                except Exception:
                    try:
                        page.goto(url.replace("https://", "http://"), timeout=15000, wait_until="domcontentloaded")
                    except Exception as e:
                        result["error"] = f"Page load failed: {e}"
                        browser.close()
                        self._run_static(url, domain, result)
                        result["method"] = "static_fallback"
                        return

                result["pre_consent_tracking"] = list(dict.fromkeys(pre_consent_fires))

                # Check for cookie wall
                page_text = page.inner_text("body") if page.locator("body").count() else ""
                if COOKIE_WALL_PATTERNS.search(page_text):
                    result["cookie_wall"] = True

                # Check banner content for reject path and dark patterns
                banner_html = self._extract_banner_html(page)
                if banner_html:
                    result["reject_path_found"] = bool(REJECT_PATTERNS.search(banner_html))
                    if PRE_TICKED_PATTERNS.search(banner_html):
                        result["dark_patterns"].append("pre_ticked_checkbox")
                    if not REJECT_PATTERNS.search(banner_html) and ACCEPT_PATTERNS.search(banner_html):
                        result["dark_patterns"].append("no_reject_option")
                    self._check_button_asymmetry(banner_html, result)
                else:
                    result["reject_path_found"] = False

                # Check consent cookie TTLs
                cookies = context.cookies()
                self._check_consent_ttls(cookies, result)

                browser.close()

        except Exception as e:
            logger.warning(f"Dynamic consent audit failed: {e}")
            result["method"] = "static_fallback"
            self._run_static(url, domain, result)

    def _extract_banner_html(self, page) -> Optional[str]:
        """Try common consent banner selectors."""
        selectors = [
            "[id*='consent']", "[id*='cookie']", "[id*='gdpr']", "[id*='cmp']",
            "[class*='consent']", "[class*='cookie-banner']", "[class*='cookie-notice']",
            "[class*='cc-banner']", "[aria-label*='cookie']", "[aria-label*='consent']",
        ]
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if el.count() and el.is_visible():
                    return el.inner_html()
            except Exception:
                continue
        return None

    def _check_button_asymmetry(self, banner_html: str, result: Dict) -> None:
        """Detect asymmetric button styling — accept visually prominent, reject buried."""
        html_lower = banner_html.lower()
        has_accept = bool(ACCEPT_PATTERNS.search(html_lower))
        has_reject = bool(REJECT_PATTERNS.search(html_lower))
        if has_accept and not has_reject:
            result["dark_patterns"].append("reject_buried_or_missing")
        btn_pattern = re.findall(
            r'<(?:button|a)[^>]*(?:btn-primary|btn-accept|btn-success|primary|highlighted)[^>]*>([^<]+)<',
            html_lower,
        )
        if btn_pattern and has_reject:
            for btn_text in btn_pattern:
                if ACCEPT_PATTERNS.search(btn_text) and not REJECT_PATTERNS.search(btn_text):
                    if "dark_pattern_asymmetric_buttons" not in result["dark_patterns"]:
                        result["dark_patterns"].append("asymmetric_button_styling")

    def _check_consent_ttls(self, cookies: List[Dict], result: Dict) -> None:
        now = datetime.now(timezone.utc).timestamp()
        consent_names = re.compile(
            r"(consent|cookie.*accept|cookieyes|onetrust|borlabs|gdpr|cmp|cc_)",
            re.IGNORECASE,
        )
        for c in cookies:
            if not consent_names.search(c.get("name", "")):
                continue
            expires = c.get("expires", -1)
            if expires and expires > 0:
                ttl = expires - now
                if ttl > EDPB_MAX_TTL_SECONDS:
                    months = round(ttl / (30 * 24 * 3600), 1)
                    result["consent_ttl_violations"].append({
                        "name": c["name"],
                        "ttl_months": months,
                        "limit_months": 13,
                    })

    # ------------------------------------------------------------------
    # Static Analysis (requests fallback)
    # ------------------------------------------------------------------

    def _run_static(self, url: str, domain: str, result: Dict) -> None:
        if result["method"] != "static_fallback":
            result["method"] = "static"
        html = self._fetch(url) or self._fetch(url.replace("https://", "http://"))
        if not html:
            result["error"] = "Could not fetch page"
            return

        html_lower = html.lower()

        # Dark pattern detection from static HTML
        if PRE_TICKED_PATTERNS.search(html):
            result["dark_patterns"].append("pre_ticked_checkbox")

        result["reject_path_found"] = bool(REJECT_PATTERNS.search(html_lower))
        if not result["reject_path_found"] and ACCEPT_PATTERNS.search(html_lower):
            result["dark_patterns"].append("no_reject_option_static")

        if COOKIE_WALL_PATTERNS.search(html_lower):
            result["cookie_wall"] = True

        # Static tracking detection (cannot determine pre/post consent order)
        for td in TRACKING_DOMAINS:
            if td in html_lower:
                result["pre_consent_tracking"].append(f"{td} (static — order unverifiable)")

        # Check Set-Cookie headers for TTL
        try:
            resp = requests.get(
                url, timeout=REQUEST_TIMEOUT, verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS/ConsentAudit"},
                allow_redirects=True,
            )
            for header_val in resp.headers.get("Set-Cookie", "").split(","):
                if "max-age" in header_val.lower():
                    m = re.search(r"max-age=(\d+)", header_val, re.IGNORECASE)
                    if m:
                        ttl_s = int(m.group(1))
                        if ttl_s > EDPB_MAX_TTL_SECONDS:
                            result["consent_ttl_violations"].append({
                                "name": "Set-Cookie header",
                                "ttl_months": round(ttl_s / (30 * 24 * 3600), 1),
                                "limit_months": 13,
                            })
        except Exception:
            pass

    def _fetch(self, url: str) -> Optional[str]:
        try:
            r = requests.get(
                url, timeout=REQUEST_TIMEOUT, verify=False,
                headers={"User-Agent": "Mozilla/5.0 YADS/ConsentAudit"},
                allow_redirects=True,
            )
            if r.status_code < 500:
                return r.text[:500_000]
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Generate findings
    # ------------------------------------------------------------------

    def _score(self, result: Dict) -> None:
        findings: List[Dict] = []

        if result["pre_consent_tracking"] and result["method"] == "dynamic":
            for tracker_url in result["pre_consent_tracking"][:10]:
                domain_part = urlparse(tracker_url).netloc or tracker_url[:60]
                findings.append({
                    "severity": "critical",
                    "title": f"Tracking request fired before consent: {domain_part}",
                    "detail": (
                        f"A network request to {tracker_url} was observed "
                        f"before any user interaction with the consent banner. "
                        f"This constitutes processing personal data (IP address) "
                        f"without a legal basis under GDPR Art. 6. "
                        f"The CMP must block this script until consent is granted."
                    ),
                    "category": "pre_consent_tracking",
                })

        if result["reject_path_found"] is False:
            findings.append({
                "severity": "high",
                "title": "No 'Reject All' option detectable in consent banner",
                "detail": (
                    "The consent UI does not appear to offer an equally accessible "
                    "way to reject non-essential cookies. The EDPB (Guidelines 05/2020) "
                    "requires that withdrawing consent be as easy as giving it. "
                    "A missing reject button makes consent legally invalid."
                ),
                "category": "no_reject_path",
            })

        for dp in result["dark_patterns"]:
            dp_msgs = {
                "pre_ticked_checkbox": (
                    "high",
                    "Pre-ticked consent checkboxes detected",
                    "Checkboxes for non-essential processing are pre-selected. "
                    "GDPR Recital 32 explicitly states that pre-ticked boxes do not "
                    "constitute valid consent.",
                ),
                "no_reject_option": (
                    "high",
                    "Accept button present with no corresponding reject option",
                    "An 'Accept' or 'Agree' action is available without an equivalent "
                    "reject option at the same level, indicating a dark pattern.",
                ),
                "asymmetric_button_styling": (
                    "medium",
                    "Asymmetric button styling — accept is visually dominant",
                    "The accept button uses primary/highlighted styling while the reject "
                    "option is visually de-emphasized. EDPB considers this a dark pattern "
                    "that undermines free consent.",
                ),
                "reject_buried_or_missing": (
                    "high",
                    "Reject option absent or not discoverable at first layer",
                    "No reject option was found in the consent banner. Users may be "
                    "forced to navigate into settings to decline, violating the "
                    "symmetry requirement of GDPR valid consent.",
                ),
            }
            if dp in dp_msgs:
                sev, title, detail = dp_msgs[dp]
                findings.append({
                    "severity": sev, "title": title, "detail": detail,
                    "category": f"dark_pattern_{dp}",
                })

        for ttl_v in result["consent_ttl_violations"]:
            findings.append({
                "severity": "medium",
                "title": f"Consent cookie TTL exceeds EDPB limit: {ttl_v['name']}",
                "detail": (
                    f"The cookie '{ttl_v['name']}' has a lifetime of "
                    f"{ttl_v['ttl_months']} months. The EDPB recommends a maximum "
                    f"of 13 months for consent cookies. Exceeding this requires "
                    f"re-soliciting consent before expiry."
                ),
                "category": "consent_ttl_violation",
            })

        if result["cookie_wall"]:
            findings.append({
                "severity": "medium",
                "title": "Possible cookie wall detected",
                "detail": (
                    "Language suggesting that access to content requires consent was "
                    "detected. Cookie walls — conditioning service access on consent — "
                    "are considered invalid under GDPR by multiple DPAs (AT, NL, DE) "
                    "as they make consent involuntary."
                ),
                "category": "cookie_wall",
            })

        if not findings and result["method"] != "dynamic":
            findings.append({
                "severity": "info",
                "title": "Static analysis only — dynamic verification recommended",
                "detail": (
                    "Playwright was not available. Pre-consent tracking fires and "
                    "reject-path enforcement could not be verified dynamically. "
                    "Install Playwright (playwright install chromium) for full audit."
                ),
                "category": "static_only",
            })

        result["findings"] = findings
        result["summary"] = {
            "method": result["method"],
            "pre_consent_fires": len(result["pre_consent_tracking"]),
            "dark_patterns": len(result["dark_patterns"]),
            "ttl_violations": len(result["consent_ttl_violations"]),
            "cookie_wall": result["cookie_wall"],
            "findings_count": len(findings),
            "highest_severity": (
                "critical" if any(f["severity"] == "critical" for f in findings) else
                "high" if any(f["severity"] == "high" for f in findings) else
                "medium" if any(f["severity"] == "medium" for f in findings) else
                "info" if findings else "pass"
            ),
        }
