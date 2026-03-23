"""
Mobile App Monitor

Searches public app stores for mobile apps associated with the target domain/brand.
Brand impersonation on mobile stores is a growing attack vector — malicious actors
publish apps mimicking legitimate services to steal credentials, distribute malware,
or intercept communications.

What this module does:
- Extracts brand name from target domain (e.g. "example.com" → "example")
- Searches Google Play Store via web scraping (no API key)
- Searches Apple App Store via public iTunes Search API
- Identifies potential impostor apps (brand name in title, different publisher)
- Flags legitimate apps that are outdated (>2 years no update) or low-rated (<2.5)
- Verifies publisher against the target domain

Severity mapping:
- Potential impostor app detected → high
- Legitimate app outdated >2 years → medium
- Legitimate app with low rating (<2.5) → info
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10

ITUNES_SEARCH_API = "https://itunes.apple.com/search"
PLAY_SEARCH_URL = "https://play.google.com/store/search"

# Days threshold for "outdated app" finding
OUTDATED_DAYS = 365 * 2  # 2 years

# Rating threshold for low-rated app
LOW_RATING_THRESHOLD = 2.5

# Common TLDs to strip from domain names
_TLDS = {
    "com", "net", "org", "io", "de", "co", "uk", "fr", "eu", "app",
    "tech", "dev", "info", "biz", "at", "ch", "nl", "be", "it", "es",
    "pl", "se", "no", "dk", "fi", "pt", "cz", "hu", "ro", "bg",
}


def _extract_brand(domain: str) -> str:
    """Extract brand name from domain. e.g. 'myapp.example.com' → 'example'."""
    domain = domain.lower().strip().split(":")[0]
    parts = domain.split(".")
    # Remove common TLD suffixes from the end
    while parts and parts[-1].lower() in _TLDS:
        parts.pop()
    # Remove leading 'www'
    if parts and parts[0] == "www":
        parts.pop(0)
    if not parts:
        return domain.split(".")[0]
    # Return the last meaningful part (company name)
    return parts[-1]


def _similarity_ratio(a: str, b: str) -> float:
    """Simple character-overlap similarity score between two strings."""
    a, b = a.lower(), b.lower()
    if not a or not b:
        return 0.0
    # Count matching characters
    set_a, set_b = set(a), set(b)
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def _normalize_publisher(publisher: str, domain: str) -> bool:
    """
    Return True if the publisher name looks like it could belong to the target domain.
    Heuristic: publisher contains the brand name or vice versa.
    """
    brand = _extract_brand(domain)
    publisher_lower = publisher.lower()
    # Check direct containment (most reliable signal)
    if brand in publisher_lower:
        return True
    # Check similarity ratio
    return _similarity_ratio(brand, publisher_lower) > 0.5


class MobileAppMonitor(BaseScannerModule):
    """
    Searches Google Play and Apple App Store for apps associated with the target brand.
    Flags potential impostors and unmaintained legitimate apps.
    """

    @property
    def module_name(self) -> str:
        return "mobile_app_monitor"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
        )
        brand = _extract_brand(domain)

        result: Dict[str, Any] = {
            "domain": domain,
            "brand": brand,
            "play_store_apps": [],
            "appstore_apps": [],
            "impostors": [],
            "legitimate_apps": [],
            "findings": [],
            "summary": {},
        }

        # Search both stores
        play_apps = self._search_play_store(brand)
        result["play_store_apps"] = play_apps

        appstore_apps = self._search_app_store(brand)
        result["appstore_apps"] = appstore_apps

        all_apps = play_apps + appstore_apps

        # Classify apps
        for app in all_apps:
            publisher = app.get("publisher", "")
            app_name = app.get("name", "")
            brand_in_name = brand.lower() in app_name.lower()
            publisher_matches = _normalize_publisher(publisher, domain)

            if brand_in_name and not publisher_matches:
                # Brand in name but publisher doesn't match → potential impostor
                app["classification"] = "impostor"
                result["impostors"].append(app)
            elif publisher_matches:
                app["classification"] = "legitimate"
                result["legitimate_apps"].append(app)
            else:
                app["classification"] = "unrelated"

        # Generate findings
        self._generate_findings(result, domain, brand)

        # Summary
        result["summary"] = {
            "domain": domain,
            "brand": brand,
            "play_store_results": len(play_apps),
            "appstore_results": len(appstore_apps),
            "total_apps_found": len(all_apps),
            "impostors_detected": len(result["impostors"]),
            "legitimate_apps": len(result["legitimate_apps"]),
            "findings_count": len(result["findings"]),
            "highest_severity": (
                "high" if any(f["severity"] == "high" for f in result["findings"]) else
                "medium" if any(f["severity"] == "medium" for f in result["findings"]) else
                "info" if result["findings"] else "pass"
            ),
        }

        return result

    # ------------------------------------------------------------------
    # Google Play Store scraper
    # ------------------------------------------------------------------

    def _search_play_store(self, brand: str) -> List[Dict[str, Any]]:
        """Scrape Google Play Store search results for the brand name."""
        apps: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                PLAY_SEARCH_URL,
                params={"q": brand, "c": "apps", "hl": "en", "gl": "US"},
                timeout=REQUEST_TIMEOUT,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/122.0.0.0 Safari/537.36"
                    ),
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )
            if resp.status_code != 200:
                logger.debug(f"Play Store search returned {resp.status_code}")
                return apps

            html = resp.text
            apps = self._parse_play_results(html, brand)

        except Exception as e:
            logger.debug(f"Play Store search failed: {e}")
        return apps

    def _parse_play_results(self, html: str, brand: str) -> List[Dict[str, Any]]:
        """Extract app data from Play Store HTML response."""
        apps: List[Dict[str, Any]] = []

        # Extract app names and publishers from the structured Play Store HTML.
        # Play Store renders data in embedded JSON within script tags.
        # Primary pattern: look for app cards with title and developer
        app_name_patterns = [
            # Pattern matching app title in data-item-id context
            r'class="[^"]*title[^"]*"[^>]*>\s*([^<]{3,60})\s*</(?:div|span|a)',
            # Aria-label patterns used for app cards
            r'aria-label="([^"]{5,80})"[^>]*data-docid',
        ]

        # More reliable: extract from JSON-embedded data in Play Store HTML
        # Look for JS data structures containing app info
        json_pattern = re.compile(
            r'\[\["([^"]{3,60})",\s*"([^"]{3,60})",\s*null,\s*"\[',
        )

        # Simpler reliable extraction: look for paired app title + developer
        # Play Store uses [[["app_id"]] with title/developer in nearby data
        block_pattern = re.compile(
            r'data-docid="([^"]+)"[^>]*>.*?'
            r'class="[^"]*title[^"]*">([^<]{2,60})</.*?'
            r'class="[^"]*subtitle[^"]*">([^<]{2,100})</.*?',
            re.DOTALL,
        )

        for m in block_pattern.finditer(html):
            app_id = m.group(1).strip()
            name = m.group(2).strip()
            publisher = m.group(3).strip()
            if not name or not app_id:
                continue
            apps.append({
                "store": "google_play",
                "app_id": app_id,
                "name": name,
                "publisher": publisher,
                "url": f"https://play.google.com/store/apps/details?id={app_id}",
                "rating": None,
                "last_updated": None,
            })

        # Fallback: simpler regex for app names in title spans
        if not apps:
            title_pub_pattern = re.compile(
                r'data-docid="([a-z][a-z0-9._]{4,})".*?'
                r'"truncate-multiline--truncated">([^<]{2,60})</span>.*?'
                r'href="/store/apps/developer[^"]*">([^<]{2,80})</a>',
                re.DOTALL,
            )
            seen_ids: set = set()
            for m in title_pub_pattern.finditer(html):
                app_id = m.group(1).strip()
                if app_id in seen_ids:
                    continue
                seen_ids.add(app_id)
                name = m.group(2).strip()
                publisher = m.group(3).strip()
                if not name:
                    continue
                apps.append({
                    "store": "google_play",
                    "app_id": app_id,
                    "name": name,
                    "publisher": publisher,
                    "url": f"https://play.google.com/store/apps/details?id={app_id}",
                    "rating": None,
                    "last_updated": None,
                })

        # Second fallback: extract from embedded JSON arrays (Play Store uses AF_initDataCallback)
        if not apps:
            apps = self._parse_play_json(html)

        return apps[:20]

    def _parse_play_json(self, html: str) -> List[Dict[str, Any]]:
        """Try to extract app data from Play Store's embedded JSON payloads."""
        apps: List[Dict[str, Any]] = []
        # Play Store embeds data in AF_initDataCallback calls
        # Look for arrays containing package IDs (com.xxx.xxx pattern) with adjacent strings
        pkg_pattern = re.compile(r'"((?:com|org|net|io)\.[a-zA-Z0-9._]{4,60})"')
        # Also find strings that look like app names near package IDs
        region = re.compile(
            r'"((?:com|org|net|io)\.[a-zA-Z0-9._]{4,60})"'
            r'.{0,500}?"([A-Z][^"]{3,50})"'
            r'.{0,200}?"([A-Z][^"]{2,60}(?:Ltd|LLC|GmbH|Inc|Corp|AG|SAS|BV|SE|AB)?)"',
            re.DOTALL,
        )
        seen: set = set()
        for m in region.finditer(html):
            pkg = m.group(1)
            name = m.group(2).strip()
            publisher = m.group(3).strip()
            if pkg in seen or len(name) < 3:
                continue
            if any(x in name.lower() for x in ("http", "://", "null", "true", "false")):
                continue
            seen.add(pkg)
            apps.append({
                "store": "google_play",
                "app_id": pkg,
                "name": name,
                "publisher": publisher,
                "url": f"https://play.google.com/store/apps/details?id={pkg}",
                "rating": None,
                "last_updated": None,
            })
        return apps[:20]

    # ------------------------------------------------------------------
    # Apple App Store (iTunes Search API)
    # ------------------------------------------------------------------

    def _search_app_store(self, brand: str) -> List[Dict[str, Any]]:
        """Query the iTunes Search API for apps matching the brand."""
        apps: List[Dict[str, Any]] = []
        try:
            resp = requests.get(
                ITUNES_SEARCH_API,
                params={
                    "term": brand,
                    "media": "software",
                    "limit": "20",
                    "country": "us",
                },
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 YADS/MobileAppMonitor"},
            )
            if resp.status_code != 200:
                return apps

            data = resp.json()
            for item in data.get("results", []):
                app_name = item.get("trackName", "")
                publisher = item.get("artistName", item.get("sellerName", ""))
                bundle_id = item.get("bundleId", "")
                track_id = item.get("trackId", "")
                rating = item.get("averageUserRating")
                rating_count = item.get("userRatingCount", 0)
                version_date_str = item.get("currentVersionReleaseDate") or item.get("releaseDate", "")
                last_updated = None
                days_since_update = None
                if version_date_str:
                    try:
                        dt = datetime.fromisoformat(version_date_str.rstrip("Z"))
                        dt = dt.replace(tzinfo=timezone.utc)
                        last_updated = version_date_str
                        days_since_update = (datetime.now(timezone.utc) - dt).days
                    except ValueError:
                        pass

                app_url = item.get("trackViewUrl", "")

                apps.append({
                    "store": "apple_appstore",
                    "app_id": str(track_id),
                    "bundle_id": bundle_id,
                    "name": app_name,
                    "publisher": publisher,
                    "url": app_url,
                    "rating": round(float(rating), 2) if rating else None,
                    "rating_count": rating_count,
                    "last_updated": last_updated,
                    "days_since_update": days_since_update,
                })

        except Exception as e:
            logger.debug(f"App Store search failed: {e}")

        return apps

    # ------------------------------------------------------------------
    # Findings generation
    # ------------------------------------------------------------------

    def _generate_findings(self, result: Dict, domain: str, brand: str) -> None:
        findings = result["findings"]

        # Impostor apps
        for app in result["impostors"]:
            store = "Google Play" if app["store"] == "google_play" else "Apple App Store"
            findings.append({
                "severity": "high",
                "title": f"Potential impostor app on {store}: \"{app['name']}\"",
                "detail": (
                    f"The app \"{app['name']}\" on {store} contains the brand name \"{brand}\" "
                    f"but is published by \"{app.get('publisher', 'unknown')}\" — "
                    f"which does not appear to match the target organisation. "
                    f"This pattern is consistent with brand impersonation: apps designed to "
                    f"deceive users into installing malware or credential-harvesting software. "
                    f"Verify legitimacy at: {app.get('url', 'N/A')} and consider filing a takedown request."
                ),
                "category": "impostor_app",
            })

        # Outdated legitimate apps
        now_ts = datetime.now(timezone.utc)
        for app in result["legitimate_apps"]:
            days = app.get("days_since_update")
            if days is not None and days > OUTDATED_DAYS:
                store = "Google Play" if app["store"] == "google_play" else "Apple App Store"
                years = round(days / 365, 1)
                findings.append({
                    "severity": "medium",
                    "title": f"Legitimate app not updated in {years} years: \"{app['name']}\" ({store})",
                    "detail": (
                        f"The app \"{app['name']}\" published by \"{app.get('publisher', 'unknown')}\" "
                        f"on {store} has not received an update in approximately {years} years "
                        f"(last update: {app.get('last_updated', 'unknown')}). "
                        f"Abandoned mobile apps with an active user base are a security liability: "
                        f"unpatched vulnerabilities accumulate, and app accounts/domains may expire "
                        f"and be re-registered by third parties. Consider updating or formally deprecating."
                    ),
                    "category": "outdated_legitimate_app",
                })

        # Low-rated legitimate apps
        for app in result["legitimate_apps"]:
            rating = app.get("rating")
            rating_count = app.get("rating_count", 0)
            if rating is not None and rating < LOW_RATING_THRESHOLD and rating_count >= 10:
                store = "Google Play" if app["store"] == "google_play" else "Apple App Store"
                findings.append({
                    "severity": "info",
                    "title": f"Legitimate app with low rating ({rating}) on {store}: \"{app['name']}\"",
                    "detail": (
                        f"The app \"{app['name']}\" has an average user rating of {rating}/5 "
                        f"based on {rating_count} review(s) on {store}. "
                        f"A low rating may indicate user dissatisfaction, security issues reported "
                        f"by users, or poor functionality — worth investigating the review content."
                    ),
                    "category": "low_rated_app",
                })

        # If nothing found at all
        if not result["play_store_apps"] and not result["appstore_apps"]:
            findings.append({
                "severity": "info",
                "title": f"No mobile apps found for brand \"{brand}\"",
                "detail": (
                    f"Searches on Google Play Store and Apple App Store for the brand \"{brand}\" "
                    f"did not return any results. Either no mobile app exists for this brand "
                    f"or the brand name is too generic to identify relevant apps."
                ),
                "category": "no_apps_found",
            })
        elif not result["impostors"] and not result["legitimate_apps"]:
            findings.append({
                "severity": "info",
                "title": f"No impostor apps detected for brand \"{brand}\"",
                "detail": (
                    f"Search results for \"{brand}\" were found but none matched the impostor "
                    f"pattern (brand name in title with mismatched publisher). "
                    f"Continue monitoring periodically as new apps can be submitted at any time."
                ),
                "category": "no_impostors",
            })
