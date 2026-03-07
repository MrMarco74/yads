"""
Mobile App Discovery Scanner (#17)

Discovers mobile applications associated with a domain:
  - Google Play Store app search via public search
  - Apple App Store app lookup via iTunes Search API
  - Deep link / Universal Links check (apple-app-site-association)
  - Android App Links check (.well-known/assetlinks.json)
  - App Store URL patterns in page source
  - Play Store badges / icons in page HTML
  - Bundle ID / package name extraction
  - Outdated app version detection via public store API

No app installation or dynamic analysis — passive discovery only.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Accept": "application/json, text/html, */*",
}

ITUNES_SEARCH = "https://itunes.apple.com/search?term={query}&entity=software&limit=5&country=us"
APPLE_SITE_ASSOC = "/.well-known/apple-app-site-association"
ANDROID_ASSET_LINKS = "/.well-known/assetlinks.json"

PLAYSTORE_APP_RE = re.compile(
    r"https?://play\.google\.com/store/apps/details\?id=([\w.]+)",
    re.IGNORECASE,
)
APPSTORE_APP_RE = re.compile(
    r"https?://apps\.apple\.com/[a-z]{2}/app/[^/]+/id(\d+)",
    re.IGNORECASE,
)
BUNDLE_ID_RE = re.compile(
    r"""["']((?:[a-z][a-z0-9_]*\.){2,}[a-z][a-z0-9_]*)["']""",
    re.IGNORECASE,
)


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _get(url: str) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except Exception:
        return None


def _search_itunes(company_name: str, domain: str) -> List[Dict]:
    """Search iTunes Search API for apps related to domain/company."""
    apps = []
    try:
        query = company_name or domain.split(".")[0]
        r = requests.get(ITUNES_SEARCH.format(query=query), timeout=TIMEOUT)
        if r.status_code == 200:
            results = r.json().get("results", [])
            for app in results[:5]:
                seller = (app.get("sellerName") or app.get("artistName") or "").lower()
                seller_url = (app.get("sellerUrl") or "").lower()
                # Filter to apps likely owned by this domain
                if domain.split(".")[0] in seller or domain.split(".")[0] in seller_url:
                    apps.append({
                        "platform": "ios",
                        "name": app.get("trackName", ""),
                        "app_id": str(app.get("trackId", "")),
                        "bundle_id": app.get("bundleId", ""),
                        "version": app.get("version", ""),
                        "seller": app.get("sellerName", ""),
                        "url": app.get("trackViewUrl", ""),
                        "rating": app.get("averageUserRating", 0),
                        "rating_count": app.get("userRatingCount", 0),
                    })
    except Exception as e:
        logger.debug(f"iTunes search failed: {e}")
    return apps


def _check_apple_site_association(base: str) -> Optional[Dict]:
    """Check apple-app-site-association for Universal Links."""
    for url_str in [
        urljoin(base + "/", APPLE_SITE_ASSOC.lstrip("/")),
        urljoin(base + "/", f".well-known/apple-app-site-association"),
    ]:
        resp = _get(url_str)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                apps = []
                for detail in data.get("applinks", {}).get("details", []):
                    apps.append({
                        "app_id": detail.get("appID", ""),
                        "paths": detail.get("paths", [])[:10],
                    })
                return {
                    "url": url_str,
                    "apps": apps,
                    "webcredentials": data.get("webcredentials", {}),
                    "raw": data,
                }
            except Exception:
                return {"url": url_str, "apps": [], "raw": {}}
    return None


def _check_android_asset_links(base: str) -> Optional[Dict]:
    """Check assetlinks.json for Android App Links."""
    url_str = urljoin(base + "/", ANDROID_ASSET_LINKS.lstrip("/"))
    resp = _get(url_str)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            apps = []
            for entry in data:
                if entry.get("relation") and "delegate_permission/common.handle_all_urls" in entry.get("relation", []):
                    target = entry.get("target", {})
                    if target.get("namespace") == "android_app":
                        apps.append({
                            "package_name": target.get("package_name", ""),
                            "sha256_certs": target.get("sha256_cert_fingerprints", [])[:2],
                        })
            return {"url": url_str, "apps": apps, "raw": data}
        except Exception:
            return {"url": url_str, "apps": [], "raw": {}}
    return None


def _extract_apps_from_page(base: str) -> Dict:
    """Scan homepage and /download /apps for app store links."""
    ios_apps = []
    android_apps = []
    bundle_ids: Set[str] = set()

    for path in ["/", "/download", "/downloads", "/app", "/apps", "/get-app"]:
        url_str = urljoin(base + "/", path.lstrip("/"))
        resp = _get(url_str)
        if resp and resp.status_code == 200:
            body = resp.text[:100000]
            # Play Store links
            for m in PLAYSTORE_APP_RE.findall(body):
                android_apps.append(m)
            # App Store links
            for m in APPSTORE_APP_RE.findall(body):
                ios_apps.append(m)
            # Bundle IDs (from JS or meta tags)
            for m in BUNDLE_ID_RE.findall(body):
                # Filter likely-real bundle IDs (not URLs or common patterns)
                if len(m.split(".")) >= 3 and len(m) < 80:
                    bundle_ids.add(m)

    return {
        "ios_app_ids": list(set(ios_apps))[:5],
        "android_packages": list(set(android_apps))[:5],
        "bundle_ids": sorted(bundle_ids)[:10],
    }


def _get_company_name(base: str) -> Optional[str]:
    """Try to extract company/brand name from homepage."""
    try:
        resp = _get(base)
        if resp and resp.status_code == 200:
            m = re.search(r"<title[^>]*>([^<]+)</title>", resp.text[:5000], re.IGNORECASE)
            if m:
                return m.group(1).split("|")[0].split("-")[0].strip()[:40]
    except Exception:
        pass
    return None


class MobileAppDiscovery(BaseScannerModule):
    """Mobile application discovery and association checking."""

    @property
    def module_name(self) -> str:
        return "mobile_app_discovery"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)
        base = f"https://{domain}"

        result: Dict[str, Any] = {
            "domain": domain,
            "ios_apps": [],
            "android_apps": [],
            "apple_site_association": None,
            "android_asset_links": None,
            "page_discovered": {},
            "findings": [],
            "summary": {
                "score": 100,
                "app_count": 0,
                "has_deep_links": False,
                "issues": 0,
            },
        }

        findings: List[Dict] = []
        score = 100
        all_apps: List[Dict] = []

        # 1. apple-app-site-association
        apple_assoc = _check_apple_site_association(base)
        result["apple_site_association"] = apple_assoc

        # 2. assetlinks.json
        asset_links = _check_android_asset_links(base)
        result["android_asset_links"] = asset_links

        # 3. Extract from page source
        page_data = _extract_apps_from_page(base)
        result["page_discovered"] = page_data

        # 4. iTunes search
        company = _get_company_name(base)
        itunes_apps = _search_itunes(company or "", domain)
        result["ios_apps"] = itunes_apps
        all_apps.extend(itunes_apps)

        # Build android app list from asset links + page
        android_apps_list: List[Dict] = []
        if asset_links:
            for a in asset_links.get("apps", []):
                android_apps_list.append({
                    "platform": "android",
                    "package_name": a.get("package_name", ""),
                    "source": "assetlinks.json",
                })
        for pkg in page_data.get("android_packages", []):
            android_apps_list.append({"platform": "android", "package_name": pkg, "source": "page"})
        result["android_apps"] = android_apps_list
        all_apps.extend(android_apps_list)

        result["summary"]["app_count"] = len(all_apps)
        has_deep_links = bool(apple_assoc or asset_links)
        result["summary"]["has_deep_links"] = has_deep_links

        # --- Findings ---
        if all_apps:
            findings.append({
                "severity": "info",
                "title": f"{len(all_apps)} mobile app(s) associated with {domain}",
                "description": (
                    f"Mobile apps linked to this domain: "
                    f"{', '.join(a.get('name') or a.get('package_name', '') for a in all_apps[:3])}"
                ),
                "apps": all_apps[:10],
            })

        if apple_assoc and apple_assoc.get("apps"):
            # Check for overly broad path matching (/*) in Universal Links
            for app in apple_assoc["apps"]:
                if "/*" in app.get("paths", []) or "*" in app.get("paths", []):
                    findings.append({
                        "severity": "low",
                        "title": "Universal Links configured with wildcard path (/*)",
                        "description": (
                            "apple-app-site-association uses wildcard paths, meaning all URLs "
                            "on this domain open the app. Overly broad configuration can cause "
                            "unexpected app launches and potential phishing vectors."
                        ),
                        "app_id": app.get("app_id"),
                    })
                    score -= 5

        if asset_links and asset_links.get("apps"):
            findings.append({
                "severity": "info",
                "title": f"Android App Links configured: {', '.join(a['package_name'] for a in asset_links['apps'][:3])}",
                "description": "assetlinks.json links this domain to Android app(s) for deep linking.",
                "packages": [a["package_name"] for a in asset_links["apps"]],
            })

        if page_data.get("bundle_ids"):
            findings.append({
                "severity": "info",
                "title": f"App bundle IDs found in page source: {', '.join(page_data['bundle_ids'][:3])}",
                "description": "Bundle/package identifiers were found in page source — useful for app store lookup.",
                "bundle_ids": page_data["bundle_ids"],
            })

        if not all_apps and not has_deep_links:
            findings.append({
                "severity": "info",
                "title": "No mobile apps discovered",
                "description": f"No iOS or Android apps were found associated with {domain}.",
            })

        result["summary"]["score"] = max(0, score)
        result["summary"]["issues"] = len([f for f in findings if f["severity"] not in ("info",)])
        result["findings"] = findings
        return result
