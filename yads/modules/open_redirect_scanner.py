"""
Open Redirect Scanner (#14)

Tests common redirect parameters for open redirect vulnerabilities.
An open redirect allows attackers to craft URLs that redirect victims
to attacker-controlled sites (phishing, credential harvesting).

Tests: GET parameters commonly used for redirects + meta-refresh + Location headers.
"""

import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
CANARY = "evil-yads-test.example.com"
CANARY_URLS = [
    f"https://{CANARY}/",
    f"http://{CANARY}/",
    f"//{CANARY}/",
    f"https://{CANARY}",
    f"\\\\{CANARY}",
    f"@{CANARY}",
]

# Common redirect parameters
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnUrl", "returnTo", "next", "next_url",
    "goto", "go", "destination", "dest", "target", "to", "link",
    "forward", "forward_url", "location", "out", "view", "ref",
    "referer", "referrer", "from", "from_url", "continue",
    "redir", "redir_url", "jump", "jump_url", "r", "u",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Accept": "text/html,application/xhtml+xml",
}

_META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^\s"\']+)',
    re.IGNORECASE,
)


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _base_urls(domain: str) -> List[str]:
    return [f"https://{domain}", f"http://{domain}"]


def _check_redirect(base_url: str, param: str, canary_url: str) -> Optional[Dict]:
    """
    Test a single URL + param + canary combination.
    Returns a finding dict if vulnerable, else None.
    """
    test_url = f"{base_url}/?{param}={urllib.parse.quote(canary_url, safe=':/')}"
    try:
        r = requests.get(
            test_url,
            timeout=TIMEOUT,
            allow_redirects=False,
            headers=HEADERS,
            verify=False,
        )
        # Check Location header
        location = r.headers.get("Location", "")
        if CANARY in location:
            return {
                "severity": "medium",
                "title": f"Open Redirect via ?{param}=",
                "description": (
                    f"The parameter `{param}` redirects to an arbitrary external URL. "
                    f"Tested URL: {test_url} → Location: {location}"
                ),
                "url": test_url,
                "parameter": param,
                "redirect_to": location,
                "method": "location_header",
            }
        # Check body for meta-refresh redirect
        if r.status_code == 200:
            body = r.text[:4096]
            m = _META_REFRESH.search(body)
            if m and CANARY in m.group(1):
                return {
                    "severity": "medium",
                    "title": f"Open Redirect (meta-refresh) via ?{param}=",
                    "description": (
                        f"The parameter `{param}` causes a meta-refresh redirect to an external URL. "
                        f"Tested URL: {test_url}"
                    ),
                    "url": test_url,
                    "parameter": param,
                    "redirect_to": m.group(1),
                    "method": "meta_refresh",
                }
    except requests.exceptions.TooManyRedirects:
        pass
    except Exception:
        pass
    return None


def _discover_existing_redirects(base_url: str) -> List[Dict]:
    """Check if the root URL itself does a redirect and if it's manipulable."""
    findings = []
    try:
        r = requests.get(
            base_url,
            timeout=TIMEOUT,
            allow_redirects=False,
            headers=HEADERS,
            verify=False,
        )
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            if location and not location.startswith("/") and "://" in location:
                parsed = urllib.parse.urlparse(location)
                if parsed.netloc and parsed.query:
                    # Check if redirect target has redirect params in its query
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    for p in REDIRECT_PARAMS:
                        if p in params:
                            findings.append({
                                "severity": "info",
                                "title": f"Redirect chain uses ?{p}= parameter",
                                "description": (
                                    f"The root URL redirects to {location}, "
                                    f"which itself contains a `{p}` parameter. "
                                    "This may be exploitable as an open redirect."
                                ),
                                "url": base_url,
                                "parameter": p,
                            })
    except Exception:
        pass
    return findings


class OpenRedirectScanner(BaseScannerModule):
    """Tests for open redirect vulnerabilities via common redirect parameters."""

    @property
    def module_name(self) -> str:
        return "open_redirect_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)
        base_urls = _base_urls(domain)

        result: Dict[str, Any] = {
            "domain": domain,
            "tested_params": [],
            "tested_urls": 0,
            "findings": [],
            "summary": {
                "score": 100,
                "vulnerable_params": 0,
                "status": "clean",
            },
        }

        findings: List[Dict] = []
        tested = 0
        seen_params = set()

        # Phase 1: targeted parameter testing (https first, stop early if found)
        for base_url in base_urls:
            for param in REDIRECT_PARAMS:
                if param in seen_params:
                    continue
                # Test with https canary only (most common case)
                finding = _check_redirect(base_url, param, f"https://{CANARY}/")
                tested += 1
                if finding:
                    # Confirmed: try with // variant too for severity upgrade
                    finding2 = _check_redirect(base_url, param, f"//{CANARY}/")
                    if finding2:
                        finding["severity"] = "high"
                        finding["title"] = finding["title"].replace("Open Redirect", "Open Redirect (protocol-relative bypass)")
                    seen_params.add(param)
                    findings.append(finding)
                    break  # Found one, move to next base_url

            # Phase 2: check for redirect chains
            findings.extend(_discover_existing_redirects(base_url))
            break  # Only need one base_url for chain detection

        result["tested_params"] = REDIRECT_PARAMS
        result["tested_urls"] = tested

        # Scoring
        vuln_count = sum(1 for f in findings if f["severity"] in ("medium", "high"))
        score = 100
        for f in findings:
            if f["severity"] == "high":
                score -= 40
            elif f["severity"] == "medium":
                score -= 25
            elif f["severity"] == "low":
                score -= 10
        score = max(0, score)

        result["summary"]["score"] = score
        result["summary"]["vulnerable_params"] = vuln_count
        result["summary"]["status"] = "vulnerable" if vuln_count > 0 else "clean"
        result["findings"] = findings
        return result
