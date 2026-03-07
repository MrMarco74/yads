"""
HTTP Security Headers Analyzer (Task #2)
==========================================
Checks all OWASP-recommended security response headers.
No external API required — pure HTTP request.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

from yads.core.base import BaseScannerModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

TIMEOUT = 8

# (header_name, severity_if_missing, recommendation)
SECURITY_HEADERS: List[Tuple[str, str, str]] = [
    (
        "Strict-Transport-Security",
        "high",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    (
        "Content-Security-Policy",
        "high",
        "Define a Content-Security-Policy to restrict resource loading",
    ),
    (
        "X-Content-Type-Options",
        "medium",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "X-Frame-Options",
        "medium",
        "Add: X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors)",
    ),
    (
        "Referrer-Policy",
        "low",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        "low",
        "Add a Permissions-Policy header to restrict browser features",
    ),
    (
        "Cross-Origin-Opener-Policy",
        "low",
        "Add: Cross-Origin-Opener-Policy: same-origin",
    ),
    (
        "Cross-Origin-Resource-Policy",
        "low",
        "Add: Cross-Origin-Resource-Policy: same-origin",
    ),
]

LEAKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "X-Drupal-Cache",
    "X-WordPress-Cache",
]

HSTS_MIN_AGE = 15_552_000  # 6 months


class HTTPHeadersScanner(BaseScannerModule):
    @property
    def module_name(self) -> str:
        return "http_headers"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[HTTPHeaders] Starting for {target}")

        headers_data, url_used = self._fetch_headers(target)
        if headers_data is None:
            return {
                "url": url_used,
                "reachable": False,
                "headers": {},
                "findings": [{"header": "N/A", "severity": "info", "issue": "Target not reachable over HTTP/HTTPS"}],
                "leaky_headers": {},
                "score": 0,
            }

        findings = self._analyze(headers_data)
        leaky = self._check_leaky(headers_data)
        score = self._score(headers_data, findings)

        logger.info(f"[HTTPHeaders] Done for {target} — score {score}/100, {len(findings)} issues")
        return {
            "url": url_used,
            "reachable": True,
            "headers": {k.lower(): v for k, v in headers_data.items()},
            "findings": findings,
            "leaky_headers": leaky,
            "score": score,
        }

    def _fetch_headers(self, target: str):
        session = requests.Session()
        session.headers["User-Agent"] = "YADS-HeaderBot/1.0"
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}/"
            try:
                resp = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
                return dict(resp.headers), url
            except Exception:
                continue
        return None, f"https://{target}/"

    def _analyze(self, headers: Dict[str, str]) -> List[Dict]:
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, severity, recommendation in SECURITY_HEADERS:
            hl = header_name.lower()
            present = hl in headers_lower
            value = headers_lower.get(hl, "")
            issues = []

            if not present:
                findings.append({
                    "header": header_name,
                    "severity": severity,
                    "issue": f"Missing header: {header_name}",
                    "recommendation": recommendation,
                    "value": None,
                })
                continue

            # Additional checks per header
            if hl == "strict-transport-security":
                issues += self._check_hsts(value)
            elif hl == "x-frame-options":
                if value.upper() not in ("DENY", "SAMEORIGIN"):
                    issues.append(f"X-Frame-Options value '{value}' is not recommended (use DENY or SAMEORIGIN)")
            elif hl == "x-content-type-options":
                if value.lower() != "nosniff":
                    issues.append(f"X-Content-Type-Options should be 'nosniff', got '{value}'")
            elif hl == "referrer-policy":
                unsafe = ("unsafe-url", "no-referrer-when-downgrade")
                if value.lower() in unsafe:
                    issues.append(f"Referrer-Policy '{value}' leaks full URL to third parties")

            for issue in issues:
                findings.append({
                    "header": header_name,
                    "severity": "medium",
                    "issue": issue,
                    "recommendation": recommendation,
                    "value": value,
                })

        return findings

    def _check_hsts(self, value: str) -> List[str]:
        issues = []
        parts = [p.strip().lower() for p in value.split(";")]
        max_age = None
        for part in parts:
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    issues.append("HSTS max-age is not a valid integer")
        if max_age is None:
            issues.append("HSTS missing max-age directive")
        elif max_age < HSTS_MIN_AGE:
            issues.append(f"HSTS max-age={max_age} is below recommended 6 months ({HSTS_MIN_AGE}s)")
        if "includesubdomains" not in parts:
            issues.append("HSTS missing includeSubDomains")
        return issues

    def _check_leaky(self, headers: Dict[str, str]) -> Dict[str, str]:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        return {h: headers_lower[h.lower()] for h in LEAKY_HEADERS if h.lower() in headers_lower}

    def _score(self, headers: Dict[str, str], findings: List[Dict]) -> int:
        headers_lower = {k.lower() for k in headers}
        present_count = sum(
            1 for h, _, _ in SECURITY_HEADERS if h.lower() in headers_lower
        )
        base = int((present_count / len(SECURITY_HEADERS)) * 80)
        # Deduct for high-severity issues
        high_issues = sum(1 for f in findings if f["severity"] == "high")
        return max(0, min(100, base - high_issues * 10))
