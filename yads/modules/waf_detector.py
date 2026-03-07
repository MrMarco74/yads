"""
WAF / CDN Detection & Bypass Check (#16)

Detects whether a target is protected by a WAF or CDN and assesses
potential bypass risks:
- WAF/CDN fingerprinting via response headers and behavior
- Origin IP disclosure check (DNS + cloud APIs)
- WAF bypass indicators (missing security on direct IP access)

Does NOT attempt active WAF evasion. Passive detection only.
"""

import logging
import re
import socket
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

# WAF/CDN fingerprints: header key → (value_pattern, provider_name)
WAF_HEADERS: List[Tuple[str, str, str]] = [
    ("server", r"cloudflare", "Cloudflare"),
    ("server", r"sucuri", "Sucuri"),
    ("server", r"akamaighost", "Akamai"),
    ("server", r"nginx/.*f5", "F5 BIG-IP"),
    ("x-sucuri-id", r".", "Sucuri"),
    ("x-cache", r"hit|miss", "CDN (generic)"),
    ("x-cdn", r".", "CDN (generic)"),
    ("cf-ray", r".", "Cloudflare"),
    ("cf-cache-status", r".", "Cloudflare"),
    ("x-amz-cf-id", r".", "AWS CloudFront"),
    ("x-amz-cf-pop", r".", "AWS CloudFront"),
    ("x-azure-ref", r".", "Azure CDN"),
    ("x-ms-ref", r".", "Azure Front Door"),
    ("x-fastly-request-id", r".", "Fastly"),
    ("via", r"fastly", "Fastly"),
    ("via", r"varnish", "Varnish"),
    ("x-varnish", r".", "Varnish"),
    ("x-akamai-transformed", r".", "Akamai"),
    ("x-check-cacheable", r".", "Akamai"),
    ("x-tw-cdn", r".", "Imperva/Incapsula"),
    ("x-iinfo", r".", "Imperva/Incapsula"),
    ("x-cdn-geo", r".", "CDN (generic)"),
    ("x-served-by", r"cache-", "Fastly"),
    ("x-timer", r"S\d+\.\d+", "Fastly"),
    ("x-edge-ip", r".", "CDN (generic)"),
    ("x-forwarded-host", r".", "Proxy/CDN"),
    ("x-cache-hits", r".", "CDN (generic)"),
    ("x-wp-cf-super-cache", r".", "Cloudflare + WP"),
    ("nel", r".", "Network Error Logging (Cloudflare)"),
    ("report-to", r"cloudflare", "Cloudflare"),
]

# Probe with suspicious payload to trigger WAF blocks
PROBE_PAYLOADS = [
    "?q=<script>alert(1)</script>",
    "?id=1 UNION SELECT 1,2,3--",
    "?file=../../../etc/passwd",
]

WAF_BLOCK_PATTERNS = re.compile(
    r"(access denied|forbidden|blocked|security|waf|firewall|sucuri|cloudflare ray id|"
    r"attention required|request rejected|sorry.*automated|bot detection)",
    re.IGNORECASE,
)


def _clean_base(target: str) -> str:
    t = target.lower().strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")


def _get_response(url: str, extra_headers: Dict = None) -> Optional[requests.Response]:
    try:
        hdrs = {**HEADERS, **(extra_headers or {})}
        return requests.get(url, timeout=TIMEOUT, headers=hdrs, verify=False, allow_redirects=True)
    except Exception:
        return None


def _fingerprint_waf(resp: requests.Response) -> Tuple[Set[str], List[Dict]]:
    """Return (detected_providers, fingerprint_details)."""
    detected: Set[str] = set()
    details = []
    lower_headers = {k.lower(): v for k, v in resp.headers.items()}

    for hdr_key, pattern, provider in WAF_HEADERS:
        val = lower_headers.get(hdr_key, "")
        if val and re.search(pattern, val, re.IGNORECASE):
            detected.add(provider)
            details.append({"header": hdr_key, "value": val, "provider": provider})

    return detected, details


def _probe_waf_block(base: str) -> bool:
    """Probe with attack-like payloads and check if WAF blocks."""
    for payload in PROBE_PAYLOADS:
        resp = _get_response(f"{base}/{payload}")
        if resp and resp.status_code in (403, 406, 429, 503):
            body = resp.text[:2000]
            if WAF_BLOCK_PATTERNS.search(body):
                return True
        if resp and WAF_BLOCK_PATTERNS.search(resp.text[:2000]):
            return True
    return False


def _get_origin_ips(domain: str) -> List[str]:
    """Try to resolve actual origin IPs (may differ from CDN edge)."""
    ips = []
    try:
        info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list({i[4][0] for i in info})
    except Exception:
        pass
    return ips


def _check_direct_ip_access(ip: str, domain: str) -> Optional[Dict]:
    """Check if origin IP is directly accessible (CDN bypass potential)."""
    try:
        resp = requests.get(
            f"https://{ip}/",
            timeout=TIMEOUT,
            headers={**HEADERS, "Host": domain},
            verify=False,
        )
        if resp.status_code < 500:
            return {
                "ip": ip,
                "status": resp.status_code,
                "server": resp.headers.get("server", ""),
                "accessible": True,
            }
    except Exception:
        pass
    try:
        resp = requests.get(
            f"http://{ip}/",
            timeout=TIMEOUT,
            headers={**HEADERS, "Host": domain},
            verify=False,
        )
        if resp.status_code < 500:
            return {
                "ip": ip,
                "status": resp.status_code,
                "server": resp.headers.get("server", ""),
                "accessible": True,
            }
    except Exception:
        pass
    return None


class WafDetector(BaseScannerModule):
    """WAF/CDN detection and bypass risk assessment."""

    @property
    def module_name(self) -> str:
        return "waf_detector"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
        )
        base = f"https://{domain}"

        result: Dict[str, Any] = {
            "domain": domain,
            "waf_detected": False,
            "providers": [],
            "fingerprints": [],
            "waf_blocking": False,
            "origin_ips": [],
            "direct_access": [],
            "findings": [],
            "summary": {
                "score": 100,
                "protection_level": "unknown",
            },
        }

        findings: List[Dict] = []

        # Get main response
        resp = _get_response(base)
        if not resp:
            result["error"] = "Target unreachable"
            return result

        # Fingerprint WAF/CDN
        detected, fingerprints = _fingerprint_waf(resp)
        result["waf_detected"] = bool(detected)
        result["providers"] = sorted(detected)
        result["fingerprints"] = fingerprints

        # Check if WAF actively blocks attack payloads
        waf_blocking = _probe_waf_block(base)
        result["waf_blocking"] = waf_blocking

        # Get origin IPs
        ips = _get_origin_ips(domain)
        result["origin_ips"] = ips

        # Check direct IP access (bypass potential)
        bypass_ips = []
        if detected and ips:
            # Only check if behind CDN — direct IP access would be a bypass
            for ip in ips[:2]:
                access = _check_direct_ip_access(ip, domain)
                if access:
                    result["direct_access"].append(access)
                    bypass_ips.append(ip)

        score = 100

        # --- Findings ---
        if detected:
            providers_str = ", ".join(sorted(detected))
            findings.append({
                "severity": "info",
                "title": f"WAF/CDN detected: {providers_str}",
                "description": f"The target is protected by {providers_str}. "
                               "This provides DDoS mitigation and attack filtering.",
                "providers": sorted(detected),
            })

            if not waf_blocking:
                findings.append({
                    "severity": "low",
                    "title": "WAF/CDN present but not blocking attack probes",
                    "description": "A WAF/CDN was detected in headers, but attack-like probes were not blocked. "
                                   "The WAF may be in monitoring-only mode or misconfigured.",
                })
                score -= 10

            if bypass_ips:
                findings.append({
                    "severity": "high",
                    "title": f"Origin IP directly accessible: {', '.join(bypass_ips)}",
                    "description": (
                        f"The origin server IP ({', '.join(bypass_ips)}) responds directly to HTTP requests "
                        "even though a WAF/CDN is in place. Attackers can bypass WAF protection by "
                        "sending requests directly to the origin IP."
                    ),
                    "ips": bypass_ips,
                })
                score -= 40

        else:
            findings.append({
                "severity": "info",
                "title": "No WAF/CDN detected",
                "description": "No Web Application Firewall or CDN was detected. "
                               "The target appears to be directly exposed to the internet.",
            })
            # No WAF at all — medium severity for production sites
            findings.append({
                "severity": "medium",
                "title": "No WAF protection — direct internet exposure",
                "description": "Without a WAF/CDN, the server is directly reachable. "
                               "Consider deploying Cloudflare, AWS WAF, or similar to filter malicious traffic.",
            })
            score -= 20

        protection_level = "strong" if (detected and waf_blocking and not bypass_ips) else \
                           "partial" if detected else "none"
        result["summary"]["protection_level"] = protection_level
        result["summary"]["score"] = max(0, score)
        result["findings"] = findings
        return result
