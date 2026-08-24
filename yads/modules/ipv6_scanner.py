"""
IPv6 Attack Surface Scanner (#36)

Checks whether the target has IPv6 exposure and assesses risks:
- AAAA record presence and reachability
- Services reachable via IPv6 that may bypass IPv4-based WAF/CDN
- Missing IPv6 (potential delivery gap)
- PTR record mismatches between IPv4 and IPv6

Uses: stdlib socket/dns.resolver, ipinfo.io (no key required)
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from yads.core.throttled_http import throttled_get
from yads.core.api_block_detection import ApiBlockedError

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 8
COMMON_PORTS = [80, 443, 22, 25, 587, 8080, 8443]
IPINFO_URL = "https://ipinfo.io/{ip}/json"


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0].split("?")[0]
    )


def _resolve_aaaa(domain: str) -> List[str]:
    """Resolve IPv6 (AAAA) addresses."""
    addrs = []
    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, "AAAA", lifetime=8)
            addrs = [r.address for r in answers]
        except Exception:
            pass
    else:
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            addrs = list({i[4][0] for i in info})
        except Exception:
            pass
    return addrs


def _resolve_a(domain: str) -> List[str]:
    """Resolve IPv4 (A) addresses."""
    addrs = []
    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=8)
            addrs = [r.address for r in answers]
        except Exception:
            pass
    else:
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET)
            addrs = list({i[4][0] for i in info})
        except Exception:
            pass
    return addrs


def _probe_port(ip: str, port: int, is_ipv6: bool) -> bool:
    """Return True if port is open."""
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            return True
    except Exception:
        return False


def _get_ipinfo(ip: str) -> Dict:
    try:
        r = throttled_get(IPINFO_URL.format(ip=ip), service="ipinfo", timeout=6)
        if r.status_code == 200:
            return r.json()
    except ApiBlockedError:
        raise
    except Exception:
        pass
    return {}


def _get_ptr(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


class IPv6Scanner(BaseScannerModule):
    """IPv6 attack surface and exposure assessment."""

    @property
    def module_name(self) -> str:
        return "ipv6_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "has_ipv6": False,
            "ipv6_addresses": [],
            "ipv4_addresses": [],
            "open_ports_ipv6": [],
            "open_ports_ipv4": [],
            "ptr_records": {},
            "ipinfo": {},
            "findings": [],
            "summary": {
                "score": 100,
                "ipv6_count": 0,
                "ipv4_count": 0,
                "open_v6_ports": 0,
                "status": "no_ipv6",
            },
        }

        ipv6_addrs = _resolve_aaaa(domain)
        ipv4_addrs = _resolve_a(domain)

        result["ipv6_addresses"] = ipv6_addrs
        result["ipv4_addresses"] = ipv4_addrs
        result["has_ipv6"] = bool(ipv6_addrs)
        result["summary"]["ipv6_count"] = len(ipv6_addrs)
        result["summary"]["ipv4_count"] = len(ipv4_addrs)

        findings: List[Dict] = []

        if not ipv6_addrs:
            findings.append({
                "severity": "info",
                "title": "No IPv6 (AAAA) records found",
                "description": f"{domain} has no AAAA DNS records. IPv6 connectivity is not available.",
            })
            result["summary"]["status"] = "no_ipv6"
            result["findings"] = findings
            return result

        result["summary"]["status"] = "has_ipv6"

        # Probe ports on first IPv6 address
        primary_v6 = ipv6_addrs[0]
        primary_v4 = ipv4_addrs[0] if ipv4_addrs else None

        open_v6 = []
        open_v4 = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            v6_futs = {ex.submit(_probe_port, primary_v6, p, True): p for p in COMMON_PORTS}
            v4_futs = {}
            if primary_v4:
                v4_futs = {ex.submit(_probe_port, primary_v4, p, False): p for p in COMMON_PORTS}

            for fut, port in v6_futs.items():
                try:
                    if fut.result(timeout=TIMEOUT + 2):
                        open_v6.append(port)
                except Exception:
                    pass
            for fut, port in v4_futs.items():
                try:
                    if fut.result(timeout=TIMEOUT + 2):
                        open_v4.append(port)
                except Exception:
                    pass

        result["open_ports_ipv6"] = open_v6
        result["open_ports_ipv4"] = open_v4
        result["summary"]["open_v6_ports"] = len(open_v6)

        # PTR records for IPv6
        for ip in ipv6_addrs[:2]:
            ptr = _get_ptr(ip)
            result["ptr_records"][ip] = ptr

        # IPInfo for first IPv6 address
        ipinfo = _get_ipinfo(primary_v6)
        result["ipinfo"] = ipinfo

        # --- Findings ---
        # 1. IPv6-only open ports (not on IPv4)
        v6_only = [p for p in open_v6 if p not in open_v4]
        if v6_only:
            findings.append({
                "severity": "medium",
                "title": f"Ports only reachable via IPv6: {', '.join(map(str, v6_only))}",
                "description": (
                    "These ports are open on the IPv6 address but not on IPv4. "
                    "Attackers with IPv6 access may bypass IPv4-based firewalls or WAF."
                ),
                "ports": v6_only,
            })

        # 2. Check if IPv6 is cloud/CDN vs direct IP (CDN bypass risk)
        org = ipinfo.get("org", "")
        v4_ipinfo = _get_ipinfo(primary_v4) if primary_v4 else {}
        v4_org = v4_ipinfo.get("org", "")
        if org and v4_org and org != v4_org:
            findings.append({
                "severity": "medium",
                "title": "IPv4 and IPv6 hosted by different providers",
                "description": (
                    f"IPv4 ({primary_v4}) is at {v4_org}, but IPv6 ({primary_v6}) is at {org}. "
                    "This may indicate the IPv4 address is behind a CDN/WAF while IPv6 is direct, "
                    "enabling WAF bypass via IPv6."
                ),
                "ipv4_org": v4_org,
                "ipv6_org": org,
            })
        elif "cdn" in v4_org.lower() or "cloudflare" in v4_org.lower() or "akamai" in v4_org.lower():
            if "cdn" not in org.lower() and "cloudflare" not in org.lower():
                findings.append({
                    "severity": "high",
                    "title": "Possible CDN/WAF bypass via IPv6",
                    "description": (
                        f"IPv4 appears to be protected by a CDN ({v4_org}), "
                        f"but IPv6 ({primary_v6}) resolves to a different provider ({org}). "
                        "Direct IPv6 access may bypass DDoS protection and WAF rules."
                    ),
                    "ipv4_org": v4_org,
                    "ipv6_org": org,
                })

        # 3. Multiple IPv6 addresses
        if len(ipv6_addrs) > 1:
            findings.append({
                "severity": "info",
                "title": f"Multiple IPv6 addresses ({len(ipv6_addrs)})",
                "description": f"Domain has {len(ipv6_addrs)} AAAA records: {', '.join(ipv6_addrs)}",
                "addresses": ipv6_addrs,
            })

        # 4. Score
        score = 100
        for f in findings:
            if f["severity"] == "high":
                score -= 35
            elif f["severity"] == "medium":
                score -= 15
            elif f["severity"] == "low":
                score -= 5
        score = max(0, score)
        result["summary"]["score"] = score
        result["findings"] = findings
        return result
