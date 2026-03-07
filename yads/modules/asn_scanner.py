"""
ASN / IP Range Discovery Scanner (#5)

Discovers the Autonomous System Number (ASN) and IP ranges associated
with a target domain. Useful for:
- Understanding the full IP footprint of an organization
- Discovering cloud provider / hosting infrastructure
- Mapping IP ranges for broader reconnaissance
- Identifying IP space that may host additional assets

Data sources:
  - ipinfo.io (free tier: ASN, org, prefix)
  - RIPE Stat (ASN details, prefixes announced)
  - BGP.he.net / Team Cymru style lookup via DNS
  - Shodan host lookup (if API key configured)
"""

import logging
import socket
from typing import Any, Dict, List, Optional, Set

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
IPINFO_URL = "https://ipinfo.io/{ip}/json"
RIPE_NETWORK_INFO = "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
RIPE_ASN_INFO = "https://stat.ripe.net/data/as-overview/data.json?resource={asn}"
RIPE_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
BGPVIEW_ASN = "https://api.bgpview.io/asn/{asn}/prefixes"


def _clean_domain(target: str) -> str:
    return (
        target.lower().strip()
        .removeprefix("https://").removeprefix("http://")
        .split("/")[0]
    )


def _resolve_ips(domain: str) -> List[str]:
    try:
        info = socket.getaddrinfo(domain, None)
        return list({i[4][0] for i in info if ":" not in i[4][0]})  # IPv4 only
    except Exception:
        return []


def _ipinfo(ip: str) -> Dict:
    try:
        r = requests.get(IPINFO_URL.format(ip=ip), timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _ripe_network_info(ip: str) -> Dict:
    try:
        r = requests.get(RIPE_NETWORK_INFO.format(ip=ip), timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "asns": data.get("asns", []),
                "prefix": data.get("prefix", ""),
            }
    except Exception:
        pass
    return {}


def _ripe_asn_overview(asn: str) -> Dict:
    """Fetch ASN name, holder, country via RIPE Stat."""
    try:
        r = requests.get(RIPE_ASN_INFO.format(asn=asn), timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "holder": data.get("holder", ""),
                "name": data.get("block", {}).get("name", ""),
                "country": data.get("block", {}).get("country", ""),
                "description": data.get("block", {}).get("description", ""),
            }
    except Exception:
        pass
    return {}


def _ripe_prefixes(asn: str) -> List[str]:
    """Get all prefixes announced by an ASN."""
    try:
        r = requests.get(RIPE_PREFIXES.format(asn=asn), timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return [p.get("prefix", "") for p in data.get("prefixes", []) if p.get("prefix")]
    except Exception:
        pass
    return []


def _bgpview_prefixes(asn_num: str) -> List[Dict]:
    """Alternative prefix source via BGPView."""
    try:
        r = requests.get(BGPVIEW_ASN.format(asn=asn_num), timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json().get("data", {})
            result = []
            for p in data.get("ipv4_prefixes", []):
                result.append({
                    "prefix": p.get("prefix", ""),
                    "name": p.get("name", ""),
                    "description": p.get("description", ""),
                    "country": p.get("country_code", ""),
                })
            return result
    except Exception:
        pass
    return []


class AsnScanner(BaseScannerModule):
    """ASN and IP range discovery for an organization."""

    @property
    def module_name(self) -> str:
        return "asn_scanner"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = _clean_domain(target)

        result: Dict[str, Any] = {
            "domain": domain,
            "ips": [],
            "asns": [],
            "prefixes": [],
            "prefixes_detail": [],
            "total_ips_estimated": 0,
            "findings": [],
            "summary": {
                "score": 100,
                "asn_count": 0,
                "prefix_count": 0,
                "hosting_providers": [],
            },
        }

        ips = _resolve_ips(domain)
        if not ips:
            result["error"] = "Domain did not resolve to any IPv4 address"
            return result

        result["ips"] = ips
        findings: List[Dict] = []

        all_asns: Set[str] = set()
        all_prefixes: Set[str] = set()
        providers: Set[str] = set()

        for ip in ips[:3]:  # Check up to 3 IPs
            # ipinfo.io
            info = _ipinfo(ip)
            asn_raw = info.get("org", "")  # e.g. "AS15169 Google LLC"
            country = info.get("country", "")
            city = info.get("city", "")
            hostname = info.get("hostname", "")

            if asn_raw:
                parts = asn_raw.split(" ", 1)
                asn_num = parts[0].lstrip("AS") if parts else ""
                asn_name = parts[1] if len(parts) > 1 else asn_raw
                all_asns.add(parts[0] if parts else asn_raw)
                providers.add(asn_name)

                if asn_num and parts[0].startswith("AS"):
                    # RIPE network info
                    net_info = _ripe_network_info(ip)
                    prefix = net_info.get("prefix", info.get("org", "").split()[0] if info.get("org") else "")
                    if prefix:
                        all_prefixes.add(prefix)

                    # Get all prefixes for this ASN
                    asn_prefixes = _ripe_prefixes(parts[0])
                    for p in asn_prefixes:
                        all_prefixes.add(p)

                    # BGPView for detailed prefix info
                    detail_prefixes = _bgpview_prefixes(asn_num)
                    if detail_prefixes:
                        result["prefixes_detail"].extend(detail_prefixes)

                    result["asns"].append({
                        "asn": parts[0],
                        "name": asn_name,
                        "country": country,
                        "city": city,
                        "ip": ip,
                        "hostname": hostname,
                        "prefix": prefix,
                    })

        result["prefixes"] = sorted(all_prefixes)
        result["summary"]["asn_count"] = len(all_asns)
        result["summary"]["prefix_count"] = len(all_prefixes)
        result["summary"]["hosting_providers"] = sorted(providers)

        # Estimate total IPs (rough: /24 = 256, /16 = 65536)
        total_est = 0
        for p in all_prefixes:
            try:
                mask = int(p.split("/")[1])
                total_est += 2 ** (32 - mask)
            except Exception:
                pass
        result["total_ips_estimated"] = total_est

        # --- Findings ---
        if len(all_asns) > 1:
            findings.append({
                "severity": "info",
                "title": f"Multiple ASNs ({len(all_asns)}): {', '.join(sorted(all_asns))}",
                "description": "The domain resolves to IPs belonging to different Autonomous Systems. "
                               "This may indicate multi-cloud or multi-provider hosting.",
                "asns": sorted(all_asns),
            })
        elif all_asns:
            asn = list(all_asns)[0]
            findings.append({
                "severity": "info",
                "title": f"Hosted on {asn} ({', '.join(sorted(providers))})",
                "description": f"The domain resolves to IP space owned by {asn}. "
                               f"Identified {len(all_prefixes)} announced prefix(es) with "
                               f"approximately {total_est:,} total IPs in this ASN.",
                "asn": asn,
                "prefix_count": len(all_prefixes),
            })

        if total_est > 10000:
            findings.append({
                "severity": "info",
                "title": f"Large IP range: ~{total_est:,} IPs in announced prefixes",
                "description": f"The ASN announces prefixes covering approximately {total_est:,} IP addresses. "
                               "This is normal for cloud providers but may indicate a large enterprise footprint.",
            })

        # Cloud/CDN detection
        cloud_keywords = ["amazon", "google", "microsoft", "azure", "cloudflare",
                          "akamai", "fastly", "cloudfront", "digitalocean", "linode",
                          "vultr", "hetzner", "ovh"]
        detected_cloud = [k for k in cloud_keywords
                          if any(k in p.lower() for p in providers)]
        if detected_cloud:
            findings.append({
                "severity": "info",
                "title": f"Cloud/CDN provider: {', '.join(detected_cloud)}",
                "description": f"The domain appears to be hosted on or protected by cloud infrastructure: "
                               f"{', '.join(sorted(providers))}",
                "providers": sorted(providers),
            })

        result["findings"] = findings
        result["summary"]["score"] = 100  # Informational scanner
        return result
