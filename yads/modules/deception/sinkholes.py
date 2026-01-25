"""
DNS Sinkhole Detection

Detects domains redirected to sinkhole infrastructure using:
- Known sinkhole IP database
- ASN matching
- Landing page analysis
"""

import re
import socket
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

import requests
import dns.resolver

logger = logging.getLogger("yads.deception.sinkholes")


# =============================================================================
# Sinkhole Database
# =============================================================================

# Known sinkhole IPs and their operators
SINKHOLE_IPS: Dict[str, Dict[str, Any]] = {
    # Spamhaus DROP/SBL indicators (returned by DNSBL queries)
    "127.0.0.2": {"operator": "Spamhaus", "type": "SBL", "confidence": 95},
    "127.0.0.3": {"operator": "Spamhaus", "type": "SBL-CSS", "confidence": 95},
    "127.0.0.4": {"operator": "Spamhaus", "type": "XBL", "confidence": 90},
    "127.0.0.9": {"operator": "Spamhaus", "type": "DROP", "confidence": 95},
    "127.0.0.10": {"operator": "Spamhaus", "type": "PBL", "confidence": 85},
    "127.0.0.11": {"operator": "Spamhaus", "type": "PBL", "confidence": 85},

    # Common sinkhole/blocklist responses
    "0.0.0.0": {"operator": "Local Block", "type": "null-route", "confidence": 90},
    "127.0.0.1": {"operator": "Local Block", "type": "localhost", "confidence": 85},

    # Known research sinkholes (examples - should be updated regularly)
    "64.120.137.52": {"operator": "Shadowserver", "type": "research", "confidence": 85},
    "87.255.51.229": {"operator": "Shadowserver", "type": "research", "confidence": 85},

    # Microsoft DCU takedowns (examples)
    "52.179.17.38": {"operator": "Microsoft DCU", "type": "takedown", "confidence": 90},

    # FBI/Law enforcement (examples - these change frequently)
    "199.168.220.15": {"operator": "FBI", "type": "seizure", "confidence": 95},
}

# Known sinkhole IP ranges (CIDR notation)
SINKHOLE_RANGES: List[Dict[str, Any]] = [
    # Shadowserver ranges
    {"range": "64.120.137.0/24", "operator": "Shadowserver", "confidence": 80},
    {"range": "87.255.51.0/24", "operator": "Shadowserver", "confidence": 80},

    # Example research institution ranges
    {"range": "192.0.2.0/24", "operator": "Documentation/Test", "confidence": 70},
]

# Known sinkhole ASNs
SINKHOLE_ASNS: Dict[str, Dict[str, Any]] = {
    "AS30823": {"operator": "Spamhaus", "confidence": 75},
    "AS8075": {"operator": "Microsoft", "confidence": 60},  # Could be legitimate
    "AS14618": {"operator": "Amazon AWS", "confidence": 30},  # Often used for sinkholes
}

# Sinkhole landing page patterns
SINKHOLE_LANDING_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"This domain has been seized",
        "operator": "Law Enforcement",
        "confidence": 95,
    },
    {
        "pattern": r"seized by the FBI",
        "operator": "FBI",
        "confidence": 98,
    },
    {
        "pattern": r"Department of Justice",
        "operator": "DOJ",
        "confidence": 95,
    },
    {
        "pattern": r"sinkhole[d]?\s*(by|domain)",
        "operator": "Generic Sinkhole",
        "confidence": 90,
    },
    {
        "pattern": r"blocked by your (ISP|Internet Service Provider)",
        "operator": "ISP Block",
        "confidence": 85,
    },
    {
        "pattern": r"malware.*blocked|blocked.*malware",
        "operator": "Security Block",
        "confidence": 80,
    },
    {
        "pattern": r"phishing.*blocked|blocked.*phishing",
        "operator": "Security Block",
        "confidence": 80,
    },
    {
        "pattern": r"This (site|domain|website) (has been|is) (blocked|suspended)",
        "operator": "Generic Block",
        "confidence": 75,
    },
    {
        "pattern": r"Shadowserver Foundation",
        "operator": "Shadowserver",
        "confidence": 95,
    },
    {
        "pattern": r"Microsoft Digital Crimes Unit",
        "operator": "Microsoft DCU",
        "confidence": 95,
    },
    {
        "pattern": r"ICANN|Registrar.*suspend",
        "operator": "Registrar Suspension",
        "confidence": 70,
    },
]

# Known sinkhole hostnames
SINKHOLE_HOSTNAMES: Dict[str, Dict[str, Any]] = {
    "sinkhole.tech": {"operator": "Generic", "confidence": 95},
    "sinkhole.ru": {"operator": "Generic", "confidence": 95},
    "blackhole.": {"operator": "Generic", "confidence": 90},
    ".sinkhole.": {"operator": "Generic", "confidence": 90},
}


@dataclass
class SinkholeDetection:
    """Represents a sinkhole detection result."""
    domain: str
    sinkhole_ip: str
    sinkhole_operator: str
    confidence: int
    risk_level: str
    indicator: str
    detection_type: str  # "ip_match", "asn_match", "landing_page", "hostname"
    details: Dict[str, Any] = field(default_factory=dict)


class SinkholeDetector:
    """Detects DNS sinkholes through multiple techniques."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._dns_resolver = dns.resolver.Resolver()
        self._dns_resolver.timeout = timeout
        self._dns_resolver.lifetime = timeout

    def detect(self, domain: str) -> List[SinkholeDetection]:
        """
        Run all sinkhole detection techniques on a domain.

        Args:
            domain: The domain to check.

        Returns:
            List of SinkholeDetection objects.
        """
        detections = []

        # Resolve domain IP
        try:
            ip = self._resolve_domain(domain)
            if not ip:
                return detections
        except Exception as e:
            logger.debug(f"Could not resolve {domain}: {e}")
            return detections

        # Check against known sinkhole IPs
        ip_detection = self.check_known_sinkhole_ip(domain, ip)
        if ip_detection:
            detections.append(ip_detection)

        # Check hostname patterns
        hostname_detection = self.check_sinkhole_hostname(domain)
        if hostname_detection:
            detections.append(hostname_detection)

        # Check landing page (only if IP detected or hostname suspicious)
        if detections or self._is_suspicious_ip(ip):
            landing_detection = self.check_landing_page(domain, ip)
            if landing_detection:
                detections.append(landing_detection)

        return detections

    def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            answers = self._dns_resolver.resolve(domain, 'A')
            if answers:
                return str(answers[0])
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
        except dns.resolver.NoAnswer:
            logger.debug(f"No A record for {domain}")
        except Exception as e:
            logger.debug(f"DNS resolution error for {domain}: {e}")
        return None

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP looks suspicious (private, localhost, etc.)."""
        suspicious_prefixes = ["0.", "127.", "10.", "192.168.", "172.16."]
        return any(ip.startswith(prefix) for prefix in suspicious_prefixes)

    def check_known_sinkhole_ip(self, domain: str, ip: str) -> Optional[SinkholeDetection]:
        """Check if IP is in the known sinkhole database."""
        if ip in SINKHOLE_IPS:
            info = SINKHOLE_IPS[ip]
            return SinkholeDetection(
                domain=domain,
                sinkhole_ip=ip,
                sinkhole_operator=info["operator"],
                confidence=info["confidence"],
                risk_level=self._calculate_risk(info["confidence"]),
                indicator=f"Known sinkhole IP: {ip}",
                detection_type="ip_match",
                details={"type": info.get("type", "unknown")}
            )

        # Check IP ranges
        for range_info in SINKHOLE_RANGES:
            if self._ip_in_range(ip, range_info["range"]):
                return SinkholeDetection(
                    domain=domain,
                    sinkhole_ip=ip,
                    sinkhole_operator=range_info["operator"],
                    confidence=range_info["confidence"],
                    risk_level=self._calculate_risk(range_info["confidence"]),
                    indicator=f"IP in sinkhole range: {range_info['range']}",
                    detection_type="ip_range_match",
                    details={"range": range_info["range"]}
                )

        return None

    def _ip_in_range(self, ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

    def check_sinkhole_hostname(self, domain: str) -> Optional[SinkholeDetection]:
        """Check if domain hostname matches known sinkhole patterns."""
        domain_lower = domain.lower()

        for pattern, info in SINKHOLE_HOSTNAMES.items():
            if pattern in domain_lower:
                return SinkholeDetection(
                    domain=domain,
                    sinkhole_ip="",
                    sinkhole_operator=info["operator"],
                    confidence=info["confidence"],
                    risk_level=self._calculate_risk(info["confidence"]),
                    indicator=f"Sinkhole hostname pattern: {pattern}",
                    detection_type="hostname",
                    details={"pattern": pattern}
                )

        return None

    def check_landing_page(self, domain: str, ip: str) -> Optional[SinkholeDetection]:
        """Check if domain serves a sinkhole landing page."""
        try:
            # Try HTTPS first, then HTTP
            for protocol in ["https", "http"]:
                try:
                    url = f"{protocol}://{domain}/"
                    response = requests.get(
                        url,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True,
                        headers={"User-Agent": "YADS-Security-Scanner/1.15.0"}
                    )

                    content = response.text.lower()

                    for pattern_info in SINKHOLE_LANDING_PATTERNS:
                        if re.search(pattern_info["pattern"], content, re.IGNORECASE):
                            return SinkholeDetection(
                                domain=domain,
                                sinkhole_ip=ip,
                                sinkhole_operator=pattern_info["operator"],
                                confidence=pattern_info["confidence"],
                                risk_level=self._calculate_risk(pattern_info["confidence"]),
                                indicator=f"Sinkhole landing page detected",
                                detection_type="landing_page",
                                details={
                                    "pattern": pattern_info["pattern"],
                                    "url": url
                                }
                            )

                    # If we got a response, no need to try HTTP
                    break

                except requests.exceptions.SSLError:
                    continue
                except requests.exceptions.ConnectionError:
                    continue

        except Exception as e:
            logger.debug(f"Error checking landing page for {domain}: {e}")

        return None

    def check_asn(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check if IP's ASN is associated with sinkhole operators."""
        # This would require an ASN lookup service
        # For now, return None - can be implemented with ipwhois or similar
        return None

    def _calculate_risk(self, confidence: int) -> str:
        """Calculate risk level from confidence score."""
        if confidence >= 80:
            return "high"
        elif confidence >= 60:
            return "medium"
        else:
            return "low"

    def check_multiple_domains_same_ip(
        self,
        domains: List[str],
        ip: str,
        threshold: int = 10
    ) -> Optional[SinkholeDetection]:
        """
        Check if many unrelated domains resolve to the same IP.

        This is a common indicator of sinkholing.
        """
        if len(domains) >= threshold:
            return SinkholeDetection(
                domain=", ".join(domains[:5]) + f"... ({len(domains)} total)",
                sinkhole_ip=ip,
                sinkhole_operator="Unknown",
                confidence=60 + min(30, len(domains)),
                risk_level="medium" if len(domains) < 50 else "high",
                indicator=f"{len(domains)} domains resolve to same IP",
                detection_type="shared_ip",
                details={"domain_count": len(domains), "sample_domains": domains[:10]}
            )
        return None
