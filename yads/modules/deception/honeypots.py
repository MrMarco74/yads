"""
Honeypot Detection

Detects various types of honeypots through:
- Banner fingerprinting
- Behavioral analysis
- Response pattern matching
"""

import re
import socket
import logging
import hashlib
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .signatures import (
    match_ssh_banner,
    match_web_content,
    match_ftp_banner,
    match_smtp_banner,
    SSH_HONEYPOT_BANNERS,
    BEHAVIORAL_INDICATORS,
    check_technology_mismatch,
    TELNET_HONEYPOT_PATTERNS,
)

logger = logging.getLogger("yads.deception.honeypots")


@dataclass
class HoneypotDetection:
    """Represents a honeypot detection result."""
    type: str  # "web", "ssh", "ftp", "smtp", "telnet", "generic"
    indicator: str
    confidence: int
    risk_level: str
    port: int
    name: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


class HoneypotDetector:
    """Detects various types of honeypots through multiple techniques."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "YADS-Security-Scanner/1.15.0"
        })

    def detect_all(self, host: str, ports: List[int] = None) -> List[HoneypotDetection]:
        """
        Run all honeypot detection techniques on a host.

        Args:
            host: The target hostname or IP.
            ports: List of ports to check. If None, uses common ports.

        Returns:
            List of HoneypotDetection objects.
        """
        if ports is None:
            ports = [22, 23, 21, 25, 80, 443, 8080]

        detections = []

        # Web honeypot detection (ports 80, 443, 8080)
        web_ports = [p for p in ports if p in [80, 443, 8080, 8443]]
        for port in web_ports:
            web_detections = self.detect_web_honeypot(host, port)
            detections.extend(web_detections)

        # SSH honeypot detection (port 22)
        if 22 in ports:
            ssh_detections = self.detect_ssh_honeypot(host, 22)
            detections.extend(ssh_detections)

        # FTP honeypot detection (port 21)
        if 21 in ports:
            ftp_detections = self.detect_ftp_honeypot(host, 21)
            detections.extend(ftp_detections)

        # SMTP honeypot detection (port 25)
        if 25 in ports:
            smtp_detections = self.detect_smtp_honeypot(host, 25)
            detections.extend(smtp_detections)

        # Telnet honeypot detection (port 23)
        if 23 in ports:
            telnet_detections = self.detect_telnet_honeypot(host, 23)
            detections.extend(telnet_detections)

        return detections

    def detect_web_honeypot(self, host: str, port: int = 80) -> List[HoneypotDetection]:
        """
        Detect web-based honeypots.

        Techniques:
        - Content signature matching
        - Header analysis
        - Response consistency checks
        - Timing analysis
        """
        detections = []
        protocol = "https" if port in [443, 8443] else "http"
        base_url = f"{protocol}://{host}:{port}" if port not in [80, 443] else f"{protocol}://{host}"

        try:
            # Fetch main page
            response = self._fetch_url(base_url)
            if not response:
                return detections

            # Check content signatures
            content_matches = match_web_content(
                response.text,
                dict(response.headers)
            )

            for match in content_matches:
                detections.append(HoneypotDetection(
                    type="web",
                    indicator=match["description"],
                    confidence=match["confidence"],
                    risk_level=self._calculate_risk(match["confidence"]),
                    port=port,
                    name=match["name"],
                    details={"url": base_url}
                ))

            # Check for behavioral indicators
            behavioral_detections = self._check_web_behavioral(host, port, base_url)
            detections.extend(behavioral_detections)

            # Check content hash against known honeypot pages
            content_hash = hashlib.sha256(response.text.encode()).hexdigest()
            # This would check against WEB_HONEYPOT_CONTENT_HASHES

        except Exception as e:
            logger.debug(f"Error detecting web honeypot on {host}:{port}: {e}")

        return detections

    def _fetch_url(self, url: str) -> Optional[requests.Response]:
        """Fetch URL with error handling."""
        try:
            return self._session.get(
                url,
                timeout=self.timeout,
                verify=False,  # nosec B501 - intentional: scanner probes potentially invalid/self-signed certs
                allow_redirects=True
            )
        except Exception as e:
            logger.debug(f"Error fetching {url}: {e}")
            return None

    def _check_web_behavioral(
        self,
        host: str,
        port: int,
        base_url: str
    ) -> List[HoneypotDetection]:
        """Check for behavioral honeypot indicators."""
        detections = []

        try:
            # Test multiple paths for same response
            test_paths = [
                "/",
                "/admin",
                "/login",
                "/test123",
                f"/{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
            ]

            responses = []
            response_times = []

            for path in test_paths:
                url = f"{base_url}{path}"
                start = time.time()
                resp = self._fetch_url(url)
                elapsed = (time.time() - start) * 1000  # ms

                if resp:
                    responses.append(resp.text[:1000])  # First 1000 chars
                    response_times.append(elapsed)

            # Check for same content on all paths
            if len(set(responses)) == 1 and len(responses) >= 3:
                indicator = BEHAVIORAL_INDICATORS["same_content_all_paths"]
                detections.append(HoneypotDetection(
                    type="web",
                    indicator=indicator["description"],
                    confidence=indicator["confidence"],
                    risk_level=self._calculate_risk(indicator["confidence"]),
                    port=port,
                    name="Behavioral Anomaly",
                    details={"paths_tested": len(test_paths)}
                ))

            # Check for consistent response times
            if response_times:
                time_variance = max(response_times) - min(response_times)
                threshold = BEHAVIORAL_INDICATORS["consistent_response_time"]["threshold_ms"]

                if time_variance < threshold and len(response_times) >= 3:
                    indicator = BEHAVIORAL_INDICATORS["consistent_response_time"]
                    detections.append(HoneypotDetection(
                        type="web",
                        indicator=indicator["description"],
                        confidence=indicator["confidence"],
                        risk_level=self._calculate_risk(indicator["confidence"]),
                        port=port,
                        name="Timing Anomaly",
                        details={"time_variance_ms": time_variance}
                    ))

        except Exception as e:
            logger.debug(f"Error in behavioral check for {host}:{port}: {e}")

        return detections

    def detect_ssh_honeypot(self, host: str, port: int = 22) -> List[HoneypotDetection]:
        """
        Detect SSH honeypots through banner analysis.

        Techniques:
        - Banner fingerprinting (Cowrie, Kippo, HonSSH)
        - Version mismatch detection
        - Impossible OS/version combinations
        """
        detections = []

        try:
            banner = self._grab_banner(host, port)
            if not banner:
                return detections

            # Check against known SSH honeypot banners
            matches = match_ssh_banner(banner)

            for match in matches:
                detections.append(HoneypotDetection(
                    type="ssh",
                    indicator=match["description"],
                    confidence=match["confidence"],
                    risk_level=self._calculate_risk(match["confidence"]),
                    port=port,
                    name=match["name"],
                    details={"banner": banner}
                ))

            # Check for version anomalies
            version_detection = self._check_ssh_version_anomalies(banner)
            if version_detection:
                detections.append(version_detection)

        except Exception as e:
            logger.debug(f"Error detecting SSH honeypot on {host}:{port}: {e}")

        return detections

    def _grab_banner(self, host: str, port: int, timeout: int = None) -> Optional[str]:
        """Grab service banner from a port."""
        timeout = timeout or self.timeout

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # For SSH, the banner is sent immediately
            if port == 22:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                # For other services, may need to send something first
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

            sock.close()
            return banner

        except Exception as e:
            logger.debug(f"Error grabbing banner from {host}:{port}: {e}")
            return None

    def _check_ssh_version_anomalies(self, banner: str) -> Optional[HoneypotDetection]:
        """Check for suspicious SSH version patterns."""
        # Check for very old versions that are commonly emulated
        old_version_pattern = r"OpenSSH_[345]\.[0-9]"
        if re.search(old_version_pattern, banner):
            # This is suspicious but could be legitimate legacy system
            return HoneypotDetection(
                type="ssh",
                indicator="Outdated SSH version (commonly emulated by honeypots)",
                confidence=30,
                risk_level="low",
                port=22,
                name="Old SSH Version",
                details={"banner": banner}
            )
        return None

    def detect_ftp_honeypot(self, host: str, port: int = 21) -> List[HoneypotDetection]:
        """Detect FTP honeypots through banner analysis."""
        detections = []

        try:
            banner = self._grab_banner(host, port)
            if not banner:
                return detections

            # Check against known FTP honeypot banners
            matches = match_ftp_banner(banner)

            for match in matches:
                detections.append(HoneypotDetection(
                    type="ftp",
                    indicator=match["description"],
                    confidence=match["confidence"],
                    risk_level=self._calculate_risk(match["confidence"]),
                    port=port,
                    name=match["name"],
                    details={"banner": banner}
                ))

        except Exception as e:
            logger.debug(f"Error detecting FTP honeypot on {host}:{port}: {e}")

        return detections

    def detect_smtp_honeypot(self, host: str, port: int = 25) -> List[HoneypotDetection]:
        """Detect SMTP honeypots through banner and behavioral analysis."""
        detections = []

        try:
            banner = self._grab_banner(host, port)
            if not banner:
                return detections

            # Check against known SMTP honeypot banners
            matches = match_smtp_banner(banner)

            for match in matches:
                detections.append(HoneypotDetection(
                    type="smtp",
                    indicator=match["description"],
                    confidence=match["confidence"],
                    risk_level=self._calculate_risk(match["confidence"]),
                    port=port,
                    name=match["name"],
                    details={"banner": banner}
                ))

        except Exception as e:
            logger.debug(f"Error detecting SMTP honeypot on {host}:{port}: {e}")

        return detections

    def detect_telnet_honeypot(self, host: str, port: int = 23) -> List[HoneypotDetection]:
        """Detect Telnet honeypots (often IoT honeypots)."""
        detections = []

        try:
            banner = self._grab_banner(host, port)
            if not banner:
                return detections

            # Check against known Telnet honeypot patterns
            for pattern_info in TELNET_HONEYPOT_PATTERNS:
                if re.search(pattern_info["pattern"], banner, re.IGNORECASE):
                    detections.append(HoneypotDetection(
                        type="telnet",
                        indicator=pattern_info["description"],
                        confidence=pattern_info["confidence"],
                        risk_level=self._calculate_risk(pattern_info["confidence"]),
                        port=port,
                        name=pattern_info["name"],
                        details={"banner": banner}
                    ))

        except Exception as e:
            logger.debug(f"Error detecting Telnet honeypot on {host}:{port}: {e}")

        return detections

    def check_port_count_anomaly(
        self,
        host: str,
        open_ports: List[int]
    ) -> Optional[HoneypotDetection]:
        """
        Check if the number of open ports is suspiciously high.

        Honeypots often expose many services to attract attackers.
        """
        threshold = BEHAVIORAL_INDICATORS["too_many_open_ports"]["threshold"]

        if len(open_ports) >= threshold:
            return HoneypotDetection(
                type="generic",
                indicator=BEHAVIORAL_INDICATORS["too_many_open_ports"]["description"],
                confidence=BEHAVIORAL_INDICATORS["too_many_open_ports"]["confidence"],
                risk_level="medium",
                port=0,
                name="Port Count Anomaly",
                details={
                    "open_port_count": len(open_ports),
                    "threshold": threshold,
                    "sample_ports": open_ports[:20]
                }
            )
        return None

    def check_service_combination(
        self,
        services: Dict[int, str]
    ) -> List[HoneypotDetection]:
        """
        Check for impossible service combinations.

        E.g., Windows IIS + nginx on same host.
        """
        detections = []

        # Collect OS and service info
        os_indicators = []
        service_indicators = []

        for port, banner in services.items():
            if "Windows" in banner or "Microsoft" in banner or "IIS" in banner:
                os_indicators.append("Windows")
            if "Linux" in banner or "Ubuntu" in banner or "Debian" in banner:
                os_indicators.append("Linux")
            if "nginx" in banner:
                service_indicators.append(f"nginx on port {port}")
            if "Apache" in banner:
                service_indicators.append(f"Apache on port {port}")
            if "IIS" in banner:
                service_indicators.append(f"IIS on port {port}")

        # Check for contradictions
        if "Windows" in os_indicators and "Linux" in os_indicators:
            detections.append(HoneypotDetection(
                type="generic",
                indicator=BEHAVIORAL_INDICATORS["impossible_service_combo"]["description"],
                confidence=BEHAVIORAL_INDICATORS["impossible_service_combo"]["confidence"],
                risk_level="medium",
                port=0,
                name="OS Mismatch",
                details={
                    "os_indicators": list(set(os_indicators)),
                    "service_indicators": service_indicators
                }
            ))

        return detections

    def _calculate_risk(self, confidence: int) -> str:
        """Calculate risk level from confidence score."""
        if confidence >= 80:
            return "critical"
        elif confidence >= 60:
            return "high"
        elif confidence >= 40:
            return "medium"
        else:
            return "low"
