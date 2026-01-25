"""
Deception Technology Detection Scanner

Detects honeypots, DNS sinkholes, and network tarpits to identify
potentially deceptive infrastructure during reconnaissance.

This module helps identify:
- Honeypots masquerading as vulnerable services
- Sinkholed domains (law enforcement, security research)
- Network tarpits designed to slow down scanners
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import asdict

from yads.core.base import BaseScannerModule

from .deception.honeypots import HoneypotDetector, HoneypotDetection
from .deception.sinkholes import SinkholeDetector, SinkholeDetection
from .deception.tarpits import TarpitDetector, TarpitDetection
from .deception.scoring import DeceptionScorer, DeceptionSummary

logger = logging.getLogger("yads.modules.deception_detector")


class DeceptionDetector(BaseScannerModule):
    """
    Detects deception technologies including honeypots, sinkholes, and tarpits.

    This scanner helps identify infrastructure that may be:
    - Security research honeypots
    - Law enforcement sinkholes
    - Network tarpits designed to slow scanners
    - Fake services designed to attract attackers

    Use cases:
    - Validate target authenticity before deeper scanning
    - Identify research/security infrastructure
    - Detect compromised or seized domains
    """

    module_name = "deception_detector"

    def __init__(self, timeout: int = 30):
        """
        Initialize the deception detector.

        Args:
            timeout: Timeout in seconds for network operations.
        """
        self.timeout = timeout
        self.honeypot_detector = HoneypotDetector(timeout=timeout)
        self.sinkhole_detector = SinkholeDetector(timeout=timeout)
        self.tarpit_detector = TarpitDetector(timeout=timeout)
        self.scorer = DeceptionScorer()

    def run_scan(self, target: str, target_id: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Run comprehensive deception detection on a target.

        Args:
            target: Domain or IP address to scan.
            target_id: Optional target ID from database.
            **kwargs: Additional options:
                - ports: List of ports to check (default: common ports)
                - skip_tarpit: Skip tarpit detection (faster but less thorough)
                - skip_honeypot: Skip honeypot detection
                - skip_sinkhole: Skip sinkhole detection

        Returns:
            Dict containing:
                - honeypots: List of detected honeypots
                - sinkholes: List of detected sinkholes
                - tarpits: List of detected tarpits
                - summary: Overall deception assessment
                - recommendations: Suggested actions
        """
        logger.info(f"Starting deception detection scan for {target}")

        ports = kwargs.get("ports", [22, 23, 21, 25, 80, 443, 8080])
        skip_tarpit = kwargs.get("skip_tarpit", False)
        skip_honeypot = kwargs.get("skip_honeypot", False)
        skip_sinkhole = kwargs.get("skip_sinkhole", False)

        honeypots: List[HoneypotDetection] = []
        sinkholes: List[SinkholeDetection] = []
        tarpits: List[TarpitDetection] = []

        # Run honeypot detection
        if not skip_honeypot:
            logger.info(f"Running honeypot detection on {target}")
            try:
                honeypots = self.honeypot_detector.detect_all(target, ports)
                logger.info(f"Found {len(honeypots)} honeypot indicators")
            except Exception as e:
                logger.error(f"Honeypot detection failed for {target}: {e}")

        # Run sinkhole detection
        if not skip_sinkhole:
            logger.info(f"Running sinkhole detection on {target}")
            try:
                sinkholes = self.sinkhole_detector.detect(target)
                logger.info(f"Found {len(sinkholes)} sinkhole indicators")
            except Exception as e:
                logger.error(f"Sinkhole detection failed for {target}: {e}")

        # Run tarpit detection (can be slow)
        if not skip_tarpit:
            logger.info(f"Running tarpit detection on {target}")
            try:
                tarpits = self.tarpit_detector.detect_all(target, ports)
                logger.info(f"Found {len(tarpits)} tarpit indicators")
            except Exception as e:
                logger.error(f"Tarpit detection failed for {target}: {e}")

        # Generate summary and scoring
        summary = self.scorer.create_summary(honeypots, sinkholes, tarpits)

        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(
            honeypots, sinkholes, tarpits, summary
        )

        # Format results
        result = {
            "honeypots": [self._format_honeypot(h) for h in honeypots],
            "sinkholes": [self._format_sinkhole(s) for s in sinkholes],
            "tarpits": [self._format_tarpit(t) for t in tarpits],
            "summary": self.scorer.to_dict(summary),
            "recommendations": recommendations,
            "scan_config": {
                "ports_scanned": ports,
                "tarpit_detection": not skip_tarpit,
                "honeypot_detection": not skip_honeypot,
                "sinkhole_detection": not skip_sinkhole,
            }
        }

        logger.info(
            f"Deception scan complete for {target}: "
            f"{summary.total_detections} total detections, "
            f"risk level: {summary.overall_risk}"
        )

        return result

    def _format_honeypot(self, detection: HoneypotDetection) -> Dict[str, Any]:
        """Format honeypot detection for output."""
        return {
            "type": detection.type,
            "indicator": detection.indicator,
            "confidence": detection.confidence,
            "risk_level": detection.risk_level,
            "port": detection.port,
            "name": detection.name,
            "details": detection.details,
        }

    def _format_sinkhole(self, detection: SinkholeDetection) -> Dict[str, Any]:
        """Format sinkhole detection for output."""
        return {
            "domain": detection.domain,
            "sinkhole_ip": detection.sinkhole_ip,
            "sinkhole_operator": detection.sinkhole_operator,
            "confidence": detection.confidence,
            "risk_level": detection.risk_level,
            "indicator": detection.indicator,
            "detection_type": detection.detection_type,
            "details": detection.details,
        }

    def _format_tarpit(self, detection: TarpitDetection) -> Dict[str, Any]:
        """Format tarpit detection for output."""
        return {
            "type": detection.type,
            "port": detection.port,
            "response_delay_ms": detection.response_delay_ms,
            "confidence": detection.confidence,
            "risk_level": detection.risk_level,
            "indicator": detection.indicator,
            "details": detection.details,
        }

    def _generate_recommendations(
        self,
        honeypots: List[HoneypotDetection],
        sinkholes: List[SinkholeDetection],
        tarpits: List[TarpitDetection],
        summary: DeceptionSummary
    ) -> List[Dict[str, str]]:
        """
        Generate actionable recommendations based on findings.

        Args:
            honeypots: List of honeypot detections.
            sinkholes: List of sinkhole detections.
            tarpits: List of tarpit detections.
            summary: Overall summary.

        Returns:
            List of recommendation dicts with severity and action.
        """
        recommendations = []

        # No detections
        if summary.total_detections == 0:
            recommendations.append({
                "severity": "info",
                "title": "No Deception Detected",
                "action": "Target appears to be legitimate infrastructure. "
                         "Continue with standard scanning procedures."
            })
            return recommendations

        # High-confidence honeypot detection
        high_conf_honeypots = [h for h in honeypots if h.confidence >= 70]
        if high_conf_honeypots:
            recommendations.append({
                "severity": "critical",
                "title": "High-Confidence Honeypot Detected",
                "action": "This target is likely a honeypot. Avoid aggressive scanning "
                         "as actions may be logged and analyzed. Consider removing "
                         "this target from your scope."
            })

        # Sinkhole detection
        law_enforcement_sinkholes = [
            s for s in sinkholes
            if s.sinkhole_operator in ["FBI", "DOJ", "Law Enforcement"]
        ]
        if law_enforcement_sinkholes:
            recommendations.append({
                "severity": "critical",
                "title": "Law Enforcement Sinkhole Detected",
                "action": "This domain has been seized by law enforcement. "
                         "Any connections may be monitored. Remove from scope immediately."
            })
        elif sinkholes:
            recommendations.append({
                "severity": "high",
                "title": "DNS Sinkhole Detected",
                "action": "This domain resolves to known sinkhole infrastructure. "
                         "The domain may be compromised or taken down. Verify domain "
                         "ownership before proceeding."
            })

        # Tarpit detection
        if tarpits:
            recommendations.append({
                "severity": "medium",
                "title": "Network Tarpit Behavior Detected",
                "action": "Target exhibits tarpit behavior (intentionally slow responses). "
                         "This may be anti-scanning defense or deception. Consider "
                         "increasing timeouts or reducing scan intensity."
            })

        # Multiple detection types (very suspicious)
        detection_types = sum([
            1 if honeypots else 0,
            1 if sinkholes else 0,
            1 if tarpits else 0
        ])
        if detection_types >= 2:
            recommendations.append({
                "severity": "critical",
                "title": "Multiple Deception Indicators",
                "action": f"Target shows {detection_types} different types of deception "
                         "indicators. This strongly suggests the target is not legitimate "
                         "infrastructure. Consider blacklisting this target."
            })

        # Overall risk assessment
        if summary.overall_risk == "critical":
            recommendations.append({
                "severity": "critical",
                "title": "Critical Deception Risk",
                "action": "Overall deception risk is CRITICAL. Do not proceed with "
                         "further scanning without explicit authorization and risk acknowledgment."
            })
        elif summary.overall_risk == "high":
            recommendations.append({
                "severity": "high",
                "title": "High Deception Risk",
                "action": "Overall deception risk is HIGH. Exercise caution and verify "
                         "target legitimacy before proceeding with further analysis."
            })

        return recommendations

    def quick_scan(self, target: str) -> Dict[str, Any]:
        """
        Run a quick deception scan (skips tarpit detection for speed).

        Args:
            target: Domain or IP address to scan.

        Returns:
            Scan results (same format as scan()).
        """
        return self.scan(target, skip_tarpit=True, ports=[22, 80, 443])

    def full_scan(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Run a comprehensive deception scan on all specified ports.

        Args:
            target: Domain or IP address to scan.
            ports: List of ports to check.

        Returns:
            Scan results (same format as scan()).
        """
        if ports is None:
            ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443]
        return self.scan(target, ports=ports)
